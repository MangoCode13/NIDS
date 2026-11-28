#!/usr/bin/env python3
"""Offline Modbus/TCP network baseline. Run build once, then evaluate repeatedly."""
import argparse
import io
import zipfile
import xml.etree.ElementTree as ET
from contextlib import ExitStack
import csv
import json
import math
import os
import subprocess
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
REQUESTS = "modbus_network_v3r2_requests.log"
MINUTES = "modbus_network_v3r2_minutes.log"
REVIEW = "network_attack_review_v3r2_since_start.csv"
LABELS = "modbus_network_v3r2_since_start_attack_log.log"
SCENARIOS = ("external", "compromised-scada")
COLUMNS = ["scenario", "minute_utc", "attack", "logged_actions", "target_ip", "status", "first_logged_utc", "first_transaction_id", "minute_result"]
UTC = timezone.utc


def utc(seconds):
	return datetime.fromtimestamp(seconds, UTC).isoformat()


def emit(stream, **fields):
	stream.write(json.dumps(fields, separators=(",", ":")) + "\n")


def p99(values):
	ordered = sorted(values)
	return ordered[math.ceil(0.99 * len(ordered)) - 1]


def groups(data):
	normal = data / "benign/network-wide-pcap-capture/network-wide"
	external = data / "attack/external/network-wide"
	for i in range(14, 23):
		yield ("benign_train" if i <= 20 else "benign_holdout",
			   normal / f"network-wide-normal-{i}.pcap")
	for i in (0, 1):
		yield "external", external / f"network-wide-normal-{i}.pcap"

	for i in range(18):
		yield "compromised-scada", data / "attack/compromised-scada/substation-wide-capture" / f"substation-{i}.pcap"


class RequestProfile:
	"""Learn client/read ranges on benign_train only. Track recent reads per split."""
	def __init__(self):
		self.normal = set()
		self.last_readers = {}
		self.split = None

	def inspect(self, split, ts, target, client, frame):
		if self.split != split:
			self.last_readers.clear()
			self.split = split
		code = frame[7]
		if code not in (1, 2, 3, 4) or len(frame) != 12:
			return [], {}
		address = int.from_bytes(frame[8:10], "big")
		quantity = int.from_bytes(frame[10:12], "big")
		key = target, frame[6], code, address, quantity
		readers = self.last_readers.setdefault(key, {})
		reasons = []
		if split == "benign_train":
			self.normal.add((client, key))
		elif (client, key) not in self.normal:
			reasons.append("unfamiliar_client_read_range")
			if any(peer != client and 0 <= ts - when <= 120
				   for peer, when in readers.items()):
				reasons.append("recent_matching_read_other_client")
		readers[client] = ts
		return reasons, dict(start_address=address, quantity=quantity)


class ReadBurst:
	"""Detect rapid groups of previously seen reads by the same client."""
	def __init__(self):
		self.history = {}
		self.bursts = {}

	def check(self, ts, client, server, adu):
		if len(adu) != 12 or adu[7] not in (1, 2, 3, 4):
			return False
		peer = client, server
		signature = adu[6:]
		tid = adu[:2]
		key = peer, signature
		previous = self.history.get(key)
		self.history[key] = ts, tid
		start, group_id, seen = self.bursts.get(peer, (ts, tid, set()))
		if group_id != tid or not 0 <= ts - start <= 0.100:
			start, group_id, seen = ts, tid, set()
		if previous and previous[1] != tid and 0 <= ts - previous[0] <= 2:
			seen.add(signature)
		self.bursts[peer] = start, group_id, seen
		return len(seen) >= 3


class Stream:
	"""Contiguous client bytes, with TCP overlap removal and bounded gap buffering."""
	def __init__(self, seq):
		self.next = seq
		self.gaps = {}
		self.buf = bytearray()
		self.last_request = None
		self.disabled = False
		self.last_wire = None
		self.last_time = 0
		self.repeat = 0

	def accept(self, seq, data):
		if self.disabled:
			return
		# Relative sequence difference, including the TCP 32-bit wrap.
		delta = ((seq - self.next + 2**31) % 2**32) - 2**31
		seq = self.next + delta
		if seq > self.next:
			if len(self.gaps) >= 128 or delta > 2**20:
				self.disabled = True
				self.gaps.clear()
			elif len(data) > len(self.gaps.get(seq, b"")):
				self.gaps[seq] = data
			return
		while True:
			fresh = data[self.next - seq:]
			self.buf.extend(fresh)
			self.next += len(fresh)
			if not self.gaps or min(self.gaps) > self.next:
				break
			seq = min(self.gaps)
			data = self.gaps.pop(seq)


def extract(path, split, output, counts, pairs, signals, profile, burst):
	fields = ["frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
			  "tcp.stream", "tcp.seq_raw", "tcp.flags.syn", "tcp.flags.fin",
			  "tcp.flags.reset", "tcp.payload", "mbtcp.trans_id"]
	cmd = ["tshark", "-n", "-r", str(path), "-Y",
		   "ip && tcp.port == 502 && (tcp.len > 0 || tcp.flags.syn == 1 || tcp.flags.fin == 1 || tcp.flags.reset == 1)",
		   "-T", "fields", "-E", "occurrence=f"]
	for field in fields:
		cmd.extend(["-e", field])
	streams = {}
	total = 0
	with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
		for line in proc.stdout:
			stamp, client, target, sport, dport, sid, seq, syn, fin, rst, payload, decoded_tid = line.rstrip("\r\n").split("\t")
			syn, fin, rst = (value.strip().lower() in {"1", "true"} for value in (syn, fin, rst))
			if dport != "502":
				# A server FIN only closes its sending direction.
				if rst:
					streams.pop(sid, None)
				continue
			ts = float(stamp)
			seq = int(seq)
			raw = bytes.fromhex(payload.replace(":", ""))
			if syn:
				seq = (seq + 1) % 2**32
				streams.setdefault(sid, Stream(seq))
			if sid not in streams and len(raw) >= 8 and decoded_tid:
				# Capture beginning mid-connection: require a dissected header at offset zero.
				if raw[2:4] == bytes(2) and int.from_bytes(raw[:2], "big") == int(decoded_tid):
					streams[sid] = Stream(seq)
			stream = streams.get(sid)
			if stream is None:
				continue
			stream.accept(seq, raw)
			records = []
			buf = stream.buf
			while not stream.disabled and len(buf) >= 4:
				if buf[2:4] != bytes(2):
					# Already enough bytes to exclude a valid next Modbus/TCP header.
					if stream.last_request:
						last_ts, last_key = stream.last_request
						reason = "unexpected_bytes_after_request"
						signals[last_key].add(reason)
						if records:
							records[-1]["evidence"].append(reason)
						else:
							emit(output, ts=last_ts, record_kind="network_v3r2_evidence",
								 split=split, target_ip=target, client_ip=client, evidence=[reason])
					stream.disabled = True
					buf.clear()
					break
				if len(buf) < 8:
					break
				length = int.from_bytes(buf[4:6], "big")
				code = buf[7]
				fixed_error = 1 <= code <= 6 and length != 6
				if not fixed_error and not 2 <= length <= 254:
					stream.disabled = True
					break
				if not fixed_error and len(buf) < 6 + length:
					break
				# A corrupt fixed-length header is evidence by itself. Stop parsing
				# this flow because the next application boundary is ambiguous.
				size = 8 if fixed_error else 6 + length
				adu = bytes(buf[:size])
				del buf[:size]
				reasons, details = profile.inspect(split, ts, target, client, adu)
				if fixed_error:
					reasons.append("invalid_fixed_request_length")
					details["declared_length"] = length
					stream.disabled = True
				if code == 5 and len(adu) == 12:
					value = int.from_bytes(adu[10:12], "big")
					details.update(coil_address=int.from_bytes(adu[8:10], "big"), coil_value=value)
					if value not in (0, 65280):
						reasons.append("invalid_coil_write_value")
				if adu == stream.last_wire and 0 <= ts - stream.last_time <= 0.100:
					stream.repeat += 1
				else:
					stream.repeat = 1
				stream.last_wire, stream.last_time = adu, ts
				if stream.repeat >= 3:
					reasons.append("rapid_identical_request_stack")
				if burst.check(ts, client, target, adu):
					reasons.append("rapid_same_client_read_replay")
				key = split, target, int(ts) // 60 * 60
				stream.last_request = ts, key
				counts[key] += 1
				pairs[key].add((client, str(code)))
				signals[key].update(reasons)
				records.append(dict(ts=ts, record_kind="network_v3r2_request", split=split,
									capture=path.name, target_ip=target, client_ip=client,
									function_code=str(code), transaction_id=str(int.from_bytes(adu[:2], "big")),
									evidence=reasons, **details))
			for record in records:
				emit(output, **record)
			total += len(records)
			if fin or rst:
				streams.pop(sid, None)
		if proc.wait():
			raise SystemExit(f"TShark failed reading {path}")
	print(f"{split} {path.name}: {total:,} requests", flush=True)


def summaries(counts, pairs, signals, output):
	known = defaultdict(set)
	by_target = defaultdict(list)
	by_hour = defaultdict(list)
	train_minutes = set()
	for (split, target, minute), count in counts.items():
		if split == "benign_train":
			train_minutes.add((target, minute))
			known[target].update(pairs[split, target, minute])
			by_target[target].append(count)
			by_hour[target, minute // 3600 % 24].append(count)
	limits = {k: p99(v) for k, v in by_target.items()}
	hourly = {k: p99(v) for k, v in by_hour.items() if len(v) >= 100}
	for (split, target, minute), count in sorted(counts.items()):
		hour_key = target, minute // 3600 % 24
		limit = hourly.get(hour_key, limits.get(target))
		if limit:
			limit += 10
		overlap = split == "benign_holdout" and (target, minute) in train_minutes
		scored = limit is not None and not overlap
		row = dict(ts=minute, record_kind="network_v3r2_minute", target_ip=target,
				   split=split, requests=count, scored=scored)
		if scored:
			unseen = sorted(pairs[split, target, minute] - known[target])
			reasons = sorted(signals.get((split, target, minute), ()))
			if count > limit:
				reasons.append("high_request_rate")
			if unseen:
				reasons.append("new_client_function")
			row.update(baseline_p99=limit, baseline_scope="hour_utc" if hour_key in hourly else "device",
					   flagged=bool(reasons), reason=", ".join(reasons),
					   new_pairs=[f"{ip} / FC {code}" for ip, code in unseen])
		else:
			row["reason"] = "shared_train_minute" if overlap else "unbaselined"
		emit(output, **row)


def workbook_rows(stream):
	# The supplied March 21 CSV lost the date and hour during export.
	# Its companion workbook retains full Excel datetimes.
	ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
	with zipfile.ZipFile(io.BytesIO(stream.read())) as book:
		strings = ["".join(node.itertext()) for node in
				   ET.fromstring(book.read("xl/sharedStrings.xml"))]
		rows = ET.fromstring(book.read("xl/worksheets/sheet1.xml")).iter(ns + "row")
		def values(row):
			result = {}
			for cell in row.findall(ns + "c"):
				val = cell.findtext(ns + "v", "")
				col = cell.attrib["r"].rstrip("0123456789")
				result[col] = strings[int(val)] if cell.get("t") == "s" else val
			return result
		header = values(next(rows))
		for row in rows:
			fields = {header[col]: value for col, value in values(row).items()}
			dt = datetime(1899, 12, 30) + timedelta(days=float(fields["Timestamp"]))
			fields["Timestamp"] = dt.isoformat()
			yield fields


def label_rows(args, scenario):
	base = args.data / "attack" / scenario
	folder = base / ("external-attacker/attacker logs" if scenario == "external" else "attack logs")
	archive = getattr(args, scenario.replace("-", "_") + "_zip", None)
	with ExitStack() as stack:
		if archive:
			z = stack.enter_context(zipfile.ZipFile(archive))
			files = [p for p in z.namelist() if "__MACOSX" not in p]
			opener = z.open
		else:
			files = [str(p) for p in folder.rglob("*") if p.is_file()]
			opener = lambda path: open(path, "rb")
		csvs = sorted(p for p in files if p.lower().endswith(".csv"))
		if not csvs:
			raise SystemExit(f"No CSVs for {scenario}: {archive or folder}")
		for path in csvs:
			if path.endswith("03-21-2023-1-original.csv"):
				companion = path.replace("-original.csv", "-formatted.xlsx")
				if companion not in files:
					raise SystemExit(f"Fzull timestamps require {companion}")
				with opener(companion) as stream:
					yield from workbook_rows(stream)
			else:
				with opener(path) as raw, io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as stream:
					yield from csv.DictReader(stream)


def capture_starts(data):
	"""Earliest raw packet in the actual evaluation files for each scenario."""
	starts = {}
	for scenario, path in groups(data):
		if scenario not in SCENARIOS:
			continue
		proc = subprocess.run(["capinfos", "-T", "-r", "-a", str(path)],
							  capture_output=True, text=True, env={**os.environ, "TZ": "UTC", "LC_ALL": "C"})
		if proc.returncode:
			raise SystemExit(f"Cannot inspect {path}: {proc.stderr.strip()}")
		stamp = proc.stdout.rstrip("\r\n").split("\t")[-1].strip().strip('"')
		if stamp.lower() == "n/a":
			continue
		try:
			ts = datetime.fromisoformat(stamp).replace(tzinfo=UTC).timestamp()
		except ValueError:
			raise SystemExit(f"Cannot read earliest timestamp for {path}: {stamp!r}")
		if scenario not in starts or ts < starts[scenario]:
			starts[scenario] = ts
	for scenario in SCENARIOS:
		if scenario not in starts:
			raise SystemExit(f"No packet timestamps found for {scenario}")
		print(f"{scenario} earliest raw packet: {utc(starts[scenario])}", flush=True)
	return starts


def review_from_minutes(args, minute_path, stage, starts):
	results = {}
	with minute_path.open() as summary:
		for line in summary:
			row = json.loads(line)
			if row["split"] in SCENARIOS:
				outcome = ("flagged" if row["flagged"] else "quiet") if row["scored"] else "unbaselined"
				results[row["split"], row["target_ip"], row["ts"]] = outcome
	make_review(args, stage / REVIEW, stage / LABELS, results, starts)
	args.review.parent.mkdir(exist_ok=True, parents=True)
	with args.review.open("xb") as dest:
		dest.write((stage / REVIEW).read_bytes())


def review_only(args):
	if not (args.logs / MINUTES).is_file():
		raise SystemExit(f"Missing {args.logs / MINUTES}. Run build first or set --logs.")
	if args.review.exists() or (args.logs / LABELS).exists():
		raise SystemExit("Filtered review output already exists. Use evaluate to score it.")
	starts = capture_starts(args.data)
	with tempfile.TemporaryDirectory(dir=args.logs) as tmp:
		stage = Path(tmp)
		review_from_minutes(args, args.logs / MINUTES, stage, starts)
		(stage / LABELS).rename(args.logs / LABELS)
	print(f"Wrote {args.review}")


def make_review(args, dest, label_path, results, starts):
	tz = ZoneInfo(args.csv_zone)
	with dest.open("w", newline="") as stream, label_path.open("w") as output:
		writer = csv.writer(stream)
		writer.writerow(COLUMNS)
		for scenario in SCENARIOS:
			excluded = 0
			events = Counter()
			earliest = {}
			for row in label_rows(args, scenario):
				action = row["Attack"].strip()
				if "complete" in action.lower() or action.lower().startswith("delay response: sending"):
					continue
				dt = datetime.fromisoformat(row["Timestamp"].strip())
				ts = (dt if dt.tzinfo else dt.replace(tzinfo=tz)).timestamp()
				if ts < starts[scenario]:
					excluded += 1
					continue
				target = (row.get("TargetIP") or "").strip()
				key = int(ts) // 60 * 60, target, action
				events[key] += 1
				if key not in earliest or ts < earliest[key][0]:
					earliest[key] = ts, (row.get("TransactionID") or "").strip()
			for (minute, target, action), count in sorted(events.items()):
				ts, tid = earliest[minute, target, action]
				outcome = results.get((scenario, target, minute), "no_request_summary") if target else "target_unknown"
				writer.writerow([scenario, utc(minute), action, count, target, "unverified", utc(ts), tid, outcome])
				emit(output, ts=minute, record_kind="network_v3r2_since_start_attack_log", split=scenario,
					 attack=action, logged_actions=count, first_logged_utc=utc(ts),
					 first_transaction_id=tid, minute_result=outcome,
					 **({"target_ip": target} if target else {}))
			print(f"{scenario}: {len(events):,} attack review rows; {excluded:,} earlier action entries excluded", flush=True)


def build(args):
	out = args.logs
	out.mkdir(exist_ok=True, parents=True)
	plans = list(groups(args.data))
	for _, path in plans:
		if not path.is_file():
			raise SystemExit(f"Missing capture: {path}")
	destinations = [out / REQUESTS, out / MINUTES, out / LABELS, args.review]
	args.review.parent.mkdir(exist_ok=True, parents=True)
	if any(p.exists() for p in destinations):
		raise SystemExit("An output already exists. Use evaluate for an existing run.")
	starts = capture_starts(args.data)
	counts = Counter()
	pairs = defaultdict(set)
	signals = defaultdict(set)
	profile = RequestProfile()
	with tempfile.TemporaryDirectory(dir=out) as temp:
		stage = Path(temp)
		with (stage / REQUESTS).open("w") as output:
			previous_split = None
			for split, path in plans:
				if split != previous_split:
					burst = ReadBurst()
					previous_split = split
				extract(path, split, output, counts, pairs, signals, profile, burst)
		for split in ("benign_train", "benign_holdout", *SCENARIOS):
			if not any(k[0] == split for k in counts):
				raise SystemExit(f"No decoded requests in {split}. Check capture and port.")
		with (stage / MINUTES).open("w") as output:
			summaries(counts, pairs, signals, output)
		review_from_minutes(args, stage / MINUTES, stage, starts)
		for name in (REQUESTS, MINUTES, LABELS):
			(stage / name).rename(out / name)
	evaluate(args)


def ratio(n, d):
	return f"{n}/{d} ({n/d:.2%})" if d else "N/A (denominator 0)"


def evaluate(args):
	benign = defaultdict(Counter)
	detected = set()
	with (args.logs / MINUTES).open() as stream:
		for line in stream:
			row = json.loads(line)
			target = row["target_ip"]
			if row["split"] == "benign_holdout":
				result = ("FP" if row["flagged"] else "TN") if row["scored"] else row["reason"]
				benign[target][result] += 1
			if row["split"] in SCENARIOS and row.get("flagged"):
				detected.add((row["split"], target, row["ts"]))
	total = sum(benign.values(), Counter())
	for target, c in [*sorted(benign.items()), ("ALL", total)]:
		print(f"{target} benign FPR {ratio(c['FP'], c['FP'] + c['TN'])}; "
			  f"TN={c['TN']}, unbaselined={c['unbaselined']}, shared_train_minute={c['shared_train_minute']}")
	positives = set()
	by_action = defaultdict(set)
	status_counts = Counter()
	with args.review.open(newline="") as stream:
		for row in csv.DictReader(stream):
			status = row["status"].strip().lower()
			if status not in {"verified", "unverified", "out_of_scope"}:
				raise ValueError(f"Invalid review status at {row['minute_utc']}: {status}")
			scenario = row["scenario"]
			if scenario not in SCENARIOS:
				raise ValueError(f"Unknown scenario: {scenario}")
			status_counts[scenario, status] += 1
			if status != "verified":
				continue
			dt = datetime.fromisoformat(row["minute_utc"].replace("Z", "+00:00"))
			if dt.tzinfo is None:
				raise ValueError("Verified timestamps must include a timezone")
			key = scenario, str(IPv4Address(row["target_ip"].strip())), int(dt.timestamp()) // 60 * 60
			positives.add(key)
			by_action[(scenario, row["attack"].split(". Address:")[0])].add(key)
	print("Review rows:", dict(status_counts))
	per_scenario = [(s, {k for k in positives if k[0] == s}) for s in SCENARIOS]
	for label, keys in [("ALL attacks", positives), *per_scenario, *sorted(by_action.items())]:
		hits = len(keys & detected)
		print(f"{label}: TP={hits}, FN={len(keys)-hits}, recall={ratio(hits,len(keys))}, "
			  f"FNR={ratio(len(keys)-hits,len(keys))}")


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("mode", choices=["build", "review", "evaluate"])
	parser.add_argument("--data", type=Path, default=Path("./Modbus Dataset"))
	parser.add_argument("--logs", type=Path, default=ROOT / "zeek_logs")
	parser.add_argument("--review", type=Path, default=ROOT / REVIEW)
	parser.add_argument("--csv-zone", default="UTC", help="Timezone of naive attacker CSV timestamps")
	for scenario in SCENARIOS:
		parser.add_argument("--" + scenario + "-zip", type=Path,
							help="Read this scenario's attack logs directly from a ZIP")
	args = parser.parse_args()
	{"build": build, "review": review_only, "evaluate": evaluate}[args.mode](args)
