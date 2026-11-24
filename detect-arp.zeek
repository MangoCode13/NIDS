@load base/frameworks/notice
@load policy/tuning/json-logs

redef ignore_checksums = T;
module ARPSpoofDetect;

export {
    redef enum Notice::Type += {
        ## Raised when a single MAC address claims multiple IP addresses
        Duplicate_MAC_Across_IPs,
        ## Raised when an IP address changes its associated MAC address
        IP_MAC_Binding_Changed
    };
}

# Track known IP -> MAC mappings and MAC -> IP mappings
global ip_to_mac: table[addr] of string &create_expire=10mins;
global mac_to_ip: table[string] of addr &create_expire=10mins;

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) {
    # Ignore empty/unassigned probes
    if ( SPA == 0.0.0.0 )
        return;

    # Detection 1: Same MAC claiming two different IPs (Matches Frame 1 & 2 in your pcap)
    if ( SHA in mac_to_ip && mac_to_ip[SHA] != SPA ) {
        NOTICE([
            $note=Duplicate_MAC_Across_IPs,
            $msg=fmt("ARP Spoof Detected: MAC %s claimed %s after previously claiming %s", SHA, SPA, mac_to_ip[SHA]),
            $src=SPA,
            $identifier=cat(SHA, SPA)
        ]);
    }

    # Detection 2: Existing IP suddenly changing its MAC address
    if ( SPA in ip_to_mac && ip_to_mac[SPA] != SHA ) {
        NOTICE([
            $note=IP_MAC_Binding_Changed,
            $msg=fmt("ARP Spoof Detected: IP %s changed MAC from %s to %s", SPA, ip_to_mac[SPA], SHA),
            $src=SPA,
            $identifier=cat(SPA, SHA)
        ]);
    }

    # Update state tables
    ip_to_mac[SPA] = SHA;
    mac_to_ip[SHA] = SPA;
}
