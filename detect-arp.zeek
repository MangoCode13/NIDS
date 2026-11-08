module ARPSpoof;
export {
    redef enum Notice::Type += { MAC_IP_Mismatch };
}
global known_macs: table[addr] of string;

event arp_reply(mac_src: string, mac_dst: string, spa: addr, sha: string, tpa: addr, tha: string) {
    if ( spa in known_macs && known_macs[spa] != sha ) {
        NOTICE([$note=MAC_IP_Mismatch, $msg=fmt("Spoofing Detected: IP %s moved from MAC %s to %s", spa, known_macs[spa], sha)]);
    } else {
        known_macs[spa] = sha;
    }
}
