use pktparse::ethernet::MacAddress;

pub fn mac_to_str(addr: MacAddress) -> String {
    format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            addr.0[0],
            addr.0[1],
            addr.0[2],
            addr.0[3],
            addr.0[4],
            addr.0[5]
    )
}