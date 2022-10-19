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

pub fn tcp_l7(port: u16) -> String {
    let app_layer = match  port {
        80 => "http".to_string(),
        443 => "https".to_string(),
        21 => "ssh".to_string(),
        23 => "telnet".to_string(),
        25 => "smtp".to_string(),
        110 => "POP3".to_string(),
        143 => "IMAP".to_string(),
        194 => "IRC".to_string(),
        _ => "unknown".to_string()
    };

    app_layer
}

pub fn udp_l7(port: u16) -> String {
    let app_layer = match  port {
        53 => "DNS".to_string(),
        67..= 68 => "DHCP".to_string(),
        69 => "TFTP".to_string(),
        161..=162 => "SNMP".to_string(),
        _ => "unknown".to_string()
    };

    app_layer
}