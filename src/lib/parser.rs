use std::fmt;
use std::net::IpAddr;
use pcap::Device;

use pktparse::arp::parse_arp_pkt;
use pktparse::ethernet::{EtherType, parse_ethernet_frame};
use pktparse::icmp::{IcmpCode, parse_icmp_header};
use pktparse::ip::IPProtocol;
use pktparse::ipv4::parse_ipv4_header;
use pktparse::ipv6::parse_ipv6_header;
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::parse_udp_header;

use crate::utils;
use crate::utils::tcp_l7;

#[derive(Debug)]
struct Packet {
    interface: String,
    src_addr: IpAddr,
    dest_addr: IpAddr,
    res_name: String,
    src_port: Option<u16>,
    dest_port: Option<u16>,
    length: u16,
    transport: String,
    application: String,
}

impl Packet {
    pub fn new(
        interface: String,
        src_addr: IpAddr,
        dest_addr: IpAddr,
        res_name: String,
        src_port: Option<u16>,
        dest_port: Option<u16>,
        length: u16,
        transport: String,
        application: String,
    ) -> Self {
        Packet {
            interface,
            src_addr,
            src_port,
            dest_addr,
            res_name,
            dest_port,
            length,
            transport,
            application,
        }
    }
}
impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //        "Interface\t| Source IP address\t| Source Port\t| Dest IP address \t| Dest Port\t| Timestamp\t|  Bytes\t| Transport \t| Application \n"
        write!(f, "| {0: <2}\t| {1: <30}\t| {2: <5}\t| {3: <30} ({4}) \t| {5: <5}\t| {6: <17}\t|  {7: <3}\t| {8: <3} \t| {9}", self.interface, self.src_addr, self.src_port.unwrap_or(0), self.dest_addr, self.res_name, self.dest_port.unwrap_or(0), chrono::offset::Local::now(), self.length, self.transport, self.application)
    }
}

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) -> String {
    let parsed_udp = parse_udp_header(packet);

    match parsed_udp {
        Ok(tuple) => {
            let payload = tuple.0;
            let header = tuple.1;

            // DONE: use dns_parser and extract the useful info about the packet (hostname, resolved ip, ...)
            match dns_parser::Packet::parse(payload) {
                Ok(dns_packet) => {
                    let p = Packet::new(
                        interface_name.to_string(),
                        source,
                        destination,
                        dns_packet.questions.iter().map(|q| { q.qname.to_string() }).collect::<Vec<String>>().join(", "),
                        Some(header.source_port),
                        Some(header.dest_port),
                        header.length,
                        "UDP".to_string(),
                        "unknown".to_string(),
                    );
                    format!(
                        "{}", p
                    )
                }
                Err(_) => {
                    let p = Packet::new(
                        interface_name.to_string(),
                        source,
                        destination,
                        "none".to_string(),
                        Some(header.source_port),
                        Some(header.dest_port),
                        header.length,
                        "UDP".to_string(),
                        "unknown".to_string(),
                    );
                    format!(
                        "{}", p
                    )
                }
            }




        },
        Err(_) => "[err]: Couldn't parse ICMP packet".to_string()
    }
}

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) -> String {
    let parsed_icmp = parse_icmp_header(packet);

    match parsed_icmp {
        Ok(tuple) => {
            let header = tuple.1;
            match header.code {
                IcmpCode::EchoReply => {
                    // DONE: parse echo reply packet for seq and id
                    let p = Packet::new(
                        interface_name.to_string(),
                        source,
                        destination,
                        "none".to_string(),
                        None,
                        None,
                        64,
                        "ICMP echo reply".to_string(),
                        "unknown".to_string(),
                    );

                    format!(
                        "{}", p
                    )
                },
                IcmpCode::EchoRequest => {
                    // DONE: parse echo request packet for seq and id
                    let p = Packet::new(
                        interface_name.to_string(),
                        source,
                        destination,
                        "none".to_string(),
                        None,
                        None,
                        64,
                        "ICMP echo request".to_string(),
                        "unknown".to_string(),
                    );

                    format!(
                        "{}", p
                    )
                },
                _ => {
                    // DONE: parse echo reply packet for seq and id
                    let p = Packet::new(
                        interface_name.to_string(),
                        source,
                        destination,
                        "none".to_string(),
                        None,
                        None,
                        64,
                        "ICMP packet".to_string(),
                        "unknown".to_string(),
                    );

                    format!(
                        "{}", p
                    )

                }
            }
        },
        Err(_) => "[err]: Couldn't parse ICMP packet".to_string()
    }
}

// fn handle_icmpv6_packet(interface_name: &str, source: IPHeader<T>, destination: IPHeader<T>, packet: &[u8]) -> String {
//     let parsed_icmpv6 = parse_icm
//     let mut ret = String::new();
//
//     if let Some(icmpv6_packet) = icmpv6_packet {
//         write!(
//             &mut ret,
//             "[{}]: ICMPv6 packet {} -> {} (type={:?})",
//             interface_name,
//             source,
//             destination,
//             icmpv6_packet.get_icmpv6_type()
//         ).unwrap();
//     } else {
//         write!(&mut ret, "[{}]: Malformed ICMPv6 Packet", interface_name).unwrap();
//     }
//
//     ret
// }

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) -> String {
    let parsed_tcp = parse_tcp_header(packet);

    match parsed_tcp {
        Ok(tuple) => {
            let _payload = tuple.0;
            let header = tuple.1;
            // DONE: L7 recognised from TCP Header
            let app_layer = tcp_l7(header.dest_port);

            let p = Packet::new(
                interface_name.to_string(),
                source,
                destination,
                "none".to_string(),
                Some(header.source_port),
                Some(header.dest_port),
                packet.len() as u16,
                "TCP".to_string(),
                app_layer,
                );
            format!("{}", p)
        },
        Err(_) => "[err]: Couldn't parse TCP packet".to_string()
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IPProtocol,
    packet: &[u8],
) -> String {

    match protocol {
        IPProtocol::UDP => {
            handle_udp_packet(interface_name, source, destination, packet)
        }
        IPProtocol::TCP => {
            handle_tcp_packet(interface_name, source, destination, packet)
        }
        IPProtocol::ICMP => {
            handle_icmp_packet(interface_name, source, destination, packet)
        }
        IPProtocol::ICMP6 => {
            // TODO: check if this works, otherwise need a way to parse icmpv6
            handle_icmp_packet(interface_name, source, destination, packet)
        }
        _ => format!(
            "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            interface_name,
            match source.is_ipv4() {
                true => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn handle_ipv4_packet(interface_name: &str, packet: &[u8]) -> String {
    let parsed_ipv4 = parse_ipv4_header(packet);

    match parsed_ipv4 {
        Ok(tuple) => {
            let payload = tuple.0;
            let header = tuple.1;
            handle_transport_protocol(
                interface_name,
                IpAddr::V4(header.source_addr),
                IpAddr::V4(header.dest_addr),
                header.protocol,
                payload,
            )
        },
        Err(_) => "[err]: Couldn't parse IPv4 packet".to_string()
    }
}

fn handle_ipv6_packet(interface_name: &str, packet: &[u8]) -> String {
    let parsed_ipv6 = parse_ipv6_header(packet);

    match parsed_ipv6 {
        Ok(tuple) => {
            let payload = tuple.0;
            let header = tuple.1;
            handle_transport_protocol(
                interface_name,
                IpAddr::V6(header.source_addr),
                IpAddr::V6(header.dest_addr),
                header.next_header,
                payload,
            )
        },
        Err(_) => "[err]: Couldn't parse IPv6 packet".to_string()
    }
}

fn handle_arp_packet(interface_name: &str, packet: &[u8]) -> String {
    let parsed_arp = parse_arp_pkt(packet);

    match parsed_arp {
        Ok(tuple) => {
            let _payload = tuple.0;
            let header = tuple.1;
            format!(
                "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
                interface_name,
                utils::mac_to_str(header.src_mac),
                header.src_addr,
                utils::mac_to_str(header.dest_mac),
                header.dest_addr,
                header.operation
            )
        },
        Err(_) => "[err]: Couldn't parse arp packet".to_string()
    }
}

pub fn handle_ethernet_frame(interface: &Device, ethernet: &[u8]) -> String {
    let interface_name = &interface.name[..];
    let ethernet_frame = parse_ethernet_frame(ethernet);

    match ethernet_frame {
        Ok(tuple) => {
            let payload = tuple.0;
            let header = tuple.1;
            match header.ethertype {
                EtherType::IPv4 => handle_ipv4_packet(interface_name, payload),
                EtherType::IPv6 => handle_ipv6_packet(interface_name, payload),
                EtherType::ARP => handle_arp_packet(interface_name, payload),
                _ => format!(
                    "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                    interface_name,
                    utils::mac_to_str(header.source_mac),
                    utils::mac_to_str(header.dest_mac),
                    header.ethertype,
                    payload.len()
                ),
            }
        },
        Err(_) => "[err]: Couldn't parse ethernet packet".to_string()
    }
}