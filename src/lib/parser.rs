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

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) -> String {
    let parsed_udp = parse_udp_header(packet);

    match parsed_udp {
        Ok(tuple) => {
            let _payload = tuple.0;
            let header = tuple.1;
            format!(
                "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                interface_name,
                source,
                header.source_port,
                destination,
                header.dest_port,
                header.length
            )

            // TODO: use dns_parser and extract the useful info about the packet (hostname, resolved ip, ...)
            // match dns_parser::Packet::parse(udp.payload()) {
            //     Ok(packet) => {
            //         println!("{:?}", packet);
            //     }
            //     Err(_) => {
            //         println!("Not a DNS packet");
            //     }
            // }
        },
        Err(_) => "[err]: Couldn't parse ICMP packet".to_string()
    }
}

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) -> String {
    let parsed_icmp = parse_icmp_header(packet);

    match parsed_icmp {
        Ok(tuple) => {
            let _payload = tuple.0;
            let header = tuple.1;
            match header.code {
                IcmpCode::EchoReply => {
                    // TODO: parse echo reply packet for seq and id
                    // let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                    format!(
                        "[{}]: ICMP echo reply {} -> {} (seq=?, id=?)",
                        interface_name,
                        source,
                        destination,
                        // echo_reply_packet.get_sequence_number(),
                        // echo_reply_packet.get_identifier()
                    )
                },
                IcmpCode::EchoRequest => {
                    // TODO: parse echo request packet for seq and id
                    // let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                    format!(
                        "[{}]: ICMP echo request {} -> {} (seq=?, id=?)",
                        interface_name,
                        source,
                        destination,
                        // echo_request_packet.get_sequence_number(),
                        // echo_request_packet.get_identifier()
                    )
                },
                _ => {
                    format!(
                        "[{}]: ICMP packet {} -> {} (type={:?})",
                        interface_name,
                        source,
                        destination,
                        header.code
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

    // TODO: implement tls_parser, to get info about tls records
    // TODO: implement httparse, to get info about http packets
    // TODO: how do we distinguish the packets?

    match parsed_tcp {
        Ok(tuple) => {
            let _payload = tuple.0;
            let header = tuple.1;
            format!(
                "[{}]: TCP Packet: {}:{} > {}:{}; sequence no: {} length: {}",
                interface_name,
                source,
                header.source_port,
                destination,
                header.dest_port,
                header.sequence_no,
                packet.len()
            )
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
    // TODO: if this computation is done here, maybe I can pass to called functions
    // TODO: just the already extracted address

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