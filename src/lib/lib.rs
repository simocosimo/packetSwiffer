pub mod tui;

pub mod parsing_utils {
    use pnet::datalink::{self, NetworkInterface};

    use pnet::packet::arp::ArpPacket;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
    use pnet::packet::icmpv6::Icmpv6Packet;
    use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::ipv6::Ipv6Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::Packet;
    use pnet::util::MacAddr;

    use std::net::IpAddr;
    use std::fmt::Write;

    fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) -> String {
        let udp = UdpPacket::new(packet);
        let mut ret = String::new();

        if let Some(udp) = udp {
            write!(
                &mut ret,
                "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                interface_name,
                source,
                udp.get_source(),
                destination,
                udp.get_destination(),
                udp.get_length()
            ).unwrap();

            // TODO: use dns_parser and extract the useful info about the packet (hostname, resolved ip, ...)
            // match dns_parser::Packet::parse(udp.payload()) {
            //     Ok(packet) => {
            //         println!("{:?}", packet);
            //     }
            //     Err(_) => {
            //         println!("Not a DNS packet");
            //     }
            // }

        } else {
            write!(&mut ret, "[{}]: Malformed UDP Packet", interface_name).unwrap();
        }

        ret
    }

    fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) -> String {
        let icmp_packet = IcmpPacket::new(packet);
        let mut ret = String::new();
        if let Some(icmp_packet) = icmp_packet {
            match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                    write!(
                        &mut ret,
                        "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                        interface_name,
                        source,
                        destination,
                        echo_reply_packet.get_sequence_number(),
                        echo_reply_packet.get_identifier()
                    ).unwrap();
                }
                IcmpTypes::EchoRequest => {
                    let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                    write!(
                        &mut ret,
                        "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                        interface_name,
                        source,
                        destination,
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier()
                    ).unwrap();
                }
                _ => {
                    write!(
                        &mut ret,
                        "[{}]: ICMP packet {} -> {} (type={:?})",
                        interface_name,
                        source,
                        destination,
                        icmp_packet.get_icmp_type()
                    ).unwrap();
                },
            }
        } else {
            write!(&mut ret, "[{}]: Malformed ICMP Packet", interface_name).unwrap();
        }

        ret
    }

    fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) -> String {
        let icmpv6_packet = Icmpv6Packet::new(packet);
        let mut ret = String::new();

        if let Some(icmpv6_packet) = icmpv6_packet {
            write!(
                &mut ret,
                "[{}]: ICMPv6 packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmpv6_packet.get_icmpv6_type()
            ).unwrap();
        } else {
            write!(&mut ret, "[{}]: Malformed ICMPv6 Packet", interface_name).unwrap();
        }

        ret
    }

    fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) -> String {
        let tcp = TcpPacket::new(packet);
        let mut ret = String::new();

        // TODO: implement tls_parser, to get info about tls records
        // TODO: implement httparse, to get info about http packets
        // TODO: how do we distinguish the packets?

        if let Some(tcp) = tcp {
            write!(
                &mut ret,
                "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                interface_name,
                source,
                tcp.get_source(),
                destination,
                tcp.get_destination(),
                packet.len()
            ).unwrap();
        } else {
            writeln!(&mut ret, "[{}]: Malformed TCP Packet", interface_name).unwrap();
        }

        ret
    }

    fn handle_transport_protocol(
        interface_name: &str,
        source: IpAddr,
        destination: IpAddr,
        protocol: IpNextHeaderProtocol,
        packet: &[u8],
    ) -> String {
        let mut ret = String::new();
        match protocol {
            IpNextHeaderProtocols::Udp => {
                handle_udp_packet(interface_name, source, destination, packet)
            }
            IpNextHeaderProtocols::Tcp => {
                handle_tcp_packet(interface_name, source, destination, packet)
            }
            IpNextHeaderProtocols::Icmp => {
                handle_icmp_packet(interface_name, source, destination, packet)
            }
            IpNextHeaderProtocols::Icmpv6 => {
                handle_icmpv6_packet(interface_name, source, destination, packet)
            }
            _ => {
                write!(
                    &mut ret,
                    "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                    interface_name,
                    match source {
                        IpAddr::V4(..) => "IPv4",
                        _ => "IPv6",
                    },
                    source,
                    destination,
                    protocol,
                    packet.len()).unwrap();
                ret
            },
        }
    }

    fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) -> String {
        let header = Ipv4Packet::new(ethernet.payload());
        let mut ret = String::new();
        if let Some(header) = header {
            handle_transport_protocol(
                interface_name,
                IpAddr::V4(header.get_source()),
                IpAddr::V4(header.get_destination()),
                header.get_next_level_protocol(),
                header.payload(),
            )
        } else {
            write!(&mut ret, "[{}]: Malformed IPv4 Packet", interface_name).unwrap();
            ret
        }
    }

    fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) -> String {
        let header = Ipv6Packet::new(ethernet.payload());
        let mut ret = String::new();
        if let Some(header) = header {
            handle_transport_protocol(
                interface_name,
                IpAddr::V6(header.get_source()),
                IpAddr::V6(header.get_destination()),
                header.get_next_header(),
                header.payload(),
            )
        } else {
            write!(&mut ret, "[{}]: Malformed IPv6 Packet", interface_name).unwrap();
            ret
        }
    }

    fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) -> String {
        let header = ArpPacket::new(ethernet.payload());
        let mut ret = String::new();
        if let Some(header) = header {
            write!(
                &mut ret,
                "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
                interface_name,
                ethernet.get_source(),
                header.get_sender_proto_addr(),
                ethernet.get_destination(),
                header.get_target_proto_addr(),
                header.get_operation()
            ).unwrap();
        } else {
            write!(&mut ret, "[{}]: Malformed ARP Packet", interface_name).unwrap();
        }
        ret
    }

    pub fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) -> String {
        let interface_name = &interface.name[..];
        let mut ret = String::new();

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
            EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
            EtherTypes::Arp => handle_arp_packet(interface_name, ethernet),
            _ => {
                write!(
                    &mut ret,
                    "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                    interface_name,
                    ethernet.get_source(),
                    ethernet.get_destination(),
                    ethernet.get_ethertype(),
                    ethernet.packet().len()
                ).unwrap();
                ret
            },
        }
    }
}
