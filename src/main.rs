use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};

use std::{env, thread};
use std::process;
use std::sync::mpsc::channel;

use packet_swiffer::parsing_utils::handle_ethernet_frame;

fn main() {
    use pnet::datalink::Channel::Ethernet;

    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            eprintln!("USAGE: packetdump <NETWORK INTERFACE>");
            process::exit(1);
        }
    };

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == iface_name)
        .next()
        .unwrap_or_else(|| {
            eprintln!("No such network interface: {}", iface_name);
            process::exit(1);
        });

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    // Channel used to pass packets between sniffing thread and parsing thread
    let (tx_thread, rx_thread) = channel::<Vec<u8>>();

    // Thread used to get packets (calls next() method)
    let sniffing_thread = thread::spawn(move | | {
        // TODO: add a mechanism to stop/resume packet sniffing
        while let Ok(packet) = rx.next() {
            let owned_packet = packet.to_owned();
            tx_thread.send(owned_packet).unwrap();
        }
    });

    let cloned_interface = interface.clone();
    // Thread needed to perform parsing of received packet
    let parsing_thread = thread::spawn(move | | {
        // TODO: add macos/ios support
        // TODO: handle filters
        while let Ok(p) = rx_thread.recv() {
            let packet_string = handle_ethernet_frame(&cloned_interface, &EthernetPacket::new(&p).unwrap());
            println!("{}", packet_string);
        }
    });

    // TODO: create thread that analyze packets and produce report (synch should be done with mutex on structure)
    let report_thread = thread::spawn(move | | {

    });

    // joining the threads as a last thing to do
    sniffing_thread.join().unwrap();
    parsing_thread.join().unwrap();
    report_thread.join().unwrap();

    // loop {
    //     let mut buf: [u8; 1600] = [0u8; 1600];
    //     let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
    //     match rx.next() {
    //         Ok(packet) => {
    //             let payload_offset;
    //             if cfg!(any(target_os = "macos", target_os = "ios"))
    //                 && interface.is_up()
    //                 && !interface.is_broadcast()
    //                 && ((!interface.is_loopback() && interface.is_point_to_point())
    //                 || interface.is_loopback())
    //             {
    //                 if interface.is_loopback() {
    //                     // The pnet code for BPF loopback adds a zero'd out Ethernet header
    //                     payload_offset = 14;
    //                 } else {
    //                     // Maybe is TUN interface
    //                     payload_offset = 0;
    //                 }
    //                 if packet.len() > payload_offset {
    //                     let version = Ipv4Packet::new(&packet[payload_offset..])
    //                         .unwrap()
    //                         .get_version();
    //                     if version == 4 {
    //                         fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
    //                         fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
    //                         fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
    //                         fake_ethernet_frame.set_payload(&packet[payload_offset..]);
    //                         handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
    //                         continue;
    //                     } else if version == 6 {
    //                         fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
    //                         fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
    //                         fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
    //                         fake_ethernet_frame.set_payload(&packet[payload_offset..]);
    //                         handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
    //                         continue;
    //                     }
    //                 }
    //             }
    //             handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
    //         }
    //         Err(e) => panic!("packetdump: unable to receive packet: {}", e),
    //     }
    // }
}