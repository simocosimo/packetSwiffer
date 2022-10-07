use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};

use timer;
use chrono;

use std::{env, thread};
use std::fmt::format;
use std::process;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;

use std::fs::File;
use std::path::Path;
use std::io::Write;

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
    // TODO: set interface to promiscuous mode
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

    // Channel used to pass parsed packets to the report_thread
    // TODO: is string the best structure? Don't think so, maybe a custom one is better
    let (tx_report, rx_report) = channel::<String>();

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
            tx_report.send(packet_string).unwrap();
        }
    });

    // TODO: temporary shared data to test report generation
    let timer_flag = Arc::new(Mutex::new(false));

    // TODO: create thread that analyze packets and produce report (synch should be done with mutex on structure)
    let report_thread = thread::spawn(move | | {
        let timer = timer::Timer::new();
        let mut index = 0;
        loop {
            let mut buffer = Vec::<String>::new();
            let timer_flag_clone = timer_flag.clone();
            let pathname = format!("report-{}.txt", index);
            let path = Path::new(&pathname);
            let _guard = timer.schedule_with_delay(chrono::Duration::seconds(10), move | | {
                let mut flag = timer_flag_clone.lock().unwrap();
                *flag = true;
            });
            while let Ok(packet) = rx_report.recv() {
                // TODO: here we should aggregate info about the traffic in a smart way
                let tmp_string = String::from(format!("REPORT: {}", packet));
                buffer.push(tmp_string);
                let mut flag = timer_flag.lock().unwrap();
                if *flag {
                    *flag = false;
                    drop(flag);
                    break;
                }
                drop(flag);
            }
            // TODO: create a file for every report, just temporary, discuss better solutions
            // Write info on report file
            let mut file = match File::create(&path) {
                Err(why) => panic!("couldn't create {}: {}", path.display(), why),
                Ok(file) => file,
            };

            writeln!(&mut file, "Report #{}", index).unwrap();
            for s in buffer {
                writeln!(&mut file, "{}", s).unwrap();
            }
            println!("[{}] Report #{} generated", chrono::offset::Local::now(), index);
            index += 1;
        }
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