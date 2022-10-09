use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;

use std::{env, thread};
use std::process;
use std::sync::mpsc::channel;
use cursive::reexports::crossbeam_channel::unbounded;

use packet_swiffer::parsing_utils::handle_ethernet_frame;
use packet_swiffer::tui::Tui;

fn main() {
    use pnet::datalink::Channel::Ethernet;

    // TODO: handle all arguments with clap
    let ui_flag = match env::args().nth(2) {
        Some(str) => str == "--tui".to_string(),
        None => false
    };

    // Creating the tui
    let mut tui = Tui::new(ui_flag);
    let sink = match tui.is_used() {
        true => tui.get_cloned_sink(),
        false => unbounded().0
    };
    if ui_flag { tui.draw(); }

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
    let thread_ui_flag = ui_flag.clone();
    // Thread needed to perform parsing of received packet
    let parsing_thread = thread::spawn(move | | {
        // TODO: add macos/ios support
        // TODO: handle filters
        while let Ok(p) = rx_thread.recv() {
            let packet_string = handle_ethernet_frame(&cloned_interface, &EthernetPacket::new(&p).unwrap());
            if thread_ui_flag {
                // The sink send the callback to the main thread, where it is executed
                // TODO: this generates too many callbacks in the main thread, leading to the interface
                // TODO: lagging. We may need to decrease callbacks by sending packets in bundles
                sink.send(Box::new(move |s|
                    Tui::append_to_TextView(s, "main", format!("\n{}", packet_string))
                )).unwrap();
            } else {
                println!("{}", packet_string);
            }
        }
    });

    // TODO: create thread that analyze packets and produce report (synch should be done with mutex on structure)
    let report_thread = thread::spawn(move | | {

    });

    if ui_flag { tui.run(); }
    else {
        // joining the threads as a last thing to do
        sniffing_thread.join().unwrap();
        parsing_thread.join().unwrap();
        report_thread.join().unwrap();
    }
}