use std::{env, thread};
use std::process;
use std::sync::mpsc::channel;
use cursive::reexports::crossbeam_channel::unbounded;

use packet_swiffer::tui::Tui;
use pcap::{Device, Capture};
use packet_swiffer::parser::handle_ethernet_frame;

fn main() {

    // TODO: handle all arguments with clap
    let ui_flag = match env::args().nth(3) {
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

    let interface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            eprintln!("USAGE: swiffer <NETWORK INTERFACE>");
            process::exit(1);
        }
    };

    let promisc_mode = env::args().nth(2) == Some("--promisc".to_string());
    println!("Promisc mode: {}", promisc_mode);

    // Find the network interface with the provided name
    let interfaces = Device::list().unwrap();
    let interface = interfaces
        .into_iter()
        .filter(|i| i.name == interface_name)
        .next()
        .unwrap_or_else(|| {
            eprintln!("No such network interface: {}", interface_name);
            process::exit(1);
        });
    let cloned_interface = interface.clone();

    // Setting up pcap capture
    let mut cap = Capture::from_device(interface).unwrap()
        .promisc(promisc_mode)
        // .timeout(10)    // this is needed to read packets in real time
        .immediate_mode(true)
        .open().unwrap();

    // Channel used to pass packets between sniffing thread and parsing thread
    let (tx_thread, rx_thread) = channel::<Vec<u8>>();

    // Thread used to get packets (calls next() method)
    let sniffing_thread = thread::spawn(move | | {
        // TODO: add a mechanism to stop/resume packet sniffing
        while let Ok(packet) = cap.next_packet() {
            let owned_packet = packet.to_owned();
            tx_thread.send(owned_packet.to_vec()).unwrap();
        }
    });

    let thread_ui_flag = ui_flag.clone();
    // Thread needed to perform parsing of received packet
    let parsing_thread = thread::spawn(move | | {
        // TODO: add macos/ios support
        // TODO: handle filters
        while let Ok(p) = rx_thread.recv() {
            let packet_string = handle_ethernet_frame(&cloned_interface, &p);
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