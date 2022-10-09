use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};

use std::{env, thread};
use std::fmt::format;
use std::process;
use std::sync::mpsc::channel;
use cursive::Cursive;
use cursive::event::{Callback, EventTrigger};
use cursive::traits::{Nameable, Scrollable};
use cursive::view::{ScrollStrategy, SizeConstraint};

use packet_swiffer::parsing_utils::handle_ethernet_frame;

use cursive::views::{TextView, LinearLayout, Panel, BoxedView, ResizedView, Dialog};

fn main() {
    use pnet::datalink::Channel::Ethernet;

    // Creating the tui
    let mut siv = cursive::default();
    let sink = siv.cb_sink().clone();
    siv.add_global_callback('q', |s| quit(s));

    siv.add_fullscreen_layer(
        ResizedView::with_full_width(
            LinearLayout::vertical().child(
                Panel::new(
                    TextView::new("")
                        .with_name("main")
                        .scrollable()
                        .scroll_strategy(ScrollStrategy::StickToBottom)
                )
            ).child(
                Panel::new(
                    TextView::new("Press q to quit.").with_name("info")
                )
            )
        )
    );

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

    // Channel to send parsed packets to ui
    let (tx_ui, rx_ui) = channel::<String>();

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
            // println!("{}", packet_string);
            // The sink send the callback to the main thread, where it is executed
            // TODO: this generates too many callbacks in the main thread, leading to the interface
            // TODO: lagging. We may need to decrease callbacks by sending packets in bundles
            sink.send(Box::new(move |s| {
                let mut packet_view = s.find_name::<TextView>("main").unwrap();
                packet_view.append(format!("\n{}", packet_string));
            })).unwrap();
        }
    });

    // TODO: create thread that analyze packets and produce report (synch should be done with mutex on structure)
    let report_thread = thread::spawn(move | | {

    });

    siv.run();

    // joining the threads as a last thing to do
    // sniffing_thread.join().unwrap();
    // parsing_thread.join().unwrap();
    // report_thread.join().unwrap();
}

fn quit(siv: &mut Cursive) {
    siv.add_layer(Dialog::around(TextView::new("Do you really want to stop the sniffing?"))
        .title("Exit?")
        .button("Quit", |s| s.quit())
        .button("Cancel", |s| { s.pop_layer(); })
    );
}