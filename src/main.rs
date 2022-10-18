use timer;
use chrono;

use std::thread;
use std::process;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;

use std::fs::File;
use std::path::Path;
use std::io::Write;

use pcap::{Device, Capture};
use packet_swiffer::parser::handle_ethernet_frame;
use packet_swiffer::args::Args;

use clap::Parser;

fn main() {

    let args = Args::parse();
    let interface_name = args.interface;
    let promisc_mode = args.promisc;
    let report_delay = args.timeout;
    let report_fm = args.filename;
    let list_mode = args.list;

    // Find the network interface with the provided name
    let interfaces = Device::list().unwrap();

    // Handle list mode
    if list_mode {
        println!("The following interfaces are available");
        println!("{0: <20} | {1: <20}", "Name", "Description");
        println!("---------------------------------------------------------------------");
        interfaces.into_iter()
            .for_each(|i| println!("{0: <20} | {1: <20}", i.name, i.desc.unwrap_or("None".to_string())));
        process::exit(0);
    }

    println!("Promisc mode: {}", promisc_mode);
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
        .immediate_mode(true)
        .open().unwrap();

    // Channel used to pass packets between sniffing thread and parsing thread
    let (tx_thread, rx_thread) = channel::<Vec<u8>>();

    // Channel used to pass parsed packets to the report_thread
    // TODO: is string the best structure? Don't think so, maybe a custom one is better
    let (tx_report, rx_report) = channel::<String>();

    // Thread used to get packets (calls next() method)
    let sniffing_thread = thread::spawn(move | | {
        // TODO: add a mechanism to stop/resume packet sniffing
        while let Ok(packet) = cap.next_packet() {
            let owned_packet = packet.to_owned();
            tx_thread.send(owned_packet.to_vec()).unwrap();
        }
    });

    // Thread needed to perform parsing of received packet
    let parsing_thread = thread::spawn(move | | {
        // TODO: add macos/ios support
        // TODO: handle filters
        while let Ok(p) = rx_thread.recv() {
            let packet_string = handle_ethernet_frame(&cloned_interface, &p);
            // let packet_string = &p[0..10];
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
            // TODO: maybe add timestamp to report filename? Or folder is better?
            let pathname = format!("{}-{}.txt", report_fm, index);
            let path = Path::new(&pathname);
            let _guard = timer.schedule_with_delay(chrono::Duration::seconds(report_delay), move | | {
                let mut flag = timer_flag_clone.lock().unwrap();
                *flag = true;
            });
            while let Ok(packet) = rx_report.recv() {
                // TODO: here we should aggregate info about the traffic in a smart way
                let tmp_string = String::from(format!("{}", packet));
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

            writeln!(&mut file, "Report #{}\n", index).unwrap();
            writeln!(&mut file, "Interface\t| Source IP address\t| Source Port\t| Dest IP address \t| Dest Port\t| Timestamp\t|  Bytes\t| Transport \t| Application \n").unwrap();
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
}