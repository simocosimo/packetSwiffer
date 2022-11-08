use timer;
use chrono;

use std::thread;
use std::process;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::collections::HashMap;

use packet_swiffer::parser::{handle_ethernet_frame, Packet};
use packet_swiffer::args::Args;
use packet_swiffer::report::ReportWriter;
use packet_swiffer::report::Report;
use packet_swiffer::report::ReportHeader;

use clap::Parser;
use pcap::{Device, Capture};

fn main() {

    let args = Args::parse();
    let interface_name = args.interface;
    let promisc_mode = args.promisc;
    let report_delay = args.timeout;
    let report_fn = args.filename;
    let list_mode = args.list;
    let csv_mode = args.csv;

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
    let (tx_report, rx_report) = channel::<Packet>();

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
        while let Ok(p) = rx_thread.recv() {
            let packet_string = handle_ethernet_frame(&cloned_interface, &p);
            match packet_string {
                Ok(pk) => {
                    println!("{}", pk);
                    tx_report.send(pk).unwrap();
                },
                Err(err) => println!("Error: {}", err)
            }

        }
    });

    let timer_flag = Arc::new(Mutex::new(false));

    let report_thread = thread::spawn(move | | {
        let timer = timer::Timer::new();
        let mut index = 0;
        let filename = format!("{}", report_fn);
        loop {
            let mut buffer = Vec::<Packet>::new();
            let timer_flag_clone = timer_flag.clone();
            let _guard = timer.schedule_with_delay(chrono::Duration::seconds(report_delay), move | | {
                let mut flag = timer_flag_clone.lock().unwrap();
                *flag = true;
            });
            while let Ok(packet) = rx_report.recv() {
                buffer.push(packet);
                let mut flag = timer_flag.lock().unwrap();
                if *flag {
                    *flag = false;
                    drop(flag);
                    break;
                }
                drop(flag);
            }

            let mut report = HashMap::new();

            let mut rw = ReportWriter::new(csv_mode, filename.as_str(), index);
            rw.report_init();

            for s in buffer {
                let bytes = s.length;

                let p_header = ReportHeader {
                    src_addr: s.src_addr,
                    dest_addr: s.dest_addr,
                    src_port: s.src_port,
                    dest_port: s.dest_port
                };

                if report.contains_key(&p_header) {
                    let mut update: &mut Report = report.get_mut(&p_header).unwrap();
                    update.total_bytes += bytes as u64;
                    update.stop_time = s.timestamp;
                } else {

                    report.insert(p_header, {
                        let time = s.timestamp.clone();
                        let time2 = s.timestamp.clone();

                        Report {
                            packet: s,
                            total_bytes: bytes as u64,
                            start_time: time,
                            stop_time: time2
                        }
                    });
                }
                //writeln!(&mut file, "{}", s).unwrap();
            }

            for pk in report {
                rw.write(pk.1);
            }
            println!("[{}] Report #{} generated", chrono::offset::Local::now().naive_local(), index);
            rw.close();
            index += 1;
        }
    });

    // joining the threads as a last thing to do
    sniffing_thread.join().unwrap();
    parsing_thread.join().unwrap();
    report_thread.join().unwrap();
}