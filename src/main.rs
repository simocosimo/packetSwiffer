use std::collections::HashMap;
use timer;
use chrono;

use std::{fmt, thread};
use std::process;
use std::sync::{Arc, Mutex, Condvar};
use std::sync::mpsc::channel;

use std::fs::File;
use std::path::Path;
use std::io::Write;
use std::io;
use::packet_swiffer::menu::Settings;
use::packet_swiffer::menu::menu;

use std::net::IpAddr;

use pcap::{Device, Capture};
use packet_swiffer::parser::{handle_ethernet_frame, Packet};
use packet_swiffer::args::Args;


use clap::Parser;
use csv::WriterBuilder;
use serde::Serialize;

#[derive(PartialEq, Eq, Hash)]
pub struct ReportHeader {
    src_addr: IpAddr,
    dest_addr: IpAddr,
    src_port: Option<u16>,
    dest_port: Option<u16>
}

#[derive(Serialize)]
pub struct Report {
    packet: Packet,
    total_bytes: u64,
    start_time: String,
    stop_time: String
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //        "Interface\t| Source IP address\t| Source Port\t| Dest IP address \t| Dest Port\t| Timestamp\t|  Bytes\t| Transport \t| Application \n"
        write!(f, "| {0: <1}\t| {1: <20}\t| {2: <5}\t| {3: <25} ({4}) \t| {5: <5}\t| {6: <3}\t| {7: <4} \t| {8: <4}\t| {9: <15}\t| {10: <15}", self.packet.interface, self.packet.src_addr, self.packet.src_port.unwrap_or(0), self.packet.dest_addr, self.packet.res_name, self.packet.dest_port.unwrap_or(0), self.total_bytes, self.packet.transport, self.packet.application, self.start_time, self.stop_time )
    }
}

fn main() {

    let args = Args::parse();
    let interface_name = args.interface;
    let promisc_mode = args.promisc;
    let report_delay = args.timeout;
    let report_fm = args.filename;
    let list_mode = args.list;
    
    // Print menu
    let mut settings = Settings::new();
    settings = menu();
    
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
    let (tx_report, rx_report) = channel::<Packet>();

    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let pair2 = Arc::clone(&pair);
    let pair3 = Arc::clone(&pair);

    // Thread used to get packets (calls next() method)
    let sniffing_thread = thread::spawn(move | | {
        let (lock, cvar) = &*pair;
        println!("Premi il tasto P per mettere in pausa lo sniffing");
        if settings.filters != "" {
            cap.filter(&settings.filters, false).unwrap();
        }
        while let Ok(packet) = cap.next_packet() {
            let mut pause = lock.lock().unwrap();
            let owned_packet = packet.to_owned();
            if !*pause {
                tx_thread.send(owned_packet.to_vec()).unwrap();
            }
            drop(lock);
        }
    });

    // Thread used to pause/resume
    let pause_thread = thread::spawn(move || {
        let (lock, cvar) = &*pair2;
        let mut buffer = String::new();
        loop {
            buffer.clear();
            io::stdin().read_line(&mut buffer).expect("Failed to read line");
            match buffer.as_str().trim() {
                "P" => {
                    let mut pause = lock.lock().unwrap();
                    println!("Controllo a pause_thread");
                    if *pause == true {
                        *pause = false;
                        println!("Sniffing ripreso!");
                    }
                    else {
                        *pause = true;
                        println!("Sniffing stoppato!");
                    }
                    io::stdout().flush().unwrap();
                    drop(pause);
                }
                _ => {}
            }
            
        }
    });

    // Thread needed to perform parsing of received packet
    let parsing_thread = thread::spawn(move | | {
        // TODO: add macos/ios support
        while let Ok(p) = rx_thread.recv() {
            let packet_string = handle_ethernet_frame(&cloned_interface, &p);
            // let packet_string = &p[0..10];
            match packet_string {
                Ok(pk) => {
                    println!("{}", pk);
                    tx_report.send(pk).unwrap();
                },
                Err(err) => println!("Error: {}", err)
            }

        }
    });

    // TODO: temporary shared data to test report generation
    let timer_flag = Arc::new(Mutex::new(false));


    // TODO: create thread that analyze packets and produce report (synch should be done with mutex on structure)
    let report_thread = thread::spawn(move | | {
        let timer = timer::Timer::new();
        let timer_flag_clone = timer_flag.clone();
        let mut index = 0;
        let _guard_timer = timer.schedule_repeating(chrono::Duration::seconds(settings.timeout.into()), move || {
            // Prendi pause lock
            // Controlla se pause == true
            // Se si, drop(guard_timer)
            let (lock, cvar) = &*pair3;
            let mut pause_flag = lock.lock().unwrap();
            if *pause_flag == false{
                let mut flag = timer_flag_clone.lock().unwrap();
                *flag = true;
            }
            drop(pause_flag);
        });
        loop {
            let mut buffer = Vec::<Packet>::new();
            let timer_flag_clone = timer_flag.clone();
            // TODO: maybe add timestamp to report filename? Or folder is better?
            let pathname = format!("{}-{}.txt", settings.filename, index);
            let csv_pathname = format!("{}-{}.csv", settings.filename, index);
            let mut csv_wrt = WriterBuilder::new().has_headers(false).from_path(csv_pathname).unwrap();
            csv_wrt.write_record(
                &["interface", "src_addr", "dest_addr",
                    "res_name", "src_port", "dest_port", "transport", "application",
                    "tot_bytes", "start_time", "stop_time"]
            ).unwrap();
            let path = Path::new(&pathname);

            while let Ok(packet) = rx_report.recv() {
                // TODO: here we should aggregate info about the traffic in a smart way
                // let tmp_string = String::from(format!("{}", packet));
                buffer.push(packet);
                let mut flag = timer_flag.lock().unwrap();
                if *flag{
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

            let mut report = HashMap::new();

            writeln!(&mut file, "Report #{}\n", index).unwrap();
            writeln!(&mut file, "| Interface\t| Source IP address\t| Source Port\t| Dest IP address \t| Dest Port\t| Tot Bytes\t| Transport \t| Application \t| First Timestamp \t| Last Timestamp \n").unwrap();

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
                writeln!(&mut file, "{}", pk.1).unwrap();
                csv_wrt.serialize(pk.1).unwrap();
            }
            println!("[{}] Report #{} generated", chrono::offset::Local::now(), index);
            csv_wrt.flush().unwrap();
            index += 1;
        }
    });

    // joining the threads as a last thing to do
    pause_thread.join().unwrap();
    sniffing_thread.join().unwrap();
    parsing_thread.join().unwrap();
    report_thread.join().unwrap();
}