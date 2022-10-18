use timer;
use chrono;

use std::{env, thread};
use std::process;
use std::sync::{Arc, Mutex, Condvar};
use std::sync::mpsc::channel;

use std::fs::File;
use std::path::Path;
use std::io::Write;
use std::io;

use pcap::{Device, Capture};
use packet_swiffer::parser::handle_ethernet_frame;

fn main() {
    
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

    // Channel used to pass parsed packets to the report_thread
    // TODO: is string the best structure? Don't think so, maybe a custom one is better
    let (tx_report, rx_report) = channel::<String>();

    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let pair2 = Arc::clone(&pair);
    let pair3 = Arc::clone(&pair);

    // Thread used to get packets (calls next() method)
    let sniffing_thread = thread::spawn(move | | {
        let (lock, cvar) = &*pair;
        println!("Premi il tasto P per mettere in pausa lo sniffing");
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
        let (lock, cvar) = &*pair3;
        loop {
            let mut buffer = Vec::<String>::new();
            let timer_flag_clone = timer_flag.clone();
            let pathname = format!("report-{}.txt", index);
            let path = Path::new(&pathname);
            let _guard_timer = timer.schedule_with_delay(chrono::Duration::seconds(10), move || {
                // Prendi pause lock
                // Controlla se pause == true
                // Se si, drop(guard_timer)
                let mut flag = timer_flag_clone.lock().unwrap();
                *flag = true;
            });

            while let Ok(packet) = rx_report.recv() {
                // TODO: here we should aggregate info about the traffic in a smart way
                let tmp_string = String::from(format!("REPORT: {}", packet));
                buffer.push(tmp_string);
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

            writeln!(&mut file, "Report #{}", index).unwrap();
            for s in buffer {
                writeln!(&mut file, "{}", s).unwrap();
            }
            println!("[{}] Report #{} generated", chrono::offset::Local::now(), index);
            index += 1;
        }
    });

    // joining the threads as a last thing to do
    pause_thread.join().unwrap();
    sniffing_thread.join().unwrap();
    parsing_thread.join().unwrap();
    report_thread.join().unwrap();
}