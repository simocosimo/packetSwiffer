use timer;
use chrono;

use std::thread;
use std::process;
use std::sync::{Arc, Mutex, Condvar};
use std::sync::mpsc::channel;

use std::io::Write;
use std::io;
use std::string::String;

use pcap::{Device, Capture};
use packet_swiffer::parser::{handle_ethernet_frame, Packet};
use packet_swiffer::args::Args;
use packet_swiffer::report::{produce_hashmap, ReportWriter, setup_directory};
use::packet_swiffer::menu::menu;

use clap::Parser;

fn main() {

    let args = Args::parse();
    let interface_name = args.interface;
    let list_mode = args.list;
    let promisc_mode = args.promisc;

    // Find the network interface with the provided name
    let interfaces = Device::list().unwrap();

    // Handle list mode
    if list_mode && interface_name == "listview__".to_string() {
        println!("The following interfaces are available");
        println!("{0: <20} | {1: <20}", "Name", "Description");
        println!("---------------------------------------------------------------------");
        interfaces.into_iter()
            .for_each(|i| println!("{0: <20} | {1: <20}", i.name, i.desc.unwrap_or("None".to_string())));
        process::exit(0);
    }

    if !list_mode && interface_name == "listview__".to_string() {
        eprintln!("Error - Specify at least one of the following arguments\n\t-i, --interface:\tName of the interface to be used for the sniffing");
        eprintln!("\t-l, --list:\t\tShow the net interfaces present in the system without launching the sniffing");
        process::exit(1);
    }

    // Print menu
    let settings = menu();
    // println!("Filters in main: {}", settings.filters);
    let report_fn = if settings.filename.is_some() { settings.filename.unwrap() } else { args.filename };
    let csv_mode = if settings.csv.is_some() { settings.csv.unwrap() } else { args.csv };
    let timeout = if settings.timeout.is_some() { settings.timeout.unwrap() } else { args.timeout };

    // println!("Promisc mode: {}", promisc_mode);
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

    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let pair2 = Arc::clone(&pair);
    let pair3 = Arc::clone(&pair);

    // Thread used to get packets (calls next() method)
    let sniffing_thread = thread::spawn(move | | {
        let (lock, _cvar) = &*pair;
        // println!("Premi il tasto P per mettere in pausa lo sniffing");
        if settings.filters != "" {
            cap.filter(&settings.filters, false).unwrap();
        }
        while let Ok(packet) = cap.next_packet() {
            let pause = lock.lock().unwrap();
            let owned_packet = packet.to_owned();
            if !*pause {
                tx_thread.send(owned_packet.to_vec()).unwrap();
            }
            drop(lock);
        }
    });

    // Thread used to pause/resume
    let pause_thread = thread::spawn(move || {
        let (lock, _cvar) = &*pair2;
        let mut buffer = String::new();
        loop {
            buffer.clear();
            io::stdin().read_line(&mut buffer).expect("Failed to read line");
            match buffer.as_str().trim() {
                "P" => {
                    let mut pause = lock.lock().unwrap();
                    // println!("Controllo a pause_thread");
                    if *pause == true {
                        *pause = false;
                        println!("Sniffing resumed!");
                    }
                    else {
                        *pause = true;
                        println!("Sniffing paused!");
                    }
                    io::stdout().flush().unwrap();
                    drop(pause);
                }
                _ => {}
            }
            
        }
    });
    let packet_arrived = Arc::new(Mutex::new(false));
    let packet_arrived_parsing_clone = packet_arrived.clone();
    let packet_arrived_report_clone = packet_arrived.clone();

    // Thread needed to perform parsing of received packet
    let parsing_thread = thread::spawn(move | | {

        while let Ok(p) = rx_thread.recv() {
            // Segnalo che il pacchetto sia arrivato
            let mut packet_arrived_flag = packet_arrived_parsing_clone.lock().unwrap();
            *packet_arrived_flag = true;
            drop(packet_arrived_flag);

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
        let timer_flag_clone = timer_flag.clone();
        let mut index = 0;
        let filename = format!("{}", report_fn);

        let _guard_timer = timer.schedule_repeating(chrono::Duration::seconds(timeout.into()), move || {
            let (lock, _cvar) = &*pair3;
            let packet_arrived_flag = packet_arrived_report_clone.lock().unwrap();
            let pause_flag = lock.lock().unwrap();
            if *pause_flag == false && *packet_arrived_flag == true {
                let mut flag = timer_flag_clone.lock().unwrap();
                *flag = true;
                drop(flag);
            }
            drop(pause_flag);
            drop(packet_arrived_flag);
        });

        // Create the directory for the sniffing reports
        let dirname = setup_directory(&filename);

        loop {
            let mut buffer = Vec::<Packet>::new();
            
            while let Ok(packet) = rx_report.recv() {
                buffer.push(packet);
                let mut flag = timer_flag.lock().unwrap();
                if *flag{
                    *flag = false;
                    drop(flag);
                    break;
                }
                drop(flag);
            }

            let mut rw = ReportWriter::new(csv_mode, &dirname, &filename, index);
            rw.report_init();

            let report = produce_hashmap(buffer);
            for (_, info) in report {
                rw.write(info);
            }

            println!("[{}] Report #{} generated", chrono::offset::Local::now().naive_local(), index);
            rw.close();
            index += 1;
        }
    });

    // joining the threads as a last thing to do
    pause_thread.join().unwrap();
    sniffing_thread.join().unwrap();
    parsing_thread.join().unwrap();
    report_thread.join().unwrap();
}