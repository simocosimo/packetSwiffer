use std::io;
use crate::args::Args;
use clap::Parser;
use pcap::Device;

#[derive(Debug)]
pub struct Filter{
    pub ip_source: String,
    pub ip_dest: String,
    pub port_source: String,
    pub port_dest: String,
    pub transport_protocol: String,
}
impl Filter {
    pub fn new() -> Self {
        return Filter{ip_source: String::new(),
                      ip_dest: String::new(),
                      port_source: String::new(),
                      port_dest: String::new(),
                      transport_protocol: String::new()};
    }
    pub fn as_array(&self) -> [String; 5] {
        return [self.ip_source.clone(), self.ip_dest.clone(), self.port_source.clone(), self.port_dest.clone(), self.transport_protocol.clone()];
    }
    
}
#[derive(Debug)]
pub struct Settings {
    pub filters: String,
    pub csv: bool, 
    pub timeout: u32,
    pub filename: String,
    // Aggiungere altri campi
}
impl Settings {
    pub fn new() -> Self {
        return Settings {
            filters: String::new(),
            csv: false,
            timeout: 10,
            filename: String::new(),
        }
    }
}

pub fn print_index(settings: &Vec<String>) -> () {
    let mut index = 4;
    //print!("{}[2J", 27 as char);
    println!("Packet Swiffer v.1.0");
    println!("Author: Barletta Francesco Pio, Cosimo Simone, Ferla Damiano");
    println!("Politecnico di Torino - All Rights Deserved");
    println!("\n");
    println!("1.\t Start Sniffing");
    println!("2.\t Set Filters");
    println!("3.\t CSV mode");
    for setting in settings {
        println!("{}.\t {}", index, setting);
        index += 1;
    }
    println!("\n\n");
    println!("While sniffing, press P to stop/resume");
}

/*
Da sistemare la struct da popolare
*/
pub fn menu() -> Settings {
    let args = Args::parse();
    let mut conditional_settings = Vec::<String>::new();
    if args.timeout == 10 {
        conditional_settings.push("Set Timeout".to_string());
    }
    if args.filename == "report" {
        conditional_settings.push("Set Filename".to_string());
    }
    if args.list == false {
        conditional_settings.push("Show Interfaces".to_string());
    }
    let mut filters = Filter::new();
    let mut csv = false;
    let mut timeout = 10;
    let mut filename = "report".to_string();
    loop {
        print_index(&conditional_settings);
        let mut buffer = String::new();
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        match buffer.as_str().trim() {
            "1" => {
                break;
             }
            "2" => {
                filters = print_filter();
            }
            "3" => {
                println!("CSV mode? (Y/N)");
                buffer.clear();
                io::stdin().read_line(&mut buffer).expect("Failed to read line");
                if buffer.trim() == "Y" {
                    csv = true;
                }
            }
            "4" => {
                if conditional_settings[0] == "Set Timeout" {
                    timeout = set_timeout();
                }
                else if conditional_settings[0] == "Set Filename" {
                    filename = set_filename();
                }
                else if conditional_settings[0] == "Show Interfaces" {
                    print_interface();
                }
            }
            "5" => {
                if conditional_settings[1] == "Set Filename" {
                    filename = set_filename();
                }
                else if conditional_settings[1] == "Show Interfaces" {
                    print_interface();
                }
            }
            "6" => {
                print_interface();
            }
            _ => {
                println!("Wrong command.");
            }
        }
    }
    let mut settings = Settings {
        filters: parse_filter(filters),
        csv: csv,
        timeout: timeout,
        filename: filename,
    };
    return settings;    
}

pub fn filter_menu() -> () {
    //print!("{}[2J", 27 as char);
    println!("Filter settings:");
    println!("\n");
    println!("1.\t Filtra per indirizzo IP sorgente");
    println!("2.\t Filtra per indirizzo IP destinazione");
    println!("3.\t Filtra per porta sorgente");
    println!("4.\t Filtra per porta destinazione");
    println!("5.\t Filtra per protocollo di trasporto");
    println!("0.\t Back to menu");
}

pub fn print_filter() -> Filter{
    let mut buffer = String::new();

    let mut vec_ip_source: Vec<String> = Vec::new();
    let mut ip_source = String::new();
    let mut vec_ip_dest: Vec<String> = Vec::new();
    let mut ip_dest = String::new();
    let mut vec_port_source: Vec<String> = Vec::new();
    let mut port_source = String::new();
    let mut vec_port_dest: Vec<String> = Vec::new();
    let mut port_dest = String::new();
    let mut vec_transport_protocol: Vec<String> = Vec::new();
    let mut transport_protocol = String::new();

    let mut filter = Filter::new();
    loop {
        filter_menu();
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        match buffer.as_str().trim() {
            "1" => {
                vec_ip_source.push(filter_ip_source());
                buffer.clear();
            }
            "2" => {
                vec_ip_dest.push(filter_ip_dest());
                buffer.clear();
            }
            "3" => {
                vec_port_source.push(filter_port_source());
                buffer.clear();
            }
            "4" => {
                vec_port_dest.push(filter_port_dest());
                buffer.clear();
            }
            "5" => {
                vec_transport_protocol.push(filter_transport_protocol());
                buffer.clear();
            }
            "0" => {

                ip_source = vec_ip_source.join(" or ");
                ip_dest = vec_ip_dest.join(" or ");
                port_source = vec_port_source.join(" or ");
                port_dest = vec_port_dest.join(" or ");
                transport_protocol = vec_transport_protocol.join(" or ");                

                filter = Filter{
                    ip_source: ip_source,
                    ip_dest: ip_dest,
                    port_source: port_source,
                    port_dest: port_dest,
                    transport_protocol: transport_protocol,
                };
                break;
            }
            _ => {}
        }
    }
    return filter;   
}

pub fn filter_ip_source() -> String {
    let mut buffer = String::new();
    loop {
        //print!("{}[2J", 27 as char);
        println!("Filtra per indirizzo IP sorgente: \n");
        println!("Inserisci indirizzo IP sorgente");
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if !check_ip_address(&buffer) {
            println!("Errore nell'indirizzo IP");
        }
        else {
            break;
        }
    }
    return "src host ".to_owned() + &buffer.trim().to_string();}

pub fn filter_ip_dest() -> String {
    let mut buffer = String::new();
    loop {
        //print!("{}[2J", 27 as char);
        println!("Filtra per indirizzo IP destinazione: \n");
        println!("Inserisci indirizzo IP destinazione");
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if !check_ip_address(&buffer) {
            println!("Errore nell'indirizzo IP");
        }
        else {
            break;
        }
    }
    return "dst host ".to_owned() + &buffer.trim().to_string();}

pub fn filter_port_source() -> String {
    let mut buffer = String::new();
    loop {
        //print!("{}[2J", 27 as char);
        println!("Filtra per porta sorgente: \n");
        println!("Inserisci porta sorgente");
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if !check_port_number(&buffer) {
            println!("Errore nella porta");
        }
        else {
            break;
        }
    }
    return "src port ".to_owned() + &buffer.trim().to_string();}

pub fn filter_port_dest() -> String {
    let mut buffer = String::new();
    loop {
        print!("{}[2J", 27 as char);
        println!("Filtra per porta destinazione: \n");
        println!("Inserisci porta destinazione");
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if !check_port_number(&buffer) {
            println!("Errore nella porta");
        }
        else {
            break;
        }
    }
    return "dst port ".to_owned() + &buffer.trim().to_string();}

pub fn filter_transport_protocol() -> String {
    let mut buffer = String::new();
    loop {
        //print!("{}[2J", 27 as char);
        println!("Filtra per protocollo di trasporto: \n");
        println!("Inserisci protocollo di trasporto");
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if !check_transport_protocol(&buffer) {
            println!("Errore nel tipo di protocollo digitato.");
        }
        else {
            if buffer == "tcp\n" || buffer == "udp\n" || buffer == "icmp\n" {
                buffer = "\\".to_owned() + &buffer;
            }
            break;
        }
    }
    return "ip proto ".to_owned() + &buffer.trim().to_string();}


pub fn parse_filter(filter: Filter) -> String {
    let filter_array: Vec<String> = filter.as_array().into_iter().filter(|x| x != "").collect();
    let filter_string = filter_array.join(" or ");
    return filter_string;
}
pub fn check_transport_protocol(string: &String) -> bool {
    let possible = vec![String::from("icmp\n"), String::from("icmp6\n"), String::from("igmp\n"),
                        String::from("igrp\n"), String::from("pim\n"), String::from("ah\n"),
                        String::from("esp\n"), String::from("vrrp\n"), String::from("udp\n"), String::from("tcp\n")];
    return possible.contains(string);
}
pub fn check_ip_address(string: &String) -> bool {
    let mut space = true;
    let splitted: Vec<&str> = string.trim().split(".").collect();
    for elem in &splitted {
        let mut number = elem.parse::<i32>();
        if number.is_ok() {
            if number.as_ref().unwrap() > &255 || number.unwrap() < 0 {
                space = false;
            }
        }
        else {
            space = false;
        }
    }
    return splitted.len() == 4 && space;
}
pub fn check_port_number(string: &String) -> bool {
    let number = string.trim().parse::<i32>();
    if number.is_ok() {
        if number.as_ref().unwrap() > &0 && number.unwrap() < 65535 {
            return true;
        }
    } 
    return false;
}
pub fn set_timeout() -> u32 {
    let mut buffer = String::new();
    loop {
        println!("Inserisci timeout: ");
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if buffer.trim().parse::<u32>().is_ok() {
            println!("{}", buffer);
            break;
        }
    }
    return buffer.trim().parse::<u32>().unwrap();
}
pub fn set_filename() -> String {
    let mut buffer = String::new();
    println!("Inserisci il nome con cui vuoi salvare il report: ");
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
    return buffer.trim().to_string();
}
pub fn print_interface() -> () {
    let interfaces = Device::list().unwrap();
    println!("The following interfaces are available");
    println!("{0: <20} | {1: <20}", "Name", "Description");
    println!("---------------------------------------------------------------------");
    interfaces.into_iter()
        .for_each(|i| println!("{0: <20} | {1: <20}", i.name, i.desc.unwrap_or("None".to_string())));
    let mut buffer = String::new();
    println!("Premi un bottone per tornare al menù principale");
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
}
