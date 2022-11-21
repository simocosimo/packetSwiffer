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

    pub fn with_args(ip_source: String, ip_dest: String, port_source: String, port_dest: String, transport_protocol: String) -> Self {
        return Filter {
            ip_source,
            ip_dest,
            port_source,
            port_dest,
            transport_protocol
        };
    }

    pub fn as_array(&self) -> [String; 5] {
        return [self.ip_source.clone(), self.ip_dest.clone(), self.port_source.clone(), self.port_dest.clone(), self.transport_protocol.clone()];
    }
    
}
#[derive(Debug)]
pub struct Settings {
    pub filters: String,
    pub csv: Option<bool>,
    pub timeout: Option<i64>,
    pub filename: Option<String>,
}
impl Settings {
    pub fn new() -> Self {
        return Settings {
            filters: String::new(),
            csv: None,
            timeout: None,
            filename: None,
        }
    }
}

pub fn print_index(settings: &Vec<String>) -> () {
    let mut index = 3;
    //print!("{}[2J", 27 as char);
    println!("Packet Swiffer v.1.0");
    println!("Author: Barletta Francesco Pio, Cosimo Simone, Ferla Damiano");
    println!("Politecnico di Torino - All Rights Deserved");
    println!("\n");
    println!("1.\t Start Sniffing");
    println!("2.\t Set Filters");
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
    if args.csv == false {
        conditional_settings.push("CSV Mode".to_string());
    }
    let mut filters = Filter::new();
    let mut csv = args.csv;
    let mut timeout = args.timeout;
    let mut filename = args.filename;
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
                if conditional_settings[0] == "Set Timeout" {
                    timeout = set_timeout();
                }
                else if conditional_settings[0] == "Set Filename" {
                    filename = set_filename();
                }
                else if conditional_settings[0] == "Show Interfaces" {
                    print_interface();
                }
                else if conditional_settings[0] == "CSV Mode" {
                    println!("CSV mode? (Y/N)");
                    buffer.clear();
                    io::stdin().read_line(&mut buffer).expect("Failed to read line");
                    if buffer.trim() == "Y" {
                        csv = true;
                    }
                    else {
                        csv = false;
                    }
                }
            }
            "4" => {
                if conditional_settings[1] == "Set Filename" {
                    filename = set_filename();
                }
                else if conditional_settings[1] == "Show Interfaces" {
                    print_interface();
                }
                else if conditional_settings[1] == "CSV Mode" {
                    println!("CSV mode? (Y/N)");
                    buffer.clear();
                    io::stdin().read_line(&mut buffer).expect("Failed to read line");
                    if buffer.trim() == "Y" {
                        csv = true;
                    }
                    else {
                        csv = false;
                    }
                }
                
            }
            "5" => {
                if conditional_settings[2] == "Show interfaces" {
                    print_interface();
                }
                else if conditional_settings[2] == "CSV Mode" {
                    println!("CSV mode? (Y/N)");
                    buffer.clear();
                    io::stdin().read_line(&mut buffer).expect("Failed to read line");
                    if buffer.trim() == "Y" {
                        csv = true;
                    }
                    else {
                        csv = false;
                    }
                }
                
            }
            "6" => {
                println!("CSV mode? (Y/N)");
                buffer.clear();
                io::stdin().read_line(&mut buffer).expect("Failed to read line");
                if buffer.trim() == "Y" {
                    csv = true;
                }
                else {
                    csv = false;
                }
            }
            _ => {
                println!("Wrong command.");
            }
        }
    }
    // println!("Filters before parsing: {:?}", filters);
    let settings = Settings {
        filters: parse_filter(filters),
        csv: Some(csv),
        timeout: Some(timeout),
        filename: Some(filename),
    };
    return settings;    
}

pub fn filter_menu() -> () {
    //print!("{}[2J", 27 as char);
    println!("Filter settings:");
    println!("\n");
    println!("1.\t Filter by source IP");
    println!("2.\t Filter by destination IP");
    println!("3.\t Filter by source port");
    println!("4.\t Filter by destination port");
    println!("5.\t Filter by transport protocol");
    println!("0.\t Back to menu");
}

pub fn print_filter() -> Filter{
    let mut buffer = String::new();

    let mut vec_ip_source: Vec<String> = Vec::new();
    //let mut ip_source = String::new();
    let mut vec_ip_dest: Vec<String> = Vec::new();
    //let mut ip_dest = String::new();
    let mut vec_port_source: Vec<String> = Vec::new();
    //let mut port_source = String::new();
    let mut vec_port_dest: Vec<String> = Vec::new();
    //let mut port_dest = String::new();
    let mut vec_transport_protocol: Vec<String> = Vec::new();
    //let mut transport_protocol = String::new();

    // let mut filter = Filter::new();
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

                let ip_source = vec_ip_source.join(" or ");
                let ip_dest = vec_ip_dest.join(" or ");
                let port_source = vec_port_source.join(" or ");
                let port_dest = vec_port_dest.join(" or ");
                let transport_protocol = vec_transport_protocol.join(" or ");                

                return Filter::with_args(
                    ip_source,
                    ip_dest,
                    port_source,
                    port_dest,
                    transport_protocol,
                );
                // break;
            }
            _ => {}
        }
    }
    // return filter;
}

pub fn filter_ip_source() -> String {
    let mut buffer = String::new();
    loop {
        //print!("{}[2J", 27 as char);
        println!("Filter by source IP: \n");
        println!("Insert source IP");
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if !check_ip_address(&buffer) {
            println!("Error in the IP address");
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
        println!("Filter by destination IP: \n");
        println!("Insert destination IP");
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if !check_ip_address(&buffer) {
            println!("Error in the IP address");
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
        println!("Filter by source port: \n");
        println!("Insert source port");
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if !check_port_number(&buffer) {
            println!("Port error");
        }
        else {
            break;
        }
    }
    return "src port ".to_owned() + &buffer.trim().to_string();}

pub fn filter_port_dest() -> String {
    let mut buffer = String::new();
    loop {
        //print!("{}[2J", 27 as char);
        println!("Filter by destination port: \n");
        println!("Insert destination port");
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if !check_port_number(&buffer) {
            println!("Port error");
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
        println!("Filter by transport protocol: \n");
        println!("Insert transport protocol");
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if !check_transport_protocol(&buffer) {
            println!("Transport protocol error");
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
        let number = elem.parse::<i32>();
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
pub fn set_timeout() -> i64 {
    let mut buffer = String::new();
    loop {
        println!("Insert timeout: ");
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        if buffer.trim().parse::<i64>().is_ok() {
            println!("{}", buffer);
            break;
        }
    }
    return buffer.trim().parse::<i64>().unwrap();
}
pub fn set_filename() -> String {
    let mut buffer = String::new();
    println!("Insert name you want to save the report: ");
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
    println!("Press enter to go back to menu");
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
}
