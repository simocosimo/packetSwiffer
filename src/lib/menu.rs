use std::io;
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
    // Aggiungere altri campi
}
impl Settings {
    pub fn new() -> Self {
        return Settings {
            filters: String::new(),
            csv: false,
        }
    }
}

pub fn print_index() -> () {
    //print!("{}[2J", 27 as char);
    println!("Packet Swiffer v.1.0");
    println!("Author: Barletta Francesco Pio, Cosimo Simone, Ferla Damiano");
    println!("Politecnico di Torino - All Rights Deserved");
    println!("\n");
    
    println!("1.\t Start Sniffing");
    println!("2.\t Set Filters");
    println!("\n\n");
    println!("While sniffing, press P to stop/resume");
}

/*
Da sistemare la struct da popolare
*/
pub fn menu() -> Settings {
    let mut filters = Filter::new();
    let mut csv = false;
    loop {
        print_index();
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
            _ => {
                println!("Wrong command.");
            }
        }
    }
    let mut settings = Settings {
        filters: parse_filter(filters),
        csv: csv,
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
    //print!("{}[2J", 27 as char);
    println!("Filtra per indirizzo IP sorgente: \n");
    println!("Inserisci indirizzo IP sorgente");
    let mut buffer = String::new();
    buffer.clear();
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
    return "src host ".to_owned() + &buffer.trim().to_string();}

pub fn filter_ip_dest() -> String {
    print!("{}[2J", 27 as char);
    println!("Filtra per indirizzo IP destinazione: \n");
    println!("Inserisci indirizzo IP destinazione");
    let mut buffer = String::new();
    buffer.clear();
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
    return "dst host ".to_owned() + &buffer.trim().to_string();}

pub fn filter_port_source() -> String {
    print!("{}[2J", 27 as char);
    println!("Filtra per porta sorgente: \n");
    println!("Inserisci porta sorgente");
    let mut buffer = String::new();
    buffer.clear();
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
    return "src port ".to_owned() + &buffer.trim().to_string();}

pub fn filter_port_dest() -> String {
    print!("{}[2J", 27 as char);
    println!("Filtra per porta destinazione: \n");
    println!("Inserisci porta destinazione");
    let mut buffer = String::new();
    buffer.clear();
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
    return "dst port ".to_owned() + &buffer.trim().to_string();}

pub fn filter_transport_protocol() -> String {
    print!("{}[2J", 27 as char);
    println!("Filtra per protocollo di trasporto: \n");
    println!("Inserisci protocollo di trasporto");
    let mut buffer = String::new();
    buffer.clear();
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
    if buffer == "tcp\n" || buffer == "udp\n" || buffer == "icmp\n" {
        buffer = "\\".to_owned() + &buffer;
    }
    return "ip proto ".to_owned() + &buffer.trim().to_string();}


pub fn parse_filter(filter: Filter) -> String {
    let filter_array: Vec<String> = filter.as_array().into_iter().filter(|x| x != "").collect();
    let filter_string = filter_array.join(" or ");
    return filter_string;
}
