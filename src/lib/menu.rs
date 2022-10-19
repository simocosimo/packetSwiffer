use std::io;
#[derive(Debug)]
pub struct Filter{
    ip_source: String,
    ip_dest: String,
}
impl Filter {
    pub fn new() -> Self {
        return Filter{ip_source: "".to_string(), ip_dest: "".to_string()};
    }
    
    pub fn set_ip_source(self, ip_source: String) -> Self {
        return Filter{ip_source: ip_source, ip_dest: self.ip_dest};
    }

    
    pub fn set_ip_dest(self, ip_dest: String) -> Self {
        return Filter{ip_source: self.ip_source, ip_dest: ip_dest};
    }
    

}

pub fn print_index() -> () {
    print!("{}[2J", 27 as char);
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
pub fn menu() -> Filter {
    let mut filters = Filter::new();
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
    return filters;    
}

pub fn filter_menu() -> () {
    print!("{}[2J", 27 as char);
    println!("Filter settings:");
    println!("\n");
    println!("1.\t Filtra per indirizzo IP sorgente");
    println!("2.\t Filtra per indirizzo IP destinazione");
    println!("3.\t Filtra per porta sorgente");
    println!("4.\t Filtra per porta destinazione");
    println!("0.\t Back to menu");
}

pub fn print_filter() -> Filter{
    let mut buffer = String::new();
    let mut ip_source = String::new();
    let mut ip_dest = String::new();
    let mut filter = Filter::new();
    loop {
        filter_menu();
        buffer.clear();
        io::stdin().read_line(&mut buffer).expect("Failed to read line");
        match buffer.as_str().trim() {
            "1" => {
                ip_source = filter_ip_source();
                buffer.clear();
            }
            "2" => {
                ip_dest = filter_ip_dest();
                buffer.clear();
            }
            "0" => {
                filter = Filter{
                    ip_source: ("src host ".to_string() + &ip_source).trim().to_string(),
                    ip_dest: ("dst host ".to_string() + &ip_dest).trim().to_string(),
                };
                break;
            }
            _ => {}
        }
    }
    return filter;   
}

pub fn filter_ip_source() -> String {
    print!("{}[2J", 27 as char);
    println!("Filtra per indirizzo IP sorgente: \n");
    println!("Inserisci indirizzo IP sorgente");
    let mut buffer = String::new();
    buffer.clear();
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
    return buffer;
}

pub fn filter_ip_dest() -> String {
    print!("{}[2J", 27 as char);
    println!("Filtra per indirizzo IP destinazione: \n");
    println!("Inserisci indirizzo IP destinazione");
    let mut buffer = String::new();
    buffer.clear();
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
    return buffer;
}