use std::io;

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
pub fn menu() -> (){
    print_index();
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
    match buffer.as_str().trim() {
        "1" => {return}
        "2" => {print_filter()}
        _ => {println!("Wrong command.")}
    }
}

pub fn print_filter() -> (){
    print!("{}[2J", 27 as char);
    println!("Filter settings");
    println!("\n");
    println!("1.\t Setting 1");
    println!("2.\t Setting 2");
    println!("3.\t Setting 3");
    println!("...");
    println!("n.\t Setting n")
}
