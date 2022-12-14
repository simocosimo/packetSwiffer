use std::collections::HashMap;
use std::fmt;
use std::fs::{create_dir, File, set_permissions};
use std::path::Path;
use std::net::IpAddr;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use csv::{Writer, WriterBuilder};
use serde::Serialize;

use crate::report::Reporter::{CSV, TXT};
use crate::parser::Packet;

#[derive(PartialEq, Eq, Hash)]
pub struct ReportHeader {
    pub src_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub src_port: Option<u16>,
    pub dest_port: Option<u16>
}

#[derive(Serialize)]
pub struct Report {
    pub packet: Packet,
    pub total_bytes: u64,
    pub start_time: String,
    pub stop_time: String
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //        "Interface\t| Source IP address\t| Source Port\t| Dest IP address \t| Dest Port\t| Timestamp\t|  Bytes\t| Transport \t| Application \n"
        write!(f, "| {0: <1}\t| {1: <20}\t| {2: <5}\t| {3: <25} ({4}) \t| {5: <5}\t| {6: <3}\t| {7: <4} \t| {8: <4}\t| {9: <15}\t| {10: <15}", self.packet.interface, self.packet.src_addr, self.packet.src_port.unwrap_or(0), self.packet.dest_addr, self.packet.res_name, self.packet.dest_port.unwrap_or(0), self.total_bytes, self.packet.transport, self.packet.application, self.start_time, self.stop_time )
    }
}

pub enum Reporter <'a> {
    CSV(&'a mut Writer<File>),
    TXT(&'a mut File)
}

pub struct ReportWriter {
    pub csv_mode: bool,
    pub filename: String,
    csv_writer: Option<Box<Writer<File>>>,
    txt_writer: Option<Box<File>>
}

impl ReportWriter {
    pub fn new(csv_mode: bool, folder: &str, filename: &str, index: i32) -> Self {
        match csv_mode {
            true => {
                let file = match WriterBuilder::new().has_headers(false).from_path(
                    format!("{}/{}-{}.csv", folder, filename, index)
                ) {
                    Err(why) => panic!("couldn't create {}.csv: {}", filename, why),
                    Ok(file) => file,
                };
                Self {
                    csv_mode,
                    filename: filename.to_string(),
                    csv_writer: Some(Box::new(file)),
                    txt_writer: None
                }
            },
            false => {
                let pathname = format!("{}/{}-{}.txt", folder, filename, index);
                let path = Path::new(&pathname);
                let file = match File::create(&path) {
                    Err(why) => panic!("couldn't create {}: {}", path.display(), why),
                    Ok(file) => file,
                };
                return Self {
                    csv_mode,
                    filename: filename.to_string(),
                    csv_writer: None,
                    txt_writer: Some(Box::new(file))
                }
            }
        }
    }

    pub fn get_csv_ref(&mut self) -> Reporter {
        match &mut self.csv_writer {
            Some(w) => CSV(&mut **w),
            None => {
                match &mut self.txt_writer {
                    Some(w) => TXT(&mut **w),
                    _ => unreachable!("Can't be here, one of the writer must exists.")
                }
            }
        }
    }

    pub fn report_init(&mut self) -> () {
        let writer = self.get_csv_ref();
        match writer {
            Reporter::CSV(csv) => csv.write_record(
                        &["interface", "src_addr", "dest_addr",
                            "res_name", "src_port", "dest_port", "transport", "application",
                            "tot_bytes", "start_time", "stop_time"]
                    ).unwrap(),
            Reporter::TXT(file) => {
                writeln!(file, "| Interface\t| Source IP address\t| Source Port\t| Dest IP address \t| Dest Port\t| Tot Bytes\t| Transport \t| Application \t| First Timestamp \t| Last Timestamp \n").unwrap();
            }
        }
    }

    pub fn write(&mut self, report: Report) -> () {
        let writer = self.get_csv_ref();
        match writer {
            Reporter::CSV(csv) => csv.serialize(report).unwrap(),
            Reporter::TXT(file) => {
                writeln!(file, "{}", report).unwrap();
            }
        }
    }

    pub fn close(&mut self) -> () {
        let writer = self.get_csv_ref();
        match writer {
            Reporter::CSV(csv) => csv.flush().unwrap(),
            _ => ()
        }
    }
}

pub fn setup_directory(filename: &str) -> String {
    let mut folder = format!(
        "{}_{}",
        filename,
        chrono::offset::Local::now().naive_local()
    );
    folder = folder[..folder.len()-10].to_string();
    folder = folder.replace(" ", "_").replace("-", "").replace(":", "_");

    // Create the directory for the current sniffing session
    match create_dir(&folder) {
        Ok(()) => (),
        Err(why) => panic!("{}", why)
    }

    match set_permissions(&folder, PermissionsExt::from_mode(0o777)) {
        Err(why) => panic!("{}", why),
        Ok(_) => {},
    }

    folder
}

pub fn produce_hashmap(buffer: Vec<Packet>) -> HashMap<ReportHeader, Report> {
    let mut report = HashMap::new();

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

    report
}