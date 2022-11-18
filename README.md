# packetSwiffer
## Introduction
**packetSwiffer** is a library that uses the rust `libpcap` library to capture packets on Windows, Linux and macOS.\
The library allows the user to capture packet on a user specified network adapter by setting it in promiscuous mode, and generates reports on the traffic observed after a specified time interval.\
The report is organized by source and destination port and address, and shows information about the number of bytes exchanged, the transport and application protocols (see caveats section for the application layer information limitations), and a time of first and last packet exchange.

## Dependencies
- [pcap](https://docs.rs/pcap/0.10.1/pcap/index.html)
- [timer](https://docs.rs/timer/0.2.0/timer/)
- [pktparse](https://docs.rs/pktparse/0.7.1/pktparse/)
- [dns_parser](https://docs.rs/dns-parser/0.8.0/dns_parser/)
- [chrono](https://docs.rs/chrono/0.4.23/chrono/)
- [clap](https://docs.rs/clap/4.0.15/clap/index.html)
- [serde](https://docs.rs/serde/1.0.147/serde/)
- [csv](https://docs.rs/csv/1.1.6/csv/)

## Structs

- ### [Packet](./docs/struct/packet.md)
- ### [ReportHeader](./docs/struct/reportHeader.md)
- ### [Report](./docs/struct/report.md)

## Enum

- ### [Error](./docs/enum/error.md)

## Errors
Most public functions return a `Result`, the possible errors are the following:

* `NoSuchDevice`: No such network interface
* `ARPParsingError`: Error while parsing ARP Packet
* `ParsingError`: Error while parsing
* `UnknownPacket`: Unknown Packet
* `IPv6ParsingError`: Error while parsing IPv6 Packet
* `IPv4ParsingError`: Error while parsing IPv4 Packet
* `ICMPParsingError`: Error while parsing ICMP Packet
* `TCPParsingError`: Error while parsing TCP Packet
* `UDPParsingError`: Error while parsing UDP Packet
* `EthernetParsingError`: Error while parsing Ethernet Packet

## Usage
NOTE: The application needs to be run with admin priviledges in order to correctly use the specified interface to sniff traffic.

The application can be run with the following arguments:
```
Usage: swiffer [OPTIONS] --interface <INTERFACE>
Options:                                                                                                                  
-t, --timeout <TIMEOUT>      Optional timeout for report generation (in seconds) [default: 10]                          
-f, --filename <FILENAME>    Optional filename for generated report (<filename>_<seq_num>.txt) [default: report]        
-i, --interface <INTERFACE>  Name of the interface to be used for the sniffing                                          
-p, --promisc                Set the interface in promiscuous mode                                                      
-l, --list                   Show the net interfaces present in the system without launching the sniffing               
-h, --help                   Print help information                                                                     
-V, --version                Print version information 
```
The only mandatory command line argument is the interface name. 
If you don't know the identifier of your network interface, you can run 
```
sudo ./swiffer -l
``` 
in order to see a list of them.

