# packetSwiffer
## Introduction
**packetSwiffer** is a library that uses the rust `libpcap` library to capture packets on Windows, Linux and macOS.\
The library allows the user to capture packet on a user specified network adapter by setting it in promiscuous mode, and generates reports on the traffic observed after a specified time interval.\
The report is organized by source and destination port and address, and shows information about the number of bytes exchanged, the transport and application protocols (see caveats section for the application layer information limitations), and a time of first and last packet exchange.

## Dependencies
The information for installing 'pcap' is available on the rust libpcap github (https://github.com/rust-pcap/pcap). For Windows the library suggested is no longer maintained, so you should install Npcap instead, together with the Npcap SDK, and add the sdk to your environment variables

## Structs

- ### [Packet](./docs/struct/)
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

## How to use
