# packetSwiffer
## Introduction
**packetSwiffer** is a library that uses the rust `libpcap` library to capture packets on Windows, Linux and macOS.\
The library allows the user to capture packet on a user specified network adapter by setting it in promiscuous mode, and generates reports on the traffic observed after a specified time interval.\
The report is organized by source and destination port and address, and shows information about the number of bytes exchanged, the transport and application protocols (see caveats section for the application layer information limitations), and a time of first and last packet exchange.

##Functions

##Errors

##How to use
