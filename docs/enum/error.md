# Error
Represents the possible errors while parsing a packet

```rust
pub enum Error {
    ParsingError,
    UnknownPacket,
    ARPParsingError,
    IPv6ParsingError,
    IPv4ParsingError,
    ICMPParsingError,
    TCPParsingError,
    UDPParsingError,
    EthernetParsingError
}
```