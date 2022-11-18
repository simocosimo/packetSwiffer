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

## Trait Implementations

```rust
impl Display for Error 
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result 
```

```rust
impl std::error::Error for Error {}
```