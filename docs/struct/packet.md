# Packet
Represents a packet returned from the parsing function

```rust
pub struct Packet {
    pub interface: String,
    pub src_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub res_name: String,
    pub src_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub length: u16,
    pub transport: String,
    pub application: String,
    pub timestamp: String
}
```

## Implementations 

```rust 
pub fn new(
        interface: String,
        src_addr: IpAddr,
        dest_addr: IpAddr,
        res_name: String,
        src_port: Option<u16>,
        dest_port: Option<u16>,
        length: u16,
        transport: String,
        application: String,
        timestamp: String
    ) -> Self
```
_Return a new `Packet` given a set of parameters_

## Trait Implementations

```rust
impl Display for Packet 
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result 
```
_Formats the value using the given formatter_