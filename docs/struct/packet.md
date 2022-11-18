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