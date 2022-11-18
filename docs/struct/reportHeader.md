# ReportHeader
Represents the informations used for grouping in the Report

```rust
pub struct ReportHeader {
    src_addr: IpAddr,
    dest_addr: IpAddr,
    src_port: Option<u16>,
    dest_port: Option<u16>
}
```