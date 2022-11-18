# Report
Represents the informations used to produce the Report

```rust
pub struct Report {
    packet: Packet,
    total_bytes: u64,
    start_time: String,
    stop_time: String
}
```

## Trait Implementations

```rust
impl Display for Report 
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result 
```