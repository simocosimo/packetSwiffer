# Args
Represents the informations used for generating a Report

```rust
pub struct Args {
    pub timeout: i64,
    pub filename: String,
    pub interface: String,
    pub promisc: bool,
    pub list: bool,
    pub csv: bool
}
```