# Filter
Represents the filter that can be setted in the menu.

```rust
pub struct Filter{
    pub ip_source: String,
    pub ip_dest: String,
    pub port_source: String,
    pub port_dest: String,
    pub transport_protocol: String,
}
```

## Implementations
```rust
pub fn new() -> Self {
        return Filter{ip_source: String::new(),
                      ip_dest: String::new(),
                      port_source: String::new(),
                      port_dest: String::new(),
                      transport_protocol: String::new()};
    }
```
_Return a new `Filter` from scratch_

```rust
pub fn with_args(ip_source: String, ip_dest: String, port_source: String, port_dest: String, transport_protocol: String) -> Self {
        return Filter {
            ip_source,
            ip_dest,
            port_source,
            port_dest,
            transport_protocol
        };
    }
```
_Return a new `Filter` given a set of parameters_ 

```rust
pub fn as_array(&self) -> [String; 5] {
        return [self.ip_source.clone(), self.ip_dest.clone(), self.port_source.clone(), self.port_dest.clone(), self.transport_protocol.clone()];
    }
```
_Convert the struct in a 5-element array_

