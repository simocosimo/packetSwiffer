# Settings
Represents the settings done in the menu.

```rust
pub struct Settings {
    pub filters: String,
    pub csv: Option<bool>,
    pub timeout: Option<i64>,
    pub filename: Option<String>,
}
```

## Implementations
```rust
pub fn new() -> Self {
        return Settings {
            filters: String::new(),
            csv: None,
            timeout: None,
            filename: None,
        }
    }
```
_Return a new `Settings` from scratch_