# Reporter
Store the information whether we're writing a csv or a txt report file
```
pub enum Reporter <'a> {
    CSV(&'a mut Writer<File>),
    TXT(&'a mut File)
}
```
