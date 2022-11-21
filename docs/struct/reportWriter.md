# ReportWriter
Abstraction for the report handler
```
pub struct ReportWriter {
    pub csv_mode: bool,
    pub filename: String,
    csv_writer: Option<Box<Writer<File>>>,
    txt_writer: Option<Box<File>>
}
```

## Implementation
```
pub fn new(csv_mode: bool, folder: &str, filename: &str, index: i32) -> Self
```
Return a new `reportWriter` instance based on the passed parameters


```
pub fn get_csv_ref(&mut self) -> Reporter 
```
Return an instance of a `Reporter` enum, that contains the active report handler (csv or txt)

```
pub fn report_init(&mut self) -> ()
```
Initialize the report document with correct heading

```
pub fn write(&mut self, report: Report) -> ()
```
Write the passed `Report` structure as a line in the report document

```
pub fn close(&mut self) -> ()
```
If csv mode is active, correctly close the report file

