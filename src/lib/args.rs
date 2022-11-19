use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Optional timeout for report generation (in seconds)
    #[arg(short, long, default_value_t = 10)]
    pub timeout: i64,

    /// Optional filename for generated report (<filename>_<seq_num>.txt)
    #[arg(short, long, default_value = "report")]
    pub filename: String,

    /// Name of the interface to be used for the sniffing
    #[arg(short, long)]
    pub interface: String,

    /// Set the interface in promiscuous mode
    #[arg(short, long, action)]
    pub promisc: bool,

    /// Show the net interfaces present in the system without launching the sniffing
    #[arg(short, long, action)]
    pub list: bool,

    /// Set report file type to csv instead of default txt
    #[arg(long, action)]
    pub csv: bool
}
