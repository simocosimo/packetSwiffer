use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Optional timeout for report generation (in seconds)
    #[clap(short, long, default_value_t = 10)]
    pub timeout: i64,

    /// Optional filename for generated report (<filename>_<seq_num>.txt)
    #[clap(short, long, default_value = "report")]
    pub filename: String,

    /// Name of the interface to be used for the sniffing
    #[clap(short, long)]
    pub interface: String,

    /// Set the interface in promiscuous mode
    #[clap(short, long, action)]
    pub promisc: bool
}
