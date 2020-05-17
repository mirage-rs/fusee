use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(
    name = "fusee",
    about = "fusee-gelee exploit launcher for the Nintendo Switch."
)]
pub struct App {
    /// Print debug logs. Note: currently unused.
    #[structopt(short, long)]
    pub debug: bool,
    /// The operation to do.
    #[structopt(subcommand)]
    pub op: Operation,
}

#[derive(StructOpt)]
pub enum Operation {
    /// Sends a payload to the connected Switch.
    Inject(InjectOptions),
}

#[derive(StructOpt)]
pub struct InjectOptions {
    /// Search until a Switch in Rcm mode is available.
    #[structopt(short, long)]
    pub wait: bool,
    /// Path to the payload binary.
    #[structopt(parse(from_os_str))]
    pub payload: PathBuf,
}
