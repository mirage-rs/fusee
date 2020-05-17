mod app;
mod error;
mod operations;
mod status;

use app::*;
use error::FuseeError;
use operations::*;
use structopt::StructOpt;

fn main() {
    match try_main() {
        Ok(_) => {}
        Err(err) => error!("Failed", "{}", err),
    }
}

fn try_main() -> Result<(), FuseeError> {
    let app = App::from_args();

    match app.op {
        Operation::Inject(options) => inject::do_inject(options),
    }
}
