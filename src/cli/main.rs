use log::*;
use pretty_env_logger::formatted_builder;

fn main() {
    let mut logger = formatted_builder();
    logger.filter(None, LevelFilter::Debug);
    logger.init();

    info!("such information");
    warn!("o_O");
    error!("much error");
}
