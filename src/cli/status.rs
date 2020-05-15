use std::boxed::Box;
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

#[macro_export]
macro_rules! ok {
    ($title:expr, $msg:expr) => {
        status::print($title, $msg, Color::Green)
    };
}

#[macro_export]
macro_rules! info {
    ($title:expr, $msg:expr) => {
        status::print($title, $msg, Color::Cyan)
    };
}

#[macro_export]
macro_rules! error {
    ($title:expr, $msg:expr) => {
        status::print($title, $msg, Color::Red)
    };
}

pub(crate) fn print(
    title: &str,
    msg: &str,
    color: Color,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = StandardStream::stdout(ColorChoice::Always);
    let mut stdout = stdout.lock();

    stdout.set_color(ColorSpec::new().set_bold(true).set_fg(Some(color)))?;

    write!(stdout, "{:>12}", title)?;

    stdout.reset()?;
    // stdout.set_color(ColorSpec::new().set_bold(true));
    writeln!(stdout, " {}", msg)?;
    stdout.flush()?;

    Ok(())
}
