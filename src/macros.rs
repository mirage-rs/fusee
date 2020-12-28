//! Macros for printing status messages to the console.
use owo_colors::{Color, OwoColorize};

#[macro_export]
macro_rules! ok {
    ($title:expr, $msg:expr) => {
        $crate::macros::print::<owo_colors::colors::Green>($title, $msg);
    };
    ($title:expr, $msg:expr, $($arg:tt)*) => {
        ok!($title, format!($msg, $($arg)*).as_str());
    };
}

#[macro_export]
macro_rules! info {
    ($title:expr, $msg:expr) => {
        $crate::macros::print::<owo_colors::colors::Cyan>($title, $msg);
    };
    ($title:expr, $msg:expr, $($arg:tt)*) => {
        ok!($title, format!($msg, $($arg)*).as_str());
    };
}

#[macro_export]
macro_rules! error {
    ($title:expr, $msg:expr) => {
        $crate::macros::print::<owo_colors::colors::Red>($title, $msg);
    };
    ($title:expr, $msg:expr, $($arg:tt)*) => {
        ok!($title, format!($msg, $($arg)*).as_str());
    };
}

pub(crate) fn print<C: Color>(title: &str, msg: &str) {
    print!("{:>12} {}\n", title.fg::<C>().bold(), msg);
}
