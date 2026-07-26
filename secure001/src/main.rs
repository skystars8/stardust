use std::env;
use std::process;

mod key_maker;
mod otp_processor;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <mode> [options]", args[0]);
        process::exit(1);
    }

    let mode = &args[1];

    let result = match mode.as_str() {
        "keygen" => key_maker::run_key_maker(&args[2..]),
        "process" => otp_processor::run_otp_processor(&args[2..]),
        _ => {
            eprintln!("Invalid mode: {}. Use 'keygen' or 'process'.", mode);
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
