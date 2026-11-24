mod admin;
mod keys;

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((mode, rest)) if mode == "keys" => {
            let Some(command) = keys::Command::parse(rest) else {
                eprintln!("{}", keys::USAGE);
                return ExitCode::from(2);
            };
            match keys::run(command) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("bunzzle keys: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some((mode, rest)) if mode == "admin" => {
            let Some((config, request)) = admin::parse(rest) else {
                eprintln!("{}", admin::USAGE);
                return ExitCode::from(2);
            };
            match admin::run(Path::new(config), &request) {
                Ok(reply) => {
                    if reply.code == ::admin::Code::Ok {
                        print!("{}", reply.text);
                    } else {
                        eprintln!("bunzzle admin: {}", reply.text);
                    }
                    admin::exit(&reply)
                }
                Err(error) => {
                    eprintln!("bunzzle admin: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some((mode, [path])) if mode == "check" => match node::check(Path::new(path)) {
            Ok(_) => {
                println!("{path}: ok");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("bunzzle check: {error}");
                ExitCode::FAILURE
            }
        },
        Some((mode, [path])) if mode == "serve" => match node::deliver(Path::new(path)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("bunzzle serve: {error}");
                ExitCode::FAILURE
            }
        },
        Some((mode, _)) if mode == "serve" => {
            eprintln!("usage: bunzzle serve <config>");
            ExitCode::from(2)
        }
        Some((mode, _)) if mode == "check" => {
            eprintln!("usage: bunzzle check <config>");
            ExitCode::from(2)
        }
        _ => {
            println!("bunzzle {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}
