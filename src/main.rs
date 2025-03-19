use std::process::{self, Command};

use clap::{command, Parser, Subcommand};
use upt::{detect_os, detect_vendor, init_vendor, UptError, Vendor};
mod error;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: SubCmd,
}

#[derive(Debug, Subcommand)]
enum SubCmd {
    Setup {
        /// The osquery-ms server URL
        #[arg(short, long)]
        uri: String,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("An error occured: {err}");
        process::exit(1);
    }
    process::exit(0);
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let args = Cli::parse();
    match args.command {
        SubCmd::Setup { .. } => install_osquery(),
    }
}

fn create_cmd(vendor: &Vendor, args: &[String], os: &str) -> Result<Vec<String>, UptError> {
    let tool = detect_vendor(os)?;
    let task = vendor.parse(args, tool.name())?;
    println!("{task:#?}");
    let cmd = tool.eval(&task)?;
    println!("{cmd:#?}");
    Ok(cmd)
}

fn install_osquery() -> Result<i32, Box<dyn std::error::Error>> {
    let bin = String::from("upt");
    let vendor = init_vendor(&bin)?;
    let args = vec![bin, "install".to_string(), "osquery".to_string()];
    let os = detect_os().unwrap_or_default();

    let cmd_args = match create_cmd(&vendor, &args, &os) {
        Ok(v) => v,
        Err(e) => return Err(e.into()),
    };

    let cmd = &cmd_args[0];
    let status = Command::new(cmd).args(&cmd_args[1..]).status()?;

    Ok(status.code().unwrap_or_default())
}
