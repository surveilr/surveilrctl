use std::process;

use clap::{command, Parser, Subcommand};
use upgrade::upgrade;

mod error;
mod setup;
mod upgrade;

use setup::Setup;

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

        /// Certificate file path
        #[arg(short, long)]
        cert_path: Option<String>,

        /// Enrollment secret file path
        #[arg(short, long)]
        secret_path: Option<String>,

        /// Username for basic authentication
        #[arg(short, long)]
        username: Option<String>,

        /// Password for basic authentication
        #[arg(short, long)]
        password: Option<String>,
    },

    Upgrade {
        /// The version to update to. If not present, it defaults to the latest.
        #[arg(short, long)]
        version: Option<String>,
        /// Skip confirmation
        #[arg(short, long, default_value = "false")]
        yes: bool,
        /// An optional Github authentication token to authenticate requests or to prevent rate limiting
        #[arg(short, long, env = "GITHUB_TOKEN")]
        token: Option<String>,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {}", err);
        process::exit(1);
    }
    process::exit(0);
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let args = Cli::parse();
    match args.command {
        SubCmd::Setup {
            uri,
            cert_path,
            secret_path,
            username,
            password,
        } => {
            let setup = Setup::new(uri, cert_path, secret_path, username, password);
            setup.run()
        }
        SubCmd::Upgrade {
            version,
            yes,
            token,
        } => {
            if let Err(err) = upgrade(version, token, yes) {
                Err(err)
            } else {
                Ok(0)
            }
        }
    }
}
