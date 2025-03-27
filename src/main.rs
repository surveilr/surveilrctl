use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{self, Command};

use clap::{command, Parser, Subcommand};
use upgrade::upgrade;
use upt::{detect_os, detect_vendor, init_vendor, UptError, Vendor};

mod error;
mod upgrade;

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
    },

    Upgrade {
        /// The version to update to. If not present, it defaults to the latest.
        #[arg(short, long)]
        version: Option<String>,
        /// Skip confirmation
        #[arg(short, long, default_value = "false")]
        yes: bool,
        /// An optional Github autehntication token to authenticate requests or to prevent rate limiting
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
        } => {
            println!("Installing osquery...");
            let install_result = install_osquery()?;
            if install_result != 0 {
                return Err("Failed to install osquery".into());
            }
            println!("osquery installed successfully.");

            setup_osquery_connection(uri, cert_path, secret_path)
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

fn create_cmd(vendor: &Vendor, args: &[String], os: &str) -> Result<Vec<String>, UptError> {
    let tool = detect_vendor(os)?;
    let task = vendor.parse(args, tool.name())?;
    let cmd = tool.eval(&task)?;
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

fn setup_osquery_connection(
    uri: String,
    cert_path: Option<String>,
    secret_path: Option<String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let default_paths = get_default_paths()?;
    let cert_path =
        cert_path.unwrap_or_else(|| default_paths.cert_path.to_string_lossy().to_string());
    let secret_path =
        secret_path.unwrap_or_else(|| default_paths.secret_path.to_string_lossy().to_string());

    println!("Downloading certificate...");
    match download_file(&format!("{}/asset/enroll/cert-prime.pem", uri), &cert_path) {
        Ok(_) => println!("Certificate saved to: {}", cert_path),
        Err(e) => {
            return Err(format!("Failed to download or save certificate: {}\nTry running the command with sudo if the destination requires elevated privileges.", e).into());
        }
    }

    println!("Downloading enrollment secret...");
    match download_file(&format!("{}/asset/enroll/secret.txt", uri), &secret_path) {
        Ok(_) => println!("Enrollment secret saved to: {}", secret_path),
        Err(e) => {
            return Err(format!("Failed to download or save enrollment secret: {}\nTry running the command with sudo if the destination requires elevated privileges.", e).into());
        }
    }

    println!("Starting osquery daemon...");
    match start_osquery_daemon(&uri, &cert_path, &secret_path) {
        Ok(_) => {
            println!("osquery daemon started successfully.");
            Ok(0)
        },
        Err(e) => {
            Err(format!("Failed to start osquery daemon: {}\nIf this is a permission issue, try running the entire command with sudo.", e).into())
        }
    }
}

struct DefaultPaths {
    cert_path: PathBuf,
    secret_path: PathBuf,
}

fn get_default_paths() -> Result<DefaultPaths, Box<dyn std::error::Error>> {
    let home_dir = match env::var("HOME").or_else(|_| env::var("USERPROFILE")) {
        Ok(path) => PathBuf::from(path),
        Err(_) => return Err("Could not determine user home directory".into()),
    };

    let base_dir = home_dir.join(".surveilrctl").join("certs");

    Ok(DefaultPaths {
        cert_path: base_dir.join("cert-prime.pem"),
        secret_path: base_dir.join("enroll-secret.txt"),
    })
}

fn download_file(url: &str, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(file_path);

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let bytes = download_content(url)?;
    fs::write(&path, &bytes)?;

    Ok(())
}

fn download_content(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // TODO: Replace with reqwest or ureq
    let output = if cfg!(windows) {
        Command::new("powershell")
            .arg("-Command")
            .arg(format!(
                "(New-Object System.Net.WebClient).DownloadString('{}')",
                url
            ))
            .output()?
    } else {
        Command::new("curl").arg("-s").arg(url).output()?
    };

    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to download from {}: {}", url, error_msg).into());
    }

    Ok(output.stdout)
}

fn start_osquery_daemon(
    uri: &str,
    cert_path: &str,
    secret_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let domain = uri.replace("https://", "").replace("http://", "");
    let tls_hostname = format!("--tls_hostname={}", domain);
    let tls_server_cert = format!("--tls_server_certs={}", cert_path);
    let enroll_secret = format!("--enroll_secret_path={}", secret_path);

    let osquery_args = vec![
        "--verbose",
        "--ephemeral",
        "--disable_database",
        &tls_hostname,
        &tls_server_cert,
        "--config_plugin=tls",
        "--config_tls_endpoint=/config",
        "--config_refresh=60",
        "--logger_tls_endpoint=/logger",
        "--logger_plugin=tls",
        "--enroll_tls_endpoint=/enroll",
        &enroll_secret,
    ];

    let osquery_exe = if cfg!(windows) {
        "osqueryd.exe"
    } else {
        "osqueryd"
    };

    let status = Command::new(osquery_exe).args(&osquery_args).status()?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("osqueryd exited with status code: {:?}", status.code()).into())
    }
}
