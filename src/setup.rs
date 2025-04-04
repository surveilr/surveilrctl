use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use reqwest::blocking::Client;
use upt::{detect_os, detect_vendor, init_vendor, UptError, Vendor};

pub struct Setup {
    uri: String,
    cert_path: Option<String>,
    secret_path: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

pub struct DefaultPaths {
    pub cert_path: PathBuf,
    pub secret_path: PathBuf,
}

impl Setup {
    pub fn new(
        uri: String,
        cert_path: Option<String>,
        secret_path: Option<String>,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            uri,
            cert_path,
            secret_path,
            username,
            password,
        }
    }

    pub fn run(&self) -> Result<i32, Box<dyn std::error::Error>> {
        println!("Installing osquery...");
        let install_result = self.install_osquery()?;
        if install_result != 0 {
            return Err("Failed to install osquery".into());
        }
        println!("osquery installed successfully.");

        self.setup_osquery_connection()
    }

    fn install_osquery(&self) -> Result<i32, Box<dyn std::error::Error>> {
        let bin = String::from("upt");
        let vendor = init_vendor(&bin)?;
        let args = vec![bin, "install".to_string(), "osquery".to_string()];
        let os = detect_os().unwrap_or_default();

        let cmd_args = match self.create_cmd(&vendor, &args, &os) {
            Ok(v) => v,
            Err(e) => return Err(e.into()),
        };

        let cmd = &cmd_args[0];
        let status = Command::new(cmd).args(&cmd_args[1..]).status()?;

        Ok(status.code().unwrap_or_default())
    }

    fn create_cmd(
        &self,
        vendor: &Vendor,
        args: &[String],
        os: &str,
    ) -> Result<Vec<String>, UptError> {
        let tool = detect_vendor(os)?;
        let task = vendor.parse(args, tool.name())?;
        let cmd = tool.eval(&task)?;
        Ok(cmd)
    }

    fn setup_osquery_connection(&self) -> Result<i32, Box<dyn std::error::Error>> {
        let default_paths = Self::get_default_paths()?;
        let cert_path = self
            .cert_path
            .clone()
            .unwrap_or_else(|| default_paths.cert_path.to_string_lossy().to_string());
        let secret_path = self
            .secret_path
            .clone()
            .unwrap_or_else(|| default_paths.secret_path.to_string_lossy().to_string());

        println!("Downloading certificate...");
        match self.download_file(
            &format!("{}/asset/enroll/cert-prime.pem", self.uri),
            &cert_path,
        ) {
            Ok(_) => println!("Certificate saved to: {}", cert_path),
            Err(e) => {
                return Err(format!("Failed to download or save certificate: {}\nTry running the command with sudo if the destination requires elevated privileges.", e).into());
            }
        }

        println!("Downloading enrollment secret...");
        match self.download_file(
            &format!("{}/asset/enroll/secret-prime", self.uri),
            &secret_path,
        ) {
            Ok(_) => println!("Enrollment secret saved to: {}", secret_path),
            Err(e) => {
                return Err(format!("Failed to download or save enrollment secret: {}\nTry running the command with sudo if the destination requires elevated privileges.", e).into());
            }
        }

        println!("Starting osquery daemon...");
        match self.start_osquery_daemon(&cert_path, &secret_path) {
            Ok(_) => {
                println!("osquery daemon started successfully.");
                Ok(0)
            },
            Err(e) => {
                Err(format!("Failed to start osquery daemon: {}\nIf this is a permission issue, try running the entire command with sudo.", e).into())
            }
        }
    }

    pub fn get_default_paths() -> Result<DefaultPaths, Box<dyn std::error::Error>> {
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

    fn download_file(&self, url: &str, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from(file_path);

        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let bytes = self.download_content(url)?;
        fs::write(&path, &bytes)?;

        Ok(())
    }

    fn download_content(&self, url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let client = Client::new();
        let mut request_builder = client.get(url);
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            request_builder = request_builder.basic_auth(username, Some(password));
        }
        let response = request_builder.send()?;
        if !response.status().is_success() {
            return Err(format!(
                "Failed to download from {}: HTTP status {}",
                url,
                response.status()
            )
            .into());
        }
        let bytes = response.bytes()?.to_vec();

        Ok(bytes)
    }

    fn start_osquery_daemon(
        &self,
        cert_path: &str,
        secret_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let domain = self.uri.replace("https://", "").replace("http://", "");
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
}

#[cfg(test)]
mod tests {
    use crate::setup::Setup;
    use mockito;
    use std::fs;

    #[test]
    fn test_setup_constructor() {
        let uri = "https://test.com".to_string();
        let cert_path = Some("/path/to/cert.pem".to_string());
        let secret_path = Some("/path/to/secret.txt".to_string());
        let username = Some("testuser".to_string());
        let password = Some("testpass".to_string());

        let setup = Setup::new(
            uri.clone(),
            cert_path.clone(),
            secret_path.clone(),
            username.clone(),
            password.clone(),
        );

        assert_eq!(setup.uri, uri);
        assert_eq!(setup.cert_path, cert_path);
        assert_eq!(setup.secret_path, secret_path);
        assert_eq!(setup.username, username);
        assert_eq!(setup.password, password);
    }

    #[test]
    fn test_default_paths() {
        let paths = Setup::get_default_paths().unwrap();

        assert!(paths.cert_path.to_string_lossy().contains("cert-prime.pem"));
        assert!(paths
            .secret_path
            .to_string_lossy()
            .contains("enroll-secret.txt"));
    }

    #[test]
    fn test_download_content_without_auth() {
        let mut server = mockito::Server::new();
        let uri = server.url();

        let m = server
            .mock("GET", "/test.txt")
            .with_status(200)
            .with_header("content-type", "text/plain")
            .with_body("test content")
            .create();

        let setup = Setup::new(uri.clone(), None, None, None, None);

        let result = setup.download_content(&format!("{}/test.txt", uri));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test content");

        m.assert();
    }

    #[test]
    fn test_download_content_with_auth() {
        let mut server = mockito::Server::new();
        let uri = server.url();

        let m = server
            .mock("GET", "/test.txt")
            .match_header("Authorization", "Basic dGVzdHVzZXI6dGVzdHBhc3M=") // base64 of testuser:testpass
            .with_status(200)
            .with_header("content-type", "text/plain")
            .with_body("authenticated content")
            .create();

        let setup = Setup::new(
            uri.clone(),
            None,
            None,
            Some("testuser".to_string()),
            Some("testpass".to_string()),
        );

        let result = setup.download_content(&format!("{}/test.txt", uri));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"authenticated content");

        m.assert();
    }

    #[test]
    fn test_download_content_auth_failure() {
        let mut server = mockito::Server::new();
        let uri = server.url();

        let m = server
            .mock("GET", "/test.txt")
            .with_status(401)
            .with_header("content-type", "text/plain")
            .with_body("Unauthorized")
            .create();

        let setup = Setup::new(
            uri.clone(),
            None,
            None,
            Some("wronguser".to_string()),
            Some("wrongpass".to_string()),
        );

        let result = setup.download_content(&format!("{}/test.txt", uri));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTP status 401"));

        m.assert();
    }

    #[test]
    fn test_download_file() {
        let mut server = mockito::Server::new();
        let uri = server.url();

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let file_path_str = file_path.to_string_lossy().to_string();

        let m = server
            .mock("GET", "/test.txt")
            .with_status(200)
            .with_header("content-type", "text/plain")
            .with_body("file content")
            .create();

        let setup = Setup::new(uri.clone(), None, None, None, None);

        let result = setup.download_file(&format!("{}/test.txt", uri), &file_path_str);
        assert!(result.is_ok());

        let content = fs::read_to_string(file_path).unwrap();
        assert_eq!(content, "file content");

        m.assert();
    }

    #[test]
    fn test_download_certificate() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir
            .path()
            .join("cert.pem")
            .to_string_lossy()
            .to_string();
        let secret_path = temp_dir
            .path()
            .join("secret.txt")
            .to_string_lossy()
            .to_string();

        let mut server = mockito::Server::new();
        let uri = server.url();

        let cert_mock = server.mock("GET", "/asset/enroll/cert-prime.pem")
            .with_status(200)
            .with_header("content-type", "application/x-pem-file")
            .with_body("-----BEGIN CERTIFICATE-----\nMIIDTTCCAjWgAwIBAgIJAJeg\n-----END CERTIFICATE-----\n")
            .create();

        let secret_mock = server
            .mock("GET", "/asset/enroll/secret.txt")
            .with_status(200)
            .with_header("content-type", "text/plain")
            .with_body("test-enrollment-secret")
            .create();

        let setup = Setup::new(
            uri,
            Some(cert_path.clone()),
            Some(secret_path.clone()),
            None,
            None,
        );

        let uri = server.url();

        let cert_url = format!("{}/asset/enroll/cert-prime.pem", uri);
        let result = setup.download_file(&cert_url, &cert_path);
        assert!(result.is_ok());

        let cert_content = fs::read_to_string(&cert_path).unwrap();
        assert!(cert_content.contains("BEGIN CERTIFICATE"));

        let secret_url = format!("{}/asset/enroll/secret.txt", uri);
        let result = setup.download_file(&secret_url, &secret_path);
        assert!(result.is_ok());

        let secret_content = fs::read_to_string(&secret_path).unwrap();
        assert_eq!(secret_content, "test-enrollment-secret");

        cert_mock.assert();
        secret_mock.assert();
    }
}
