# surveilrctl

A tool for setting up and managing osQuery connections to the osQuery management server started by [surveilr](www.surveilr.com).

## Overview

`surveilrctl` simplifies the process of installing osQuery and connecting nodes to the osQuery management server started by `surveilr osquery-ms`. It automates the installation, certificate retrieval, enrollment, and configuration of nodes.

## Installation

### Using Prebuilt Binaries

Download the appropriate binary for your platform from the [Releases](https://github.com/surveilr/surveilrctl/releases) page:

- **Linux**: `surveilrctl_[version]_x86_64-unknown-linux-gnu.tar.gz`
- **macOS**: `surveilrctl_[version]_x86_64-apple-darwin.zip`
- **Windows**: `surveilrctl_[version]_x86_64-pc-windows-msvc.zip`

Extract the archive and place the binary in a location included in your PATH.

#### Linux & macOS
```bash
# Extract the archive
tar -xzf surveilrctl_[version]_x86_64-unknown-linux-gnu.tar.gz  # Linux
unzip surveilrctl_[version]_x86_64-apple-darwin.zip  # macOS

# Move to a directory in your PATH
sudo mv surveilrctl /usr/local/bin/
```

#### Windows
Extract the ZIP file and add the directory to your PATH or move the executable to a directory that's already in your PATH.

### Building from Source

If you have Rust installed, you can build the tool from source:

```bash
# Clone the repository
git clone https://github.com/yourusername/surveilrctl.git
cd surveilrctl

# Build the project
cargo build --release

# The binary will be available at target/release/surveilrctl
```

## Usage

### Basic Setup

The most common use case is to set up a node to connect to an osQuery management server:

```bash
# On Linux/macOS - may require sudo for system directories
sudo surveilrctl setup --uri https://osquery-ms.example.com

# On Windows (in an Administrator Command Prompt)
surveilrctl setup --uri https://osquery-ms.example.com
```

This command performs the following actions:
1. Installs osQuery if not already present
2. Downloads the TLS certificate from the server
3. Retrieves the enrollment secret
4. Starts the osQuery daemon with the appropriate configuration

### Custom File Paths

You can specify custom paths for the certificate and enrollment secret:

```bash
surveilrctl setup --uri https://osquery-ms.example.com \
  --cert-path /path/to/cert.pem \
  --secret-path /path/to/secret.txt
```

By default, files are stored in:
- Linux: `~/.surveilrctl/certs/`
- macOS: `~/.surveilrctl/certs/`
- Windows: `%USERPROFILE%\.surveilrctl\certs\`

## Permissions

### Linux & macOS

Some operations may require elevated privileges, especially when:
- Installing osQuery system-wide
- Writing to system directories
- Starting the osQuery daemon as a service

In these cases, run the command with `sudo`:

```bash
sudo surveilrctl setup --uri https://osquery-ms.example.com
```

### Windows

On Windows, you may need to run Command Prompt or PowerShell as Administrator for operations that require elevated privileges.

## Advanced Usage

### Manual Start

If you want to set up the files but start `osqueryd` manually, you can note the paths from the output messages and then run `osqueryd` with those parameters:

```bash
osqueryd --verbose --ephemeral --disable_database \
  --tls_hostname=osquery-ms.example.com \
  --tls_server_certs=/path/to/cert.pem \
  --config_plugin=tls \
  --config_tls_endpoint=/config \
  --logger_tls_endpoint=/logger \
  --logger_plugin=tls \
  --enroll_tls_endpoint=/enroll \
  --enroll_secret_path=/path/to/secret.txt
```