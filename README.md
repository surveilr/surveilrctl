# surveilrctl

A tool for setting up and managing osQuery connections to the osQuery management server started by [surveilr](www.surveilr.com).

## Overview

`surveilrctl` simplifies the process of installing osQuery and connecting nodes to the osQuery management server started by `surveilr osquery-ms`. It automates the installation, certificate retrieval, enrollment, and configuration of nodes.

## Installation

### Quick Installation

#### Linux & macOS

One-line installation with automatic setup:

```bash
SURVEILR_HOST=https://your-host curl -sL surveilr.com/surveilrctl.sh | bash
```

This will download, install, and set up surveilrctl with your specified host in one command.

#### Windows

One-line installation using PowerShell:

```powershell
irm https://surveilr.com/surveilrctl.ps1 | iex
```

With automatic setup:

```powershell
$env:SURVEILR_HOST="https://your-host"; irm https://surveilr.com/surveilrctl.ps1 | iex
```

Note: For Windows, you may need to run PowerShell as Administrator for this to work properly.

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
git clone https://github.com/surveilr/surveilrctl.git
cd surveilrctl

# Build the project
cargo build --release

# The binary will be available at target/release/surveilrctl
```

## Commands and Arguments

`surveilrctl` provides the following commands:

### 1. Setup Command

The `setup` command installs osQuery and configures it to connect to a management server.

```bash
surveilrctl setup --uri <SERVER_URL> [OPTIONS]
```

#### Required Arguments:

- `--uri, -u <SERVER_URL>`: The osQuery management server URL.
  - This is the URL of the server running the osQuery management service.
  - Example: `https://osquery-ms.example.com`

#### Optional Arguments:

- `--cert-path, -c <PATH>`: Custom path for storing the TLS certificate.
  - If not specified, the certificate will be stored in a default location based on your OS.
  - Default paths:
    - Linux: `~/.surveilrctl/certs/cert-prime.pem`
    - macOS: `~/.surveilrctl/certs/cert-prime.pem`
    - Windows: `%USERPROFILE%\.surveilrctl\certs\cert-prime.pem`

- `--secret-path, -s <PATH>`: Custom path for storing the enrollment secret.
  - If not specified, the secret will be stored in a default location based on your OS.
  - Default paths:
    - Linux: `~/.surveilrctl/certs/enroll-secret.txt`
    - macOS: `~/.surveilrctl/certs/enroll-secret.txt`
    - Windows: `%USERPROFILE%\.surveilrctl\certs\enroll-secret.txt`

- `--username, -u <USERNAME>`: Username for basic authentication.
  - Use this if your osQuery management server requires basic authentication.
  - Must be used together with `--password`.

- `--password, -p <PASSWORD>`: Password for basic authentication.
  - Use this if your osQuery management server requires basic authentication.
  - Must be used together with `--username`.

#### Setup Process:

When you run the `setup` command, surveilrctl will:

1. Install osQuery if it's not already installed.
2. Download the TLS certificate from the server and validate it.
3. Download the enrollment secret from the server and verify it's not empty.
4. Start the osQuery daemon with the appropriate configuration to connect to the server.

### 2. Upgrade Command

The `upgrade` command updates surveilrctl to a newer version.

```bash
surveilrctl upgrade [OPTIONS]
```

#### Optional Arguments:

- `--version, -v <VERSION>`: Specific version to upgrade to.
  - If not specified, upgrades to the latest available version.
  - Example: `--version 1.2.0`

- `--yes, -y`: Skip confirmation prompts.
  - Automatically answer "yes" to any confirmation prompts during the upgrade.
  - Useful for scripted/automated upgrades.

- `--token, -t <TOKEN>`: GitHub authentication token.
  - Used to authenticate with GitHub when downloading the release.
  - Helps avoid rate limiting for frequent upgrades.
  - Can also be set via the `GITHUB_TOKEN` environment variable.

#### Upgrade Process:

When you run the `upgrade` command, surveilrctl will:

1. Check the currently installed version.
2. Determine the latest available version (or use the specified version).
3. Download the new version.
4. Replace the current executable with the new version.

## Examples

### Basic Setup

Connect a node to an osQuery management server:

```bash
surveilrctl setup --uri https://osquery-ms.example.com
```

### Setup with Basic Authentication

Connect to a server that requires authentication:

```bash
surveilrctl setup --uri https://osquery-ms.example.com --username admin --password securepass
```

### Setup with Custom File Paths

Specify custom paths for the certificate and secret:

```bash
surveilrctl setup --uri https://osquery-ms.example.com \
  --cert-path /path/to/cert.pem \
  --secret-path /path/to/secret.txt
```

### Upgrade to Latest Version

Update surveilrctl to the latest version:

```bash
surveilrctl upgrade
```

### Upgrade to Specific Version

Update surveilrctl to a specific version:

```bash
surveilrctl upgrade --version 1.2.0
```

### Non-Interactive Upgrade

Upgrade without confirmation prompts:

```bash
surveilrctl upgrade --yes
```

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
