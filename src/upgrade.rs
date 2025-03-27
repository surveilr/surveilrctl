use std::{env, error};

use self_update::cargo_crate_version;

use crate::error::SurveilrCtlError;

pub fn upgrade(
    version: Option<String>,
    token: Option<String>,
    no_confirm: bool,
) -> Result<(), Box<dyn error::Error>> {
    let target = match env::consts::OS {
        "linux" => "x86_64-unknown-linux-musl",
        "windows" => "x86_64-unknown-windows-gnu",
        "macos" => "x86_64-apple-darwin",
        other => {
            return Err(SurveilrCtlError::InvalidCommand(format!("Unsopported OS: {other}")).into())
        }
    };

    let mut update = self_update::backends::github::Update::configure();
    update
        .repo_owner("surveilr")
        .repo_name("surveilrctl")
        .bin_name("surveilrctl")
        .current_version(cargo_crate_version!())
        .target(target)
        .no_confirm(no_confirm)
        .show_download_progress(true);

    if let Some(ref ver) = version {
        update.target_version_tag(ver);
    }

    if let Some(ref auth_token) = token {
        update.auth_token(auth_token);
    }

    let status = update.build()?.update();

    match status {
        Ok(status) => {
            println!("Update status: `{}`!", status.version());
            Ok(())
        }
        Err(e) => {
            if let Some(version) = version {
                if e.to_string().contains("NotFound") {
                    Err(
                        SurveilrCtlError::InvalidCommand(format!("Version {} not found.", version))
                            .into(),
                    )
                } else {
                    Err(e.into())
                }
            } else {
                Err(e.into())
            }
        }
    }
}
