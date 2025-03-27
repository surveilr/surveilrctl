use std::error::Error;
use std::fmt::{self, Display};

#[derive(Debug, PartialEq)]
pub enum SurveilrCtlError {
    InvalidCommand(String),
}

impl Error for SurveilrCtlError {}

impl Display for SurveilrCtlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SurveilrCtlError::*;
        match self {
            InvalidCommand(v) => write!(
                f,
                "The command '{}' is invalid. Please run help to see a list of available commands",
                v
            ),
        }
    }
}
