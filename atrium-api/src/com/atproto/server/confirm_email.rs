// @generated - This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.server.confirmEmail` namespace.
pub const NSID: &str = "com.atproto.server.confirmEmail";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InputData {
    pub email: String,
    pub token: String,
}
pub type Input = crate::types::Object<InputData>;
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "error", content = "message")]
pub enum Error {
    AccountNotFound(Option<String>),
    ExpiredToken(Option<String>),
    InvalidToken(Option<String>),
    InvalidEmail(Option<String>),
}
impl std::fmt::Display for Error {
    fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::AccountNotFound(msg) => {
                write!(_f, "AccountNotFound")?;
                if let Some(msg) = msg {
                    write!(_f, ": {msg}")?;
                }
            }
            Error::ExpiredToken(msg) => {
                write!(_f, "ExpiredToken")?;
                if let Some(msg) = msg {
                    write!(_f, ": {msg}")?;
                }
            }
            Error::InvalidToken(msg) => {
                write!(_f, "InvalidToken")?;
                if let Some(msg) = msg {
                    write!(_f, ": {msg}")?;
                }
            }
            Error::InvalidEmail(msg) => {
                write!(_f, "InvalidEmail")?;
                if let Some(msg) = msg {
                    write!(_f, ": {msg}")?;
                }
            }
        }
        Ok(())
    }
}
