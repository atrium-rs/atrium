// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.sync.getHead` namespace.
pub const NSID: &str = "com.atproto.sync.getHead";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    ///The DID of the repo.
    pub did: crate::types::string::Did,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub root: crate::types::string::Cid,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "error", content = "message")]
pub enum Error {
    HeadNotFound(Option<String>),
}
impl std::fmt::Display for Error {
    fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::HeadNotFound(msg) => {
                write!(_f, "HeadNotFound")?;
                if let Some(msg) = msg {
                    write!(_f, ": {msg}")?;
                }
            }
        }
        Ok(())
    }
}
