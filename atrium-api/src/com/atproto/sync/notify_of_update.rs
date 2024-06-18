// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.sync.notifyOfUpdate` namespace.
pub const NSID: &str = "com.atproto.sync.notifyOfUpdate";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    ///Hostname of the current service (usually a PDS) that is notifying of update.
    pub hostname: String,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "error", content = "message")]
pub enum Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
        Ok(())
    }
}
