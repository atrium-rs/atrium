// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.server.createInviteCodes` namespace.
pub const NSID: &str = "com.atproto.server.createInviteCodes";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    pub code_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub for_accounts: Option<Vec<crate::types::string::Did>>,
    pub use_count: i64,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub codes: Vec<AccountCodes>,
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
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountCodes {
    pub account: String,
    pub codes: Vec<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
