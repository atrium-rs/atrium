// @generated - This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.server.createInviteCodes` namespace.
pub const NSID: &str = "com.atproto.server.createInviteCodes";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InputData {
    pub code_count: i64,
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub for_accounts: core::option::Option<Vec<crate::types::string::Did>>,
    pub use_count: i64,
}
pub type Input = crate::types::Object<InputData>;
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    pub codes: Vec<AccountCodes>,
}
pub type Output = crate::types::Object<OutputData>;
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
pub struct AccountCodesData {
    pub account: String,
    pub codes: Vec<String>,
}
pub type AccountCodes = crate::types::Object<AccountCodesData>;
