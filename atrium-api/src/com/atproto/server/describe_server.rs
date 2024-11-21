// @generated - This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.server.describeServer` namespace.
pub const NSID: &str = "com.atproto.server.describeServer";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    ///List of domain suffixes that can be used in account handles.
    pub available_user_domains: Vec<String>,
    ///Contact information
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub contact: core::option::Option<Contact>,
    pub did: crate::types::string::Did,
    ///If true, an invite code must be supplied to create an account on this instance.
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub invite_code_required: core::option::Option<bool>,
    ///URLs of service policy documents.
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub links: core::option::Option<Links>,
    ///If true, a phone verification token must be supplied to create an account on this instance.
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub phone_verification_required: core::option::Option<bool>,
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
pub struct ContactData {
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub email: core::option::Option<String>,
}
pub type Contact = crate::types::Object<ContactData>;
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinksData {
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub privacy_policy: core::option::Option<String>,
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub terms_of_service: core::option::Option<String>,
}
pub type Links = crate::types::Object<LinksData>;
