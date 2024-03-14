// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.server.describeServer` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    ///List of domain suffixes that can be used in account handles.
    pub available_user_domains: Vec<String>,
    ///Contact information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Contact>,
    pub did: crate::types::string::Did,
    ///If true, an invite code must be supplied to create an account on this instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_code_required: Option<bool>,
    ///URLs of service policy documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
    ///If true, a phone verification token must be supplied to create an account on this instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_verification_required: Option<bool>,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "error", content = "message")]
pub enum Error {}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Links {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<String>,
}
