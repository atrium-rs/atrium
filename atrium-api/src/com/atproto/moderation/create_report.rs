// @generated - This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.moderation.createReport` namespace.
pub const NSID: &str = "com.atproto.moderation.createReport";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InputData {
    ///Additional context about the content and violation.
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub reason: core::option::Option<String>,
    ///Indicates the broad category of violation the report is for.
    pub reason_type: crate::com::atproto::moderation::defs::ReasonType,
    pub subject: crate::types::Union<InputSubjectRefs>,
}
pub type Input = crate::types::Object<InputData>;
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    pub created_at: crate::types::string::Datetime,
    pub id: i64,
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub reason: core::option::Option<String>,
    pub reason_type: crate::com::atproto::moderation::defs::ReasonType,
    pub reported_by: crate::types::string::Did,
    pub subject: crate::types::Union<OutputSubjectRefs>,
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
#[serde(tag = "$type")]
pub enum InputSubjectRefs {
    #[serde(rename = "com.atproto.admin.defs#repoRef")]
    ComAtprotoAdminDefsRepoRef(Box<crate::com::atproto::admin::defs::RepoRef>),
    #[serde(rename = "com.atproto.repo.strongRef")]
    ComAtprotoRepoStrongRefMain(Box<crate::com::atproto::repo::strong_ref::Main>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum OutputSubjectRefs {
    #[serde(rename = "com.atproto.admin.defs#repoRef")]
    ComAtprotoAdminDefsRepoRef(Box<crate::com::atproto::admin::defs::RepoRef>),
    #[serde(rename = "com.atproto.repo.strongRef")]
    ComAtprotoRepoStrongRefMain(Box<crate::com::atproto::repo::strong_ref::Main>),
}
