// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.server.getAccountInviteCodes` namespace.
pub const NSID: &str = "com.atproto.server.getAccountInviteCodes";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    ///Controls whether any new 'earned' but not 'created' invites should be created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_used: Option<bool>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub codes: Vec<crate::com::atproto::server::defs::InviteCode>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "error", content = "message")]
pub enum Error {
    DuplicateCreate(Option<String>),
}
impl std::fmt::Display for Error {
    fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::DuplicateCreate(msg) => {
                write!(_f, "DuplicateCreate")?;
                if let Some(msg) = msg {
                    write!(_f, ": {msg}")?;
                }
            }
        }
        Ok(())
    }
}
