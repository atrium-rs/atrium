// @generated - This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `tools.ozone.team.defs` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemberData {
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub created_at: core::option::Option<crate::types::string::Datetime>,
    pub did: crate::types::string::Did,
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub disabled: core::option::Option<bool>,
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub last_updated_by: core::option::Option<String>,
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub profile: core::option::Option<
        crate::app::bsky::actor::defs::ProfileViewDetailed,
    >,
    pub role: String,
    #[serde(skip_serializing_if = "core::option::Option::is_none")]
    pub updated_at: core::option::Option<crate::types::string::Datetime>,
}
pub type Member = crate::types::Object<MemberData>;
///Admin role. Highest level of access, can perform all actions.
pub const ROLE_ADMIN: &str = "tools.ozone.team.defs#roleAdmin";
///Moderator role. Can perform most actions.
pub const ROLE_MODERATOR: &str = "tools.ozone.team.defs#roleModerator";
///Triage role. Mostly intended for monitoring and escalating issues.
pub const ROLE_TRIAGE: &str = "tools.ozone.team.defs#roleTriage";
///Verifier role. Only allowed to issue verifications.
pub const ROLE_VERIFIER: &str = "tools.ozone.team.defs#roleVerifier";
