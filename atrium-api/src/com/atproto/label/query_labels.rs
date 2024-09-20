// @generated - This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.label.queryLabels` namespace.
pub const NSID: &str = "com.atproto.label.queryLabels";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ParametersData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<crate::types::LimitedNonZeroU8<250u8>>,
    ///Optional list of label sources (DIDs) to filter on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<crate::types::string::Did>>,
    ///List of AT URI patterns to match (boolean 'OR'). Each may be a prefix (ending with '*'; will match inclusive of the string leading to '*'), or a full URI.
    pub uri_patterns: Vec<String>,
}
pub type Parameters = crate::types::Object<ParametersData>;
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub labels: Vec<crate::com::atproto::label::defs::Label>,
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
