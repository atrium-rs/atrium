// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `app.bsky.labeler.service` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub created_at: crate::types::string::Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<crate::types::Union<RecordLabelsRefs>>,
    pub policies: crate::app::bsky::labeler::defs::LabelerPolicies,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum RecordLabelsRefs {
    #[serde(rename = "com.atproto.label.defs#selfLabels")]
    ComAtprotoLabelDefsSelfLabels(Box<crate::com::atproto::label::defs::SelfLabels>),
}
