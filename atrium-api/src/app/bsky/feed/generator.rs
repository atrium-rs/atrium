// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `app.bsky.feed.generator` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    ///Declaration that a feed accepts feedback interactions from a client through app.bsky.feed.sendInteractions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepts_interactions: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<crate::types::BlobRef>,
    pub created_at: crate::types::string::Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_facets: Option<Vec<crate::app::bsky::richtext::facet::Main>>,
    pub did: crate::types::string::Did,
    pub display_name: String,
    ///Self-label values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<crate::types::Union<RecordLabelsRefs>>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum RecordLabelsRefs {
    #[serde(rename = "com.atproto.label.defs#selfLabels")]
    ComAtprotoLabelDefsSelfLabels(Box<crate::com::atproto::label::defs::SelfLabels>),
}
