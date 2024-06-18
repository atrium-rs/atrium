// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `app.bsky.graph.follow` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub created_at: crate::types::string::Datetime,
    pub subject: crate::types::string::Did,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
