// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `app.bsky.graph.listitem` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub created_at: String,
    ///Reference (AT-URI) to the list record (app.bsky.graph.list).
    pub list: String,
    ///The account which is included on the list.
    pub subject: crate::types::string::Did,
}
