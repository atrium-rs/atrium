// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `app.bsky.feed.threadgate` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<crate::types::Union<RecordAllowItem>>>,
    pub created_at: crate::types::string::Datetime,
    ///Reference (AT-URI) to the post record.
    pub post: String,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Allow replies from actors you follow.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FollowingRule {
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Allow replies from actors on a list.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListRule {
    pub list: String,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Allow replies from actors mentioned in your post.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MentionRule {
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum RecordAllowItem {
    #[serde(rename = "app.bsky.feed.threadgate#mentionRule")]
    MentionRule(Box<MentionRule>),
    #[serde(rename = "app.bsky.feed.threadgate#followingRule")]
    FollowingRule(Box<FollowingRule>),
    #[serde(rename = "app.bsky.feed.threadgate#listRule")]
    ListRule(Box<ListRule>),
}
