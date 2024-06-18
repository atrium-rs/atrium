// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `chat.bsky.moderation.getMessageContext` namespace.
pub const NSID: &str = "chat.bsky.moderation.getMessageContext";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<i64>,
    ///Conversation that the message is from. NOTE: this field will eventually be required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convo_id: Option<String>,
    pub message_id: String,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub messages: Vec<crate::types::Union<OutputMessagesItem>>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
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
pub enum OutputMessagesItem {
    #[serde(rename = "chat.bsky.convo.defs#messageView")]
    ChatBskyConvoDefsMessageView(Box<crate::chat::bsky::convo::defs::MessageView>),
    #[serde(rename = "chat.bsky.convo.defs#deletedMessageView")]
    ChatBskyConvoDefsDeletedMessageView(
        Box<crate::chat::bsky::convo::defs::DeletedMessageView>,
    ),
}
