// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `app.bsky.feed.defs` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockedAuthor {
    pub did: crate::types::string::Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer: Option<crate::app::bsky::actor::defs::ViewerState>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockedPost {
    pub author: BlockedAuthor,
    pub blocked: bool,
    pub uri: String,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///User clicked through to the author of the feed item
pub const CLICKTHROUGH_AUTHOR: &str = "app.bsky.feed.defs#clickthroughAuthor";
///User clicked through to the embedded content of the feed item
pub const CLICKTHROUGH_EMBED: &str = "app.bsky.feed.defs#clickthroughEmbed";
///User clicked through to the feed item
pub const CLICKTHROUGH_ITEM: &str = "app.bsky.feed.defs#clickthroughItem";
///User clicked through to the reposter of the feed item
pub const CLICKTHROUGH_REPOSTER: &str = "app.bsky.feed.defs#clickthroughReposter";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FeedViewPost {
    ///Context provided by feed generator that may be passed back alongside interactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed_context: Option<String>,
    pub post: PostView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<crate::types::Union<FeedViewPostReasonRefs>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<ReplyRef>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GeneratorView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepts_interactions: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    pub cid: crate::types::string::Cid,
    pub creator: crate::app::bsky::actor::defs::ProfileView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_facets: Option<Vec<crate::app::bsky::richtext::facet::Main>>,
    pub did: crate::types::string::Did,
    pub display_name: String,
    pub indexed_at: crate::types::string::Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<crate::com::atproto::label::defs::Label>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub like_count: Option<usize>,
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer: Option<GeneratorViewerState>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GeneratorViewerState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub like: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Interaction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    ///Context on a feed item that was orginally supplied by the feed generator on getFeedSkeleton.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///User liked the feed item
pub const INTERACTION_LIKE: &str = "app.bsky.feed.defs#interactionLike";
///User quoted the feed item
pub const INTERACTION_QUOTE: &str = "app.bsky.feed.defs#interactionQuote";
///User replied to the feed item
pub const INTERACTION_REPLY: &str = "app.bsky.feed.defs#interactionReply";
///User reposted the feed item
pub const INTERACTION_REPOST: &str = "app.bsky.feed.defs#interactionRepost";
///Feed item was seen by user
pub const INTERACTION_SEEN: &str = "app.bsky.feed.defs#interactionSeen";
///User shared the feed item
pub const INTERACTION_SHARE: &str = "app.bsky.feed.defs#interactionShare";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NotFoundPost {
    pub not_found: bool,
    pub uri: String,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PostView {
    pub author: crate::app::bsky::actor::defs::ProfileViewBasic,
    pub cid: crate::types::string::Cid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed: Option<crate::types::Union<PostViewEmbedRefs>>,
    pub indexed_at: crate::types::string::Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<crate::com::atproto::label::defs::Label>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub like_count: Option<i64>,
    pub record: crate::records::Record,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repost_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threadgate: Option<ThreadgateView>,
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer: Option<ViewerState>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReasonRepost {
    pub by: crate::app::bsky::actor::defs::ProfileViewBasic,
    pub indexed_at: crate::types::string::Datetime,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReplyRef {
    ///When parent is a reply to another post, this is the author of that post.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grandparent_author: Option<crate::app::bsky::actor::defs::ProfileViewBasic>,
    pub parent: crate::types::Union<ReplyRefParentRefs>,
    pub root: crate::types::Union<ReplyRefRootRefs>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Request that less content like the given feed item be shown in the feed
pub const REQUEST_LESS: &str = "app.bsky.feed.defs#requestLess";
///Request that more content like the given feed item be shown in the feed
pub const REQUEST_MORE: &str = "app.bsky.feed.defs#requestMore";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SkeletonFeedPost {
    ///Context that will be passed through to client and may be passed to feed generator back alongside interactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed_context: Option<String>,
    pub post: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<crate::types::Union<SkeletonFeedPostReasonRefs>>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SkeletonReasonRepost {
    pub repost: String,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ThreadViewPost {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<crate::types::Union<ThreadViewPostParentRefs>>,
    pub post: PostView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replies: Option<Vec<crate::types::Union<ThreadViewPostRepliesItem>>>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ThreadgateView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<crate::types::string::Cid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lists: Option<Vec<crate::app::bsky::graph::defs::ListViewBasic>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<crate::records::Record>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Metadata about the requesting account's relationship with the subject content. Only has meaningful content for authed requests.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ViewerState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub like: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repost: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_muted: Option<bool>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum FeedViewPostReasonRefs {
    #[serde(rename = "app.bsky.feed.defs#reasonRepost")]
    ReasonRepost(Box<ReasonRepost>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum PostViewEmbedRefs {
    #[serde(rename = "app.bsky.embed.images#view")]
    AppBskyEmbedImagesView(Box<crate::app::bsky::embed::images::View>),
    #[serde(rename = "app.bsky.embed.external#view")]
    AppBskyEmbedExternalView(Box<crate::app::bsky::embed::external::View>),
    #[serde(rename = "app.bsky.embed.record#view")]
    AppBskyEmbedRecordView(Box<crate::app::bsky::embed::record::View>),
    #[serde(rename = "app.bsky.embed.recordWithMedia#view")]
    AppBskyEmbedRecordWithMediaView(
        Box<crate::app::bsky::embed::record_with_media::View>,
    ),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum ReplyRefParentRefs {
    #[serde(rename = "app.bsky.feed.defs#postView")]
    PostView(Box<PostView>),
    #[serde(rename = "app.bsky.feed.defs#notFoundPost")]
    NotFoundPost(Box<NotFoundPost>),
    #[serde(rename = "app.bsky.feed.defs#blockedPost")]
    BlockedPost(Box<BlockedPost>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum ReplyRefRootRefs {
    #[serde(rename = "app.bsky.feed.defs#postView")]
    PostView(Box<PostView>),
    #[serde(rename = "app.bsky.feed.defs#notFoundPost")]
    NotFoundPost(Box<NotFoundPost>),
    #[serde(rename = "app.bsky.feed.defs#blockedPost")]
    BlockedPost(Box<BlockedPost>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum SkeletonFeedPostReasonRefs {
    #[serde(rename = "app.bsky.feed.defs#skeletonReasonRepost")]
    SkeletonReasonRepost(Box<SkeletonReasonRepost>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum ThreadViewPostParentRefs {
    #[serde(rename = "app.bsky.feed.defs#threadViewPost")]
    ThreadViewPost(Box<ThreadViewPost>),
    #[serde(rename = "app.bsky.feed.defs#notFoundPost")]
    NotFoundPost(Box<NotFoundPost>),
    #[serde(rename = "app.bsky.feed.defs#blockedPost")]
    BlockedPost(Box<BlockedPost>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum ThreadViewPostRepliesItem {
    #[serde(rename = "app.bsky.feed.defs#threadViewPost")]
    ThreadViewPost(Box<ThreadViewPost>),
    #[serde(rename = "app.bsky.feed.defs#notFoundPost")]
    NotFoundPost(Box<NotFoundPost>),
    #[serde(rename = "app.bsky.feed.defs#blockedPost")]
    BlockedPost(Box<BlockedPost>),
}
