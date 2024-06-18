// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `tools.ozone.moderation.defs` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlobView {
    pub cid: crate::types::string::Cid,
    pub created_at: crate::types::string::Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<crate::types::Union<BlobViewDetailsRefs>>,
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moderation: Option<Moderation>,
    pub size: i64,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImageDetails {
    pub height: i64,
    pub width: i64,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventAcknowledge {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Add a comment to a subject
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventComment {
    pub comment: String,
    ///Make the comment persistent on the subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sticky: Option<bool>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Divert a record's blobs to a 3rd party service for further scanning/tagging
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventDivert {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Keep a log of outgoing email to a user
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventEmail {
    ///Additional comment about the outgoing comm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    ///The content of the email sent to the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    ///The subject line of the email sent to the user.
    pub subject_line: String,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventEscalate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Apply/Negate labels on a subject
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventLabel {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub create_label_vals: Vec<String>,
    pub negate_label_vals: Vec<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Mute incoming reports on a subject
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventMute {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    ///Indicates how long the subject should remain muted.
    pub duration_in_hours: i64,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Mute incoming reports from an account
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventMuteReporter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    ///Indicates how long the account should remain muted.
    pub duration_in_hours: i64,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Report a subject
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    ///Set to true if the reporter was muted from reporting at the time of the event. These reports won't impact the reviewState of the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_reporter_muted: Option<bool>,
    pub report_type: crate::com::atproto::moderation::defs::ReasonType,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Resolve appeal on a subject
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventResolveAppeal {
    ///Describe resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Revert take down action on a subject
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventReverseTakedown {
    ///Describe reasoning behind the reversal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Add/Remove a tag on a subject
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventTag {
    ///Tags to be added to the subject. If already exists, won't be duplicated.
    pub add: Vec<String>,
    ///Additional comment about added/removed tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    ///Tags to be removed to the subject. Ignores a tag If it doesn't exist, won't be duplicated.
    pub remove: Vec<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Take down a subject permanently or temporarily
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventTakedown {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    ///Indicates how long the takedown should be in effect before automatically expiring.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_in_hours: Option<i64>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Unmute action on a subject
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventUnmute {
    ///Describe reasoning behind the reversal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Unmute incoming reports from an account
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventUnmuteReporter {
    ///Describe reasoning behind the reversal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventView {
    pub created_at: crate::types::string::Datetime,
    pub created_by: crate::types::string::Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator_handle: Option<String>,
    pub event: crate::types::Union<ModEventViewEventRefs>,
    pub id: i64,
    pub subject: crate::types::Union<ModEventViewSubjectRefs>,
    pub subject_blob_cids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_handle: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModEventViewDetail {
    pub created_at: crate::types::string::Datetime,
    pub created_by: crate::types::string::Did,
    pub event: crate::types::Union<ModEventViewDetailEventRefs>,
    pub id: i64,
    pub subject: crate::types::Union<ModEventViewDetailSubjectRefs>,
    pub subject_blobs: Vec<BlobView>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Moderation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_status: Option<SubjectStatusView>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModerationDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_status: Option<SubjectStatusView>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecordView {
    pub blob_cids: Vec<crate::types::string::Cid>,
    pub cid: crate::types::string::Cid,
    pub indexed_at: crate::types::string::Datetime,
    pub moderation: Moderation,
    pub repo: RepoView,
    pub uri: String,
    pub value: crate::records::Record,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecordViewDetail {
    pub blobs: Vec<BlobView>,
    pub cid: crate::types::string::Cid,
    pub indexed_at: crate::types::string::Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<crate::com::atproto::label::defs::Label>>,
    pub moderation: ModerationDetail,
    pub repo: RepoView,
    pub uri: String,
    pub value: crate::records::Record,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecordViewNotFound {
    pub uri: String,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepoView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<crate::types::string::Datetime>,
    pub did: crate::types::string::Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub handle: crate::types::string::Handle,
    pub indexed_at: crate::types::string::Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invited_by: Option<crate::com::atproto::server::defs::InviteCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invites_disabled: Option<bool>,
    pub moderation: Moderation,
    pub related_records: Vec<crate::records::Record>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepoViewDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<crate::types::string::Datetime>,
    pub did: crate::types::string::Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirmed_at: Option<crate::types::string::Datetime>,
    pub handle: crate::types::string::Handle,
    pub indexed_at: crate::types::string::Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invited_by: Option<crate::com::atproto::server::defs::InviteCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invites: Option<Vec<crate::com::atproto::server::defs::InviteCode>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invites_disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<crate::com::atproto::label::defs::Label>>,
    pub moderation: ModerationDetail,
    pub related_records: Vec<crate::records::Record>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepoViewNotFound {
    pub did: crate::types::string::Did,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
///Moderator review status of a subject: Closed. Indicates that the subject was already reviewed and resolved by a moderator
pub const REVIEW_CLOSED: &str = "tools.ozone.moderation.defs#reviewClosed";
///Moderator review status of a subject: Escalated. Indicates that the subject was escalated for review by a moderator
pub const REVIEW_ESCALATED: &str = "tools.ozone.moderation.defs#reviewEscalated";
///Moderator review status of a subject: Unnecessary. Indicates that the subject does not need a review at the moment but there is probably some moderation related metadata available for it
pub const REVIEW_NONE: &str = "tools.ozone.moderation.defs#reviewNone";
///Moderator review status of a subject: Open. Indicates that the subject needs to be reviewed by a moderator
pub const REVIEW_OPEN: &str = "tools.ozone.moderation.defs#reviewOpen";
pub type SubjectReviewState = String;
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SubjectStatusView {
    ///True indicates that the a previously taken moderator action was appealed against, by the author of the content. False indicates last appeal was resolved by moderators.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appealed: Option<bool>,
    ///Sticky comment on the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    ///Timestamp referencing the first moderation status impacting event was emitted on the subject
    pub created_at: crate::types::string::Datetime,
    pub id: i64,
    ///Timestamp referencing when the author of the subject appealed a moderation action
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_appealed_at: Option<crate::types::string::Datetime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reported_at: Option<crate::types::string::Datetime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reviewed_at: Option<crate::types::string::Datetime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reviewed_by: Option<crate::types::string::Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mute_reporting_until: Option<crate::types::string::Datetime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mute_until: Option<crate::types::string::Datetime>,
    pub review_state: SubjectReviewState,
    pub subject: crate::types::Union<SubjectStatusViewSubjectRefs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_blob_cids: Option<Vec<crate::types::string::Cid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_repo_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspend_until: Option<crate::types::string::Datetime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takendown: Option<bool>,
    ///Timestamp referencing when the last update was made to the moderation status of the subject
    pub updated_at: crate::types::string::Datetime,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VideoDetails {
    pub height: i64,
    pub length: i64,
    pub width: i64,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum BlobViewDetailsRefs {
    #[serde(rename = "tools.ozone.moderation.defs#imageDetails")]
    ImageDetails(Box<ImageDetails>),
    #[serde(rename = "tools.ozone.moderation.defs#videoDetails")]
    VideoDetails(Box<VideoDetails>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum ModEventViewDetailEventRefs {
    #[serde(rename = "tools.ozone.moderation.defs#modEventTakedown")]
    ModEventTakedown(Box<ModEventTakedown>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventReverseTakedown")]
    ModEventReverseTakedown(Box<ModEventReverseTakedown>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventComment")]
    ModEventComment(Box<ModEventComment>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventReport")]
    ModEventReport(Box<ModEventReport>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventLabel")]
    ModEventLabel(Box<ModEventLabel>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventAcknowledge")]
    ModEventAcknowledge(Box<ModEventAcknowledge>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventEscalate")]
    ModEventEscalate(Box<ModEventEscalate>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventMute")]
    ModEventMute(Box<ModEventMute>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventUnmute")]
    ModEventUnmute(Box<ModEventUnmute>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventMuteReporter")]
    ModEventMuteReporter(Box<ModEventMuteReporter>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventUnmuteReporter")]
    ModEventUnmuteReporter(Box<ModEventUnmuteReporter>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventEmail")]
    ModEventEmail(Box<ModEventEmail>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventResolveAppeal")]
    ModEventResolveAppeal(Box<ModEventResolveAppeal>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventDivert")]
    ModEventDivert(Box<ModEventDivert>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum ModEventViewDetailSubjectRefs {
    #[serde(rename = "tools.ozone.moderation.defs#repoView")]
    RepoView(Box<RepoView>),
    #[serde(rename = "tools.ozone.moderation.defs#repoViewNotFound")]
    RepoViewNotFound(Box<RepoViewNotFound>),
    #[serde(rename = "tools.ozone.moderation.defs#recordView")]
    RecordView(Box<RecordView>),
    #[serde(rename = "tools.ozone.moderation.defs#recordViewNotFound")]
    RecordViewNotFound(Box<RecordViewNotFound>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum ModEventViewEventRefs {
    #[serde(rename = "tools.ozone.moderation.defs#modEventTakedown")]
    ModEventTakedown(Box<ModEventTakedown>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventReverseTakedown")]
    ModEventReverseTakedown(Box<ModEventReverseTakedown>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventComment")]
    ModEventComment(Box<ModEventComment>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventReport")]
    ModEventReport(Box<ModEventReport>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventLabel")]
    ModEventLabel(Box<ModEventLabel>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventAcknowledge")]
    ModEventAcknowledge(Box<ModEventAcknowledge>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventEscalate")]
    ModEventEscalate(Box<ModEventEscalate>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventMute")]
    ModEventMute(Box<ModEventMute>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventUnmute")]
    ModEventUnmute(Box<ModEventUnmute>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventMuteReporter")]
    ModEventMuteReporter(Box<ModEventMuteReporter>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventUnmuteReporter")]
    ModEventUnmuteReporter(Box<ModEventUnmuteReporter>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventEmail")]
    ModEventEmail(Box<ModEventEmail>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventResolveAppeal")]
    ModEventResolveAppeal(Box<ModEventResolveAppeal>),
    #[serde(rename = "tools.ozone.moderation.defs#modEventDivert")]
    ModEventDivert(Box<ModEventDivert>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum ModEventViewSubjectRefs {
    #[serde(rename = "com.atproto.admin.defs#repoRef")]
    ComAtprotoAdminDefsRepoRef(Box<crate::com::atproto::admin::defs::RepoRef>),
    #[serde(rename = "com.atproto.repo.strongRef")]
    ComAtprotoRepoStrongRefMain(Box<crate::com::atproto::repo::strong_ref::Main>),
    #[serde(rename = "chat.bsky.convo.defs#messageRef")]
    ChatBskyConvoDefsMessageRef(Box<crate::chat::bsky::convo::defs::MessageRef>),
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "$type")]
pub enum SubjectStatusViewSubjectRefs {
    #[serde(rename = "com.atproto.admin.defs#repoRef")]
    ComAtprotoAdminDefsRepoRef(Box<crate::com::atproto::admin::defs::RepoRef>),
    #[serde(rename = "com.atproto.repo.strongRef")]
    ComAtprotoRepoStrongRefMain(Box<crate::com::atproto::repo::strong_ref::Main>),
}
