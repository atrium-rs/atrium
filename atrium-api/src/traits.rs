// This file is generated by atrium-codegen. Do not edit.

#[macro_export]
macro_rules! impl_traits {
    ($type:ty) => {
        impl atrium_api::app::bsky::actor::get_profile::GetProfile for $type {}
        impl atrium_api::app::bsky::actor::get_profiles::GetProfiles for $type {}
        impl atrium_api::app::bsky::actor::get_suggestions::GetSuggestions for $type {}
        impl atrium_api::app::bsky::actor::search_actors::SearchActors for $type {}
        impl atrium_api::app::bsky::actor::search_actors_typeahead::SearchActorsTypeahead for $type {}
        impl atrium_api::app::bsky::feed::get_author_feed::GetAuthorFeed for $type {}
        impl atrium_api::app::bsky::feed::get_likes::GetLikes for $type {}
        impl atrium_api::app::bsky::feed::get_post_thread::GetPostThread for $type {}
        impl atrium_api::app::bsky::feed::get_posts::GetPosts for $type {}
        impl atrium_api::app::bsky::feed::get_reposted_by::GetRepostedBy for $type {}
        impl atrium_api::app::bsky::feed::get_timeline::GetTimeline for $type {}
        impl atrium_api::app::bsky::graph::get_blocks::GetBlocks for $type {}
        impl atrium_api::app::bsky::graph::get_followers::GetFollowers for $type {}
        impl atrium_api::app::bsky::graph::get_follows::GetFollows for $type {}
        impl atrium_api::app::bsky::graph::get_mutes::GetMutes for $type {}
        impl atrium_api::app::bsky::graph::mute_actor::MuteActor for $type {}
        impl atrium_api::app::bsky::graph::unmute_actor::UnmuteActor for $type {}
        impl atrium_api::app::bsky::notification::get_unread_count::GetUnreadCount for $type {}
        impl atrium_api::app::bsky::notification::list_notifications::ListNotifications for $type {}
        impl atrium_api::app::bsky::notification::update_seen::UpdateSeen for $type {}
        impl atrium_api::app::bsky::unspecced::get_popular::GetPopular for $type {}
        impl atrium_api::com::atproto::admin::disable_invite_codes::DisableInviteCodes for $type {}
        impl atrium_api::com::atproto::admin::get_invite_codes::GetInviteCodes for $type {}
        impl atrium_api::com::atproto::admin::get_moderation_action::GetModerationAction for $type {}
        impl atrium_api::com::atproto::admin::get_moderation_actions::GetModerationActions for $type {}
        impl atrium_api::com::atproto::admin::get_moderation_report::GetModerationReport for $type {}
        impl atrium_api::com::atproto::admin::get_moderation_reports::GetModerationReports for $type {}
        impl atrium_api::com::atproto::admin::get_record::GetRecord for $type {}
        impl atrium_api::com::atproto::admin::get_repo::GetRepo for $type {}
        impl atrium_api::com::atproto::admin::resolve_moderation_reports::ResolveModerationReports for $type {}
        impl atrium_api::com::atproto::admin::reverse_moderation_action::ReverseModerationAction for $type {}
        impl atrium_api::com::atproto::admin::search_repos::SearchRepos for $type {}
        impl atrium_api::com::atproto::admin::take_moderation_action::TakeModerationAction for $type {}
        impl atrium_api::com::atproto::admin::update_account_email::UpdateAccountEmail for $type {}
        impl atrium_api::com::atproto::admin::update_account_handle::UpdateAccountHandle for $type {}
        impl atrium_api::com::atproto::identity::resolve_handle::ResolveHandle for $type {}
        impl atrium_api::com::atproto::identity::update_handle::UpdateHandle for $type {}
        impl atrium_api::com::atproto::label::query_labels::QueryLabels for $type {}
        impl atrium_api::com::atproto::moderation::create_report::CreateReport for $type {}
        impl atrium_api::com::atproto::repo::apply_writes::ApplyWrites for $type {}
        impl atrium_api::com::atproto::repo::create_record::CreateRecord for $type {}
        impl atrium_api::com::atproto::repo::delete_record::DeleteRecord for $type {}
        impl atrium_api::com::atproto::repo::describe_repo::DescribeRepo for $type {}
        impl atrium_api::com::atproto::repo::get_record::GetRecord for $type {}
        impl atrium_api::com::atproto::repo::list_records::ListRecords for $type {}
        impl atrium_api::com::atproto::repo::put_record::PutRecord for $type {}
        impl atrium_api::com::atproto::repo::upload_blob::UploadBlob for $type {}
        impl atrium_api::com::atproto::server::create_account::CreateAccount for $type {}
        impl atrium_api::com::atproto::server::create_app_password::CreateAppPassword for $type {}
        impl atrium_api::com::atproto::server::create_invite_code::CreateInviteCode for $type {}
        impl atrium_api::com::atproto::server::create_invite_codes::CreateInviteCodes for $type {}
        impl atrium_api::com::atproto::server::create_session::CreateSession for $type {}
        impl atrium_api::com::atproto::server::delete_account::DeleteAccount for $type {}
        impl atrium_api::com::atproto::server::delete_session::DeleteSession for $type {}
        impl atrium_api::com::atproto::server::describe_server::DescribeServer for $type {}
        impl atrium_api::com::atproto::server::get_account_invite_codes::GetAccountInviteCodes for $type {}
        impl atrium_api::com::atproto::server::get_session::GetSession for $type {}
        impl atrium_api::com::atproto::server::list_app_passwords::ListAppPasswords for $type {}
        impl atrium_api::com::atproto::server::refresh_session::RefreshSession for $type {}
        impl atrium_api::com::atproto::server::request_account_delete::RequestAccountDelete for $type {}
        impl atrium_api::com::atproto::server::request_password_reset::RequestPasswordReset for $type {}
        impl atrium_api::com::atproto::server::reset_password::ResetPassword for $type {}
        impl atrium_api::com::atproto::server::revoke_app_password::RevokeAppPassword for $type {}
        impl atrium_api::com::atproto::sync::get_blob::GetBlob for $type {}
        impl atrium_api::com::atproto::sync::get_blocks::GetBlocks for $type {}
        impl atrium_api::com::atproto::sync::get_checkout::GetCheckout for $type {}
        impl atrium_api::com::atproto::sync::get_commit_path::GetCommitPath for $type {}
        impl atrium_api::com::atproto::sync::get_head::GetHead for $type {}
        impl atrium_api::com::atproto::sync::get_record::GetRecord for $type {}
        impl atrium_api::com::atproto::sync::get_repo::GetRepo for $type {}
        impl atrium_api::com::atproto::sync::list_blobs::ListBlobs for $type {}
        impl atrium_api::com::atproto::sync::list_repos::ListRepos for $type {}
        impl atrium_api::com::atproto::sync::notify_of_update::NotifyOfUpdate for $type {}
        impl atrium_api::com::atproto::sync::request_crawl::RequestCrawl for $type {}
    };
}
