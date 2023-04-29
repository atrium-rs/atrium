// This file is generated by atrium-codegen. Do not edit.
//! Definitions for the `app.bsky.feed.getPostThread` namespace.

#[async_trait::async_trait]
pub trait GetPostThread: crate::xrpc::XrpcClient {
    async fn get_post_thread(&self, params: Parameters) -> Result<Output, Box<dyn std::error::Error>> {
        let body = crate::xrpc::XrpcClient::send(
            self,
            http::Method::GET,
            "app.bsky.feed.getPostThread",
            Some(serde_urlencoded::to_string(&params)?),
            None,
            None,
        )
        .await?;
        serde_json::from_slice(&body).map_err(|e| e.into())
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<i32>,
    pub uri: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub thread: Box<OutputThreadEnum>,
}

pub enum Error {
    NotFound,
}

#[allow(clippy::large_enum_variant)]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "$type")]
pub enum OutputThreadEnum {
    #[serde(rename = "app.bsky.feed.defs#threadViewPost")]
    AppBskyFeedDefsThreadViewPost(crate::app::bsky::feed::defs::ThreadViewPost),
    #[serde(rename = "app.bsky.feed.defs#notFoundPost")]
    AppBskyFeedDefsNotFoundPost(crate::app::bsky::feed::defs::NotFoundPost),
    #[serde(rename = "app.bsky.feed.defs#blockedPost")]
    AppBskyFeedDefsBlockedPost(crate::app::bsky::feed::defs::BlockedPost),
}
