// This file is generated by atrium-codegen. Do not edit.
//! Definitions for the `com.atproto.admin.reverseModerationAction` namespace.

/// Reverse a moderation action.
#[async_trait::async_trait]
pub trait ReverseModerationAction: crate::xrpc::XrpcClient {
    async fn reverse_moderation_action(&self, input: Input) -> Result<Output, Box<dyn std::error::Error>> {
        let body = crate::xrpc::XrpcClient::send(
            self,
            http::Method::POST,
            "com.atproto.admin.reverseModerationAction",
            None,
            Some(serde_json::to_vec(&input)?),
            Some(String::from("application/json")),
        )
        .await?;
        serde_json::from_slice(&body).map_err(|e| e.into())
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    pub created_by: String,
    pub id: i32,
    pub reason: String,
}

pub type Output = crate::com::atproto::admin::defs::ActionView;

pub enum Error {
}
