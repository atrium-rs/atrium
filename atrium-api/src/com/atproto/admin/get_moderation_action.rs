// This file is generated by atrium-codegen. Do not edit.
//! Definitions for the `com.atproto.admin.getModerationAction` namespace.

/// View details about a moderation action.
#[async_trait::async_trait]
pub trait GetModerationAction: crate::xrpc::XrpcClient {
    async fn get_moderation_action(&self, params: Parameters) -> Result<Output, Box<dyn std::error::Error>> {
        let body = crate::xrpc::XrpcClient::send(
            self,
            http::Method::GET,
            "com.atproto.admin.getModerationAction",
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
    pub id: i32,
}

pub type Output = crate::com::atproto::admin::defs::ActionViewDetail;

pub enum Error {
}
