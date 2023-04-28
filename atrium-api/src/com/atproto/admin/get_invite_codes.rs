// This file is generated by atrium-codegen. Do not edit.
//! Definitions for the `com.atproto.admin.getInviteCodes` namespace.

/// Admin view of invite codes
#[async_trait::async_trait]
pub trait GetInviteCodes: crate::xrpc::XrpcClient {
    async fn get_invite_codes(&self, params: Parameters) -> Result<Output, Box<dyn std::error::Error>> {
        let body = crate::xrpc::XrpcClient::send(
            self,
            http::Method::GET,
            "com.atproto.admin.getInviteCodes",
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
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub codes: Vec<crate::com::atproto::server::defs::InviteCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

pub enum Error {
}
