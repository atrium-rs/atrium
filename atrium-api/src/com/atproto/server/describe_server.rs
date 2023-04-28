// This file is generated by atrium-codegen. Do not edit.
//! Definitions for the `com.atproto.server.describeServer` namespace.

/// Get a document describing the service's accounts configuration.
#[async_trait::async_trait]
pub trait DescribeServer: crate::xrpc::XrpcClient {
    async fn describe_server(&self) -> Result<Output, Box<dyn std::error::Error>> {
        let body = crate::xrpc::XrpcClient::send(
            self,
            http::Method::GET,
            "com.atproto.server.describeServer",
            None,
            None,
            None,
        )
        .await?;
        serde_json::from_slice(&body).map_err(|e| e.into())
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub available_user_domains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_code_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

pub enum Error {
}

// com.atproto.server.describeServer#links
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Links {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<String>,
}
