// This file is generated by atrium-codegen. Do not edit.
//! Definitions for the `com.atproto.server.createAppPassword` namespace.

/// Create an app-specific password.
#[async_trait::async_trait]
pub trait CreateAppPassword: crate::xrpc::XrpcClient {
    async fn create_app_password(&self, input: Input) -> Result<Output, Box<dyn std::error::Error>> {
        let body = crate::xrpc::XrpcClient::send(
            self,
            http::Method::POST,
            "com.atproto.server.createAppPassword",
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
    pub name: String,
}

pub type Output = AppPassword;

pub enum Error {
    AccountTakedown,
}

// com.atproto.server.createAppPassword#appPassword
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppPassword {
    pub created_at: String,
    pub name: String,
    pub password: String,
}
