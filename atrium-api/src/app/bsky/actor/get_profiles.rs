// This file is generated by atrium-codegen. Do not edit.
//! Definitions for the `app.bsky.actor.getProfiles` namespace.

#[async_trait::async_trait]
pub trait GetProfiles: crate::xrpc::XrpcClient {
    async fn get_profiles(&self, params: Parameters) -> Result<Output, Box<dyn std::error::Error>> {
        let body = crate::xrpc::XrpcClient::send(
            self,
            http::Method::GET,
            "app.bsky.actor.getProfiles",
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
    pub actors: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub profiles: Vec<crate::app::bsky::actor::defs::ProfileViewDetailed>,
}

pub enum Error {
}
