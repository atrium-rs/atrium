use atrium_identity::handle::{DnsTxtResolver, HandleResolverImpl};
use atrium_identity::identity_resolver::{DidResolverConfig, HandleResolverConfig};
use atrium_oauth_client::store::state::MemoryStateStore;
use atrium_oauth_client::{
    AtprotoLocalhostClientMetadata, AuthorizeOptions, OAuthClient, OAuthClientConfig,
    OAuthResolverConfig,
};
use atrium_xrpc::http::Uri;
use hickory_resolver::TokioAsyncResolver;
use std::io::{stdin, stdout, BufRead, Write};
use std::sync::Arc;

struct HickoryDnsTxtResolver {
    resolver: TokioAsyncResolver,
}

impl Default for HickoryDnsTxtResolver {
    fn default() -> Self {
        Self {
            resolver: TokioAsyncResolver::tokio_from_system_conf()
                .expect("failed to create resolver"),
        }
    }
}

#[async_trait::async_trait]
impl DnsTxtResolver for HickoryDnsTxtResolver {
    async fn resolve(
        &self,
        query: &str,
    ) -> core::result::Result<Vec<String>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(self
            .resolver
            .txt_lookup(query)
            .await?
            .iter()
            .map(|txt| txt.to_string())
            .collect())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OAuthClientConfig {
        client_metadata: AtprotoLocalhostClientMetadata {
            redirect_uris: vec!["http://127.0.0.1".to_string()],
        },
        keys: None,
        resolver: OAuthResolverConfig {
            did: DidResolverConfig::default(),
            handle: HandleResolverConfig {
                r#impl: HandleResolverImpl::Atproto(Arc::new(HickoryDnsTxtResolver::default())),
                cache: Default::default(),
            },
            authorization_server_metadata: Default::default(),
            protected_resource_metadata: Default::default(),
        },
        state_store: MemoryStateStore::default(),
    };
    let client = OAuthClient::new(config)?;
    println!(
        "Authorization url: {}",
        client
            .authorize(
                std::env::var("HANDLE").unwrap_or(String::from("https://bsky.social")),
                AuthorizeOptions {
                    scopes: Some(vec![String::from("atproto")]),
                    ..Default::default()
                }
            )
            .await?
    );

    // Click the URL and sign in,
    // then copy and paste the URL like “http://127.0.0.1/?iss=...&code=...” after it is redirected.

    print!("Redirected url: ");
    stdout().lock().flush()?;
    let mut url = String::new();
    stdin().lock().read_line(&mut url)?;

    let uri = url.trim().parse::<Uri>()?;
    let params = serde_html_form::from_str(uri.query().unwrap())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&client.callback(params).await?)?
    );

    Ok(())
}
