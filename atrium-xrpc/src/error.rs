#![doc = "Error types."]
use http::StatusCode;
use std::fmt::Debug;

/// [A standard error response schema](https://atproto.com/specs/xrpc#error-responses)
///
/// ```typescript
/// export const errorResponseBody = z.object({
///   error: z.string().optional(),
///   message: z.string().optional(),
/// })
/// export type ErrorResponseBody = z.infer<typeof errorResponseBody>
/// ```
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ErrorResponseBody {
    pub error: Option<String>,
    pub message: Option<String>,
}

/// An enum of possible XRPC error kinds.
///
/// Error defined in Lexicon schema or other standard error.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum XrpcErrorKind<E> {
    Custom(E),
    Undefined(ErrorResponseBody),
}

/// XRPC response error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrpcError<E> {
    pub status: StatusCode,
    pub error: Option<XrpcErrorKind<E>>,
}

/// An enum of possible error kinds.
#[derive(thiserror::Error, Debug)]
pub enum Error<E> {
    #[error("xrpc response error: {0:?}")]
    XrpcResponse(XrpcError<E>),
    #[error("http request error: {0}")]
    HttpRequest(#[from] http::Error),
    #[error("http client error: {0}")]
    HttpClient(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("serde_qs error: {0}")]
    SerdeQs(#[from] serde_qs::Error),
    #[error("unexpected response type")]
    UnexpectedResponseType,
}
