// @generated - This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `app.bsky.unspecced.defs` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SkeletonSearchActorData {
    pub did: crate::types::string::Did,
}
pub type SkeletonSearchActor = crate::types::Object<SkeletonSearchActorData>;
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SkeletonSearchPostData {
    pub uri: String,
}
pub type SkeletonSearchPost = crate::types::Object<SkeletonSearchPostData>;
