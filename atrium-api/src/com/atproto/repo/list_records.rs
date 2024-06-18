// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `com.atproto.repo.listRecords` namespace.
pub const NSID: &str = "com.atproto.repo.listRecords";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    ///The NSID of the record type.
    pub collection: crate::types::string::Nsid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    ///The number of records to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<crate::types::LimitedNonZeroU8<100u8>>,
    ///The handle or DID of the repo.
    pub repo: crate::types::string::AtIdentifier,
    ///Flag to reverse the order of the returned records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse: Option<bool>,
    ///DEPRECATED: The highest sort-ordered rkey to stop at (exclusive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rkey_end: Option<String>,
    ///DEPRECATED: The lowest sort-ordered rkey to start from (exclusive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rkey_start: Option<String>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub records: Vec<Record>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "error", content = "message")]
pub enum Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
        Ok(())
    }
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub cid: crate::types::string::Cid,
    pub uri: String,
    pub value: crate::records::Record,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
