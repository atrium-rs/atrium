// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `tools.ozone.communication.updateTemplate` namespace.
pub const NSID: &str = "tools.ozone.communication.updateTemplate";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    ///Content of the template, markdown supported, can contain variable placeholders.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_markdown: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    ///ID of the template to be updated.
    pub id: String,
    ///Name of the template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    ///Subject of the message, used in emails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    ///DID of the user who is updating the template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<crate::types::string::Did>,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
pub type Output = crate::tools::ozone::communication::defs::TemplateView;
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "error", content = "message")]
pub enum Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
        Ok(())
    }
}
