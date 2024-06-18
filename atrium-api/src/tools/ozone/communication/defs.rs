// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `tools.ozone.communication.defs` namespace.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TemplateView {
    ///Subject of the message, used in emails.
    pub content_markdown: String,
    pub created_at: crate::types::string::Datetime,
    pub disabled: bool,
    pub id: String,
    ///DID of the user who last updated the template.
    pub last_updated_by: crate::types::string::Did,
    ///Name of the template.
    pub name: String,
    ///Content of the template, can contain markdown and variable placeholders.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub updated_at: crate::types::string::Datetime,
    #[serde(flatten)]
    pub extra_data: ipld_core::ipld::Ipld,
}
