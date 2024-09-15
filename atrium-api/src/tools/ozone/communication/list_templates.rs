// This file is generated by atrium-codegen. DO NOT EDIT.
//!Definitions for the `tools.ozone.communication.listTemplates` namespace.
pub const NSID: &str = "tools.ozone.communication.listTemplates";
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    pub communication_templates: Vec<
        crate::tools::ozone::communication::defs::TemplateView,
    >,
}
pub type Output = crate::types::Object<OutputData>;
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "error", content = "message")]
pub enum Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
        Ok(())
    }
}
