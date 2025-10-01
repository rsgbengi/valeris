use bollard::secret::ContainerInspectResponse;
use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Finding {
    pub kind: String,
    pub description: String,
    pub risk: RiskLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

#[derive(Debug, Serialize,Deserialize, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Informative,
    Low,
    Medium,
    High,
}
pub struct ContainerResult {
    pub container: ContainerInspectResponse,
    pub findings: Vec<Finding>,
}
