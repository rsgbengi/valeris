use bollard::secret::ContainerInspectResponse;
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub kind: String, 
    pub description: String,
    pub risk: RiskLevel,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
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

