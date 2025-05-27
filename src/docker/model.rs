#[derive(Debug)]
pub struct Finding {
    pub kind: String, 
    pub description: String,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Informative,
    Low,
    Medium,
    High,
}
