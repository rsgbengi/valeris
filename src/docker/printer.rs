use crate::docker::model::{Finding, RiskLevel};
use bollard::models::ContainerInspectResponse;

pub fn print_container_report(container: &ContainerInspectResponse, findings: &[Finding]) {
    let name = container
        .name
        .as_deref()
        .unwrap_or("<none>")
        .trim_start_matches('/');
    let image = container
        .config
        .as_ref()
        .and_then(|cfg| cfg.image.as_deref())
        .or(container.image.as_deref())
        .unwrap_or("<unknown>");
    let image_with_tag = if image.contains(':') {
        image.to_string()
    } else {
        format!("{image}:latest")
    };

    println!("🔍 Container: {}", name);
    println!("   └─ Image: {}", image_with_tag);

    if findings.is_empty() {
        println!("   ✅ No findings detected.");
    } else {
        for finding in findings {
            let prefix = match finding.risk {
                RiskLevel::High => " [!!] ",
                RiskLevel::Medium => " [!]  ",
                RiskLevel::Low => " [·]  ",
                RiskLevel::Informative => " [i]  ",
            };
            println!("{prefix} {}: {}", finding.kind, finding.description);
        }
    }

    println!("---------------------------------------------");
}
