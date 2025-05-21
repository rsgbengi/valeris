use anyhow::Result;
use bollard::container::{InspectContainerOptions, ListContainersOptions};
use bollard::secret::ContainerInspectResponse;
use bollard::Docker;

const DANGEROUS_PATHS: [&str; 5] = ["/var/run/docker.sock", "/proc", "/sys", "/etc", "/root"];

pub async fn scan_containers() -> Result<()> {
    let docker = Docker::connect_with_socket_defaults()?;
    let containers = docker
        .list_containers(Some(ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        }))
        .await?;
    for container in containers {
        let id = container.id.as_deref().unwrap_or("");
        let inspect: ContainerInspectResponse = docker
            .inspect_container(id, None::<InspectContainerOptions>)
            .await?;
        print_conainer_info(&inspect);
    }
    Ok(())
}

fn print_conainer_info(container: &ContainerInspectResponse) {
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
    let privilaged = container
        .host_config
        .as_ref()
        .and_then(|hc| hc.privileged)
        .unwrap_or(false);
    let is_root = container
        .config
        .as_ref()
        .and_then(|c| c.user.as_ref())
        .map_or(true, |u| u == "0" || u.is_empty());

    println!("Container: {}", name);
    println!("   └─ Image: {}", image);
    println!("   └─ Privileged: {}", privilaged);
    println!("   └─ Root: {}", is_root);
    let mounts_findings = analyze_mounts(container);
    if !mounts_findings.is_empty() {
        println!("   └─ Mounts: ");
        for finding in mounts_findings {
            println!("  {}", finding);
        }
    }
    println!("---------------------------------------");
}

pub fn analyze_mounts(container: &ContainerInspectResponse) -> Vec<String> {
    let mut findings = Vec::new();
    if let Some(mounts) = &container.mounts {
        for mount in mounts {
            let source = mount.source.as_deref().unwrap_or("");
            let destination = mount.destination.as_deref().unwrap_or("");
            let len_findings = findings.len();
            for dangerous in DANGEROUS_PATHS {
                if source.starts_with(dangerous) {
                    findings.push(format!("      ⚠️  {} → {}", source, destination));
                }
            }
            if len_findings == findings.len() {
                findings.push(format!("          {} → {}", source, destination));
            }
        }
    }
    findings
}
