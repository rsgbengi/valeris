use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::*;

#[test]
fn prints_help() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(contains("Usage"));
}

#[test]
fn scan_runs_with_valid_plugin() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--only", "exposed_ports"])
        .assert()
        .success();
}

#[test]
fn scan_fails_with_invalid_plugin() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--only", "invalid_plugin"])
        .assert()
        .failure()
        .stderr(contains("Unknown detector"));
}

#[test]
fn scan_runs_with_defaults() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.arg("scan").assert().success();
}

#[test]
fn scan_runs_with_exclude() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--exclude", "exposed_ports"])
        .assert()
        .success();
}

#[test]
fn scan_fails_with_only_and_exclude_together() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args([
        "scan",
        "--only",
        "exposed_ports",
        "--exclude",
        "readonly_rootfs",
    ])
    .assert()
    .failure()
    .stderr(contains("cannot be used with"));
}

#[test]
fn scan_fails_with_invalid_exclude() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--exclude", "does_not_exist"])
        .assert()
        .failure()
        .stderr(contains("Unknown detector"));
}

#[test]
fn list_plugins_runs() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.arg("list-plugins")
        .assert()
        .success()
        .stdout(contains("Plugins").or(contains("exposed_ports")));
}

#[test]
fn list_plugins_with_target() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["list-plugins", "--target", "docker"])
        .assert()
        .success()
        .stdout(contains("Plugins").or(contains("exposed_ports")));
}

#[test]
fn list_plugins_invalid_target() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["list-plugins", "--target", "banana"])
        .assert()
        .failure()
        .stderr(contains("error").or(contains("Invalid value")));
}

#[test]
fn scan_runs_with_duplicate_plugins_in_only() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--only", "exposed_ports,exposed_ports"])
        .assert()
        .success();
}

#[test]
fn scan_runs_with_state_filter() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--state", "running"]).assert().success();
}

#[test]
fn scan_runs_with_container_filter() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--container", "nginx"])
        .assert()
        .success();
}

#[test]
fn scan_runs_with_multiple_container_filters() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--container", "nginx,redis,postgres"])
        .assert()
        .success();
}

#[test]
fn scan_runs_with_container_short_flag() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "-c", "web-app"]).assert().success();
}

#[test]
fn scan_runs_with_severity_filter() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--severity", "high"]).assert().success();
}

#[test]
fn scan_runs_with_min_severity() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--min-severity", "medium"])
        .assert()
        .success();
}

#[test]
fn scan_runs_with_fail_on() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    // This may fail with exit code 1 if findings exist, which is expected
    cmd.args(["scan", "--fail-on", "high"]).assert();
}

#[test]
fn scan_quiet_mode_requires_fail_on() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--quiet"])
        .assert()
        .failure()
        .stderr(contains("required arguments"));
}

#[test]
fn scan_severity_conflicts_with_min_severity() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--severity", "high", "--min-severity", "medium"])
        .assert()
        .failure()
        .stderr(contains("cannot be used with"));
}
