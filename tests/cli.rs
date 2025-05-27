use assert_cmd::Command;
use predicates::str::*;
use predicates::prelude::*;

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
        .stderr(contains("Unknown plugin"));
}

#[test]
fn scan_runs_with_defaults() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.arg("scan")
        .assert()
        .success();
}

#[test]
fn scan_runs_with_exclude() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--exclude", "exposed_ports"])
        .assert()
        .success();
}

#[test]
fn scan_runs_with_only_and_exclude() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--only", "exposed_ports", "--exclude", "readonly_rootfs"])
        .assert()
        .success();
}

#[test]
fn scan_fails_with_invalid_exclude() {
    let mut cmd = Command::cargo_bin("valeris").unwrap();
    cmd.args(["scan", "--exclude", "does_not_exist"])
        .assert()
        .failure()
        .stderr(contains("Unknown plugin"));
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
