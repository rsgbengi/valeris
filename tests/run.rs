use valeris::run_with_args;

#[tokio::test]
async fn run_scan_command_works() {
    let args = vec!["valeris", "scan"];
    let result = run_with_args(args).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn run_list_plugins_works() {
    let args = vec!["valeris", "list-plugins"];
    let result = run_with_args(args).await;
    assert!(result.is_ok());
}
