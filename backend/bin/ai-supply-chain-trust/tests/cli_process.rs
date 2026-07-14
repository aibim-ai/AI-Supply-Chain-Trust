use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ai-supply-chain-trust"))
}

#[test]
fn help_and_openapi_commands_are_executable() {
    let help = binary().arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("Free repository trust"));
    assert!(help.contains("serve"));
    assert!(help.contains("security-context"));

    let openapi = binary().arg("openapi").output().unwrap();
    assert!(openapi.status.success());
    let schema: serde_json::Value = serde_json::from_slice(&openapi.stdout).unwrap();
    assert_eq!(schema["openapi"], "3.1.0");
    assert!(schema["paths"].get("/api/v1/scan").is_some());
}

#[test]
fn database_stats_command_uses_the_requested_persistent_path() {
    let db_path = std::env::temp_dir().join(format!(
        "ai-supply-chain-trust-cli-{}.db",
        std::process::id()
    ));
    let output = binary()
        .args(["--db-path", db_path.to_str().unwrap(), "db", "stats"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metrics: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(metrics["scans_total"], 0);
    assert_eq!(metrics["unique_repos"], 0);
    assert!(db_path.exists());

    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
}
