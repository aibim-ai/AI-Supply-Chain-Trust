use std::process::Command;

#[test]
fn verification_harness_exposes_reproducible_cli_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_verification-harness"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("Security Context verification harness"));
    assert!(help.contains("--db-path"));
    assert!(help.contains("--token"));
}
