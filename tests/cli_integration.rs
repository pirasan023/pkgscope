#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

use assert_cmd::Command;
use serde_json::json;

#[test]
fn scans_five_manager_fixtures_and_emits_clean_json_and_plans() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let mock_bin = temp.path().join("mock-bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&mock_bin).unwrap();

    let npm_root = temp.path().join("npm-root");
    let npm_prefix = temp.path().join("npm-prefix");
    let npm_package = npm_root.join("demo-npm");
    create_node_package(&npm_package, "demo-npm", "demo-npm");
    executable(&npm_prefix.join("bin/demo-npm"), "#!/bin/sh\nexit 0\n");
    let npm_listing = json!({
        "dependencies": {
            "demo-npm": {"version": "1.2.3", "path": npm_package}
        }
    });
    executable(
        &mock_bin.join("npm"),
        &format!(
            "#!/bin/sh\ncase \"$*\" in\n  'prefix -g') printf '%s\\n' '{}' ;;\n  'root -g') printf '%s\\n' '{}' ;;\n  'ls -g --depth=0 --json --long') printf '%s\\n' '{}' ;;\n  *) exit 2 ;;\nesac\n",
            npm_prefix.display(),
            npm_root.display(),
            npm_listing
        ),
    );

    let pnpm_root = temp.path().join("pnpm-root");
    let pnpm_bin = temp.path().join("pnpm-bin");
    let pnpm_store = temp.path().join("pnpm-store");
    let pnpm_package = pnpm_root.join("demo-pnpm");
    create_node_package(&pnpm_package, "demo-pnpm", "demo-pnpm");
    executable(&pnpm_bin.join("demo-pnpm"), "#!/bin/sh\nexit 0\n");
    let pnpm_listing = json!([{
        "dependencies": {
            "demo-pnpm": {"version": "2.0.0", "path": pnpm_package}
        }
    }]);
    executable(
        &mock_bin.join("pnpm"),
        &format!(
            "#!/bin/sh\ncase \"$*\" in\n  'root -g') printf '%s\\n' '{}' ;;\n  'bin -g') printf '%s\\n' '{}' ;;\n  'store path') printf '%s\\n' '{}' ;;\n  'list -g --depth=0 --json') printf '%s\\n' '{}' ;;\n  *) exit 2 ;;\nesac\n",
            pnpm_root.display(),
            pnpm_bin.display(),
            pnpm_store.display(),
            pnpm_listing
        ),
    );

    let pipx_home = temp.path().join("pipx-home");
    let pipx_bin = temp.path().join("pipx-bin");
    let pipx_venv = pipx_home.join("venvs/demo-pipx");
    executable(&pipx_venv.join("bin/python"), "#!/bin/sh\nexit 0\n");
    executable(&pipx_bin.join("demo-pipx"), "#!/bin/sh\nexit 0\n");
    let pipx_listing = json!({
        "pipx_spec_version": "0.1",
        "venvs": {
            "demo-pipx": {"metadata": {"main_package": {
                "package": "demo-pipx", "package_version": "3.1.4", "apps": ["demo-pipx"]
            }, "injected_packages": {}}}
        }
    });
    executable(
        &mock_bin.join("pipx"),
        &format!(
            "#!/bin/sh\nif [ \"$*\" = 'list --json' ]; then printf '%s\\n' '{}'; elif [ \"$*\" = 'environment --value PIPX_HOME' ]; then printf '%s\\n' '{}'; elif [ \"$*\" = 'environment --value PIPX_BIN_DIR' ]; then printf '%s\\n' '{}'; else exit 2; fi\n",
            pipx_listing,
            pipx_home.display(),
            pipx_bin.display()
        ),
    );

    let uv_tools = temp.path().join("uv-tools");
    let uv_bin = temp.path().join("uv-bin");
    let uv_env = uv_tools.join("demo-uv");
    let metadata = uv_env.join("lib/python3.12/site-packages/demo_uv-4.0.0.dist-info/METADATA");
    fs::create_dir_all(metadata.parent().unwrap()).unwrap();
    fs::write(
        &metadata,
        "Metadata-Version: 2.3\nName: demo-uv\nVersion: 4.0.0\nSummary: A demonstration uv tool\nHome-page: https://example.test/demo-uv\n",
    )
    .unwrap();
    executable(&uv_env.join("bin/demo-uv"), "#!/bin/sh\nexit 0\n");
    fs::create_dir_all(&uv_bin).unwrap();
    symlink(uv_env.join("bin/demo-uv"), uv_bin.join("demo-uv")).unwrap();
    executable(
        &mock_bin.join("uv"),
        &format!(
            "#!/bin/sh\nif [ \"$*\" = 'tool dir' ]; then printf '%s\\n' '{}'; elif [ \"$*\" = 'tool dir --bin' ]; then printf '%s\\n' '{}'; else exit 2; fi\n",
            uv_tools.display(),
            uv_bin.display()
        ),
    );

    let cargo_home = temp.path().join("cargo-home");
    executable(&mock_bin.join("cargo"), "#!/bin/sh\nexit 0\n");
    executable(&cargo_home.join("bin/demo-cargo"), "#!/bin/sh\nexit 0\n");
    fs::write(
        cargo_home.join(".crates2.json"),
        serde_json::to_vec(&json!({"installs": {
            "demo-cargo 5.0.0 (registry+https://github.com/rust-lang/crates.io-index)": {
                "bins": ["demo-cargo"], "features": ["default"], "profile": "release"
            }
        }}))
        .unwrap(),
    )
    .unwrap();

    let mut command = pkgscope_command(&home, &mock_bin, &cargo_home);
    let output = command
        .args([
            "scan",
            "--manager",
            "npm",
            "--manager",
            "pnpm",
            "--manager",
            "pipx",
            "--manager",
            "uv",
            "--manager",
            "cargo",
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(snapshot["schema_version"], 1);
    assert_eq!(snapshot["partial"], false);
    let names: BTreeSet<_> = snapshot["installations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["identity"]["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "demo-cargo",
            "demo-npm",
            "demo-pipx",
            "demo-pnpm",
            "demo-uv"
        ])
    );
    let installations = snapshot["installations"].as_array().unwrap();
    let npm = installations
        .iter()
        .find(|record| record["identity"]["name"] == "demo-npm")
        .unwrap();
    assert_eq!(npm["metadata"]["description"], "A demonstration Node tool");
    assert_eq!(
        npm["metadata"]["description_source"],
        "installed_package_json"
    );
    assert_eq!(npm["metadata"]["homepage"], "https://example.test/node");
    let uv = installations
        .iter()
        .find(|record| record["identity"]["name"] == "demo-uv")
        .unwrap();
    assert_eq!(uv["metadata"]["description"], "A demonstration uv tool");
    assert_eq!(
        uv["metadata"]["description_source"],
        "installed_dist_info_metadata"
    );
    assert!(
        output.stderr.is_empty(),
        "JSON diagnostics leaked despite --quiet"
    );

    let mut plan = pkgscope_command(&home, &mock_bin, &cargo_home);
    plan.args(["removal-plan", "demo-npm", "--quiet"])
        .assert()
        .success()
        .stdout(predicates::str::contains("npm uninstall -g demo-npm"))
        .stdout(predicates::str::contains("nothing will be executed"));

    let mut missing = pkgscope_command(&home, &mock_bin, &cargo_home);
    missing
        .args(["inspect", "not-installed", "--quiet"])
        .assert()
        .code(4)
        .stderr(predicates::str::contains("no installation matches"));
}

#[test]
fn manager_failure_is_partial_json_with_exit_code_three() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let mock_bin = temp.path().join("mock-bin");
    let cargo_home = temp.path().join("cargo-home");
    fs::create_dir_all(&home).unwrap();
    executable(
        &mock_bin.join("pnpm"),
        "#!/bin/sh\nprintf '%s\\n' 'fixture manager failed' >&2\nexit 9\n",
    );
    let mut command = pkgscope_command(&home, &mock_bin, &cargo_home);
    let output = command
        .args(["scan", "--manager", "pnpm", "--format", "json", "--quiet"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(snapshot["partial"], true);
    assert_eq!(snapshot["errors"][0]["manager"], "pnpm");
    assert_eq!(snapshot["manager_instances"][0]["scan_status"], "failed");
}

#[test]
fn unsafe_privacy_config_is_rejected_with_configuration_exit_code() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let mock_bin = temp.path().join("mock-bin");
    let cargo_home = temp.path().join("cargo-home");
    let config = home.join(".config/pkgscope/config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "[privacy]\nstore_raw_history = true\n").unwrap();
    let mut command = pkgscope_command(&home, &mock_bin, &cargo_home);
    command
        .arg("doctor")
        .assert()
        .code(2)
        .stderr(predicates::str::contains("configuration error"));
}

use std::collections::BTreeSet;

fn pkgscope_command(home: &Path, mock_bin: &Path, cargo_home: &Path) -> Command {
    let mut command = Command::cargo_bin("pkgscope").unwrap();
    command
        .env("HOME", home)
        .env("PATH", mock_bin)
        .env("CARGO_HOME", cargo_home)
        .env_remove("CARGO_INSTALL_ROOT")
        .env_remove("PIPX_HOME")
        .env_remove("PIPX_BIN_DIR")
        .env_remove("UV_TOOL_DIR")
        .env_remove("UV_TOOL_BIN_DIR");
    command
}

fn create_node_package(path: &Path, name: &str, bin: &str) {
    fs::create_dir_all(path).unwrap();
    fs::write(
        path.join("package.json"),
        serde_json::to_vec(&json!({
            "name": name,
            "description": "A demonstration Node tool",
            "homepage": "https://example.test/node",
            "license": "MIT",
            "bin": {bin: "cli.js"}
        }))
        .unwrap(),
    )
    .unwrap();
}

fn executable(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}
