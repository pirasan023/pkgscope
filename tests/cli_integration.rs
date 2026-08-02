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
    assert_eq!(snapshot["schema_version"], 2);
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
fn scans_linux_manager_fixtures_with_explicit_packages_and_separate_flatpak_scopes() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let mock_bin = temp.path().join("mock-bin");
    let cargo_home = temp.path().join("cargo-home");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&mock_bin).unwrap();

    executable(&mock_bin.join("apt-get"), "#!/bin/sh\nexit 0\n");
    executable(
        &mock_bin.join("apt-mark"),
        "#!/bin/sh\n[ \"$1\" = showmanual ] && printf '%s\\n' demo-apt\n",
    );
    executable(
        &mock_bin.join("dpkg-query"),
        "#!/bin/sh\nif [ \"$1\" = --show ]; then printf 'demo-apt\\t1.2-1\\tamd64\\t12\\thttps://apt.example\\tAPT demo\\tii \\tlibc6 (>= 2)\\tca-certificates\\n'; elif [ \"$1\" = --listfiles ]; then printf '/usr/bin/demo-apt\\n'; else exit 2; fi\n",
    );

    executable(
        &mock_bin.join("dnf"),
        "#!/bin/sh\ncase \"$*\" in *repoquery*) printf '%s\\n' demo-dnf ;; *) exit 2 ;; esac\n",
    );
    executable(
        &mock_bin.join("rpm"),
        "#!/bin/sh\nif [ \"$1\" = -qa ]; then printf 'demo-dnf\\t0:2.0-3\\tx86_64\\t2048\\t1700000000\\tDNF demo\\thttps://dnf.example\\n'; elif [ \"$1\" = -ql ]; then printf '/usr/bin/demo-dnf\\n'; else exit 2; fi\n",
    );

    let pacman_root = temp.path().join("pacman-root");
    let pacman_db = pacman_root.join("var/lib/pacman");
    let pacman_package = pacman_db.join("local/demo-pacman-3.0-1");
    fs::create_dir_all(&pacman_package).unwrap();
    fs::write(
        pacman_package.join("desc"),
        "%NAME%\ndemo-pacman\n\n%VERSION%\n3.0-1\n\n%DESC%\nPacman demo\n\n%URL%\nhttps://pacman.example\n\n%ARCH%\nx86_64\n\n%ISIZE%\n3072\n\n%INSTALLDATE%\n1700000000\n\n%DEPENDS%\nglibc>=2\n",
    )
    .unwrap();
    fs::write(
        pacman_package.join("files"),
        "%FILES%\nusr/bin/demo-pacman\n",
    )
    .unwrap();
    executable(
        &pacman_root.join("usr/bin/demo-pacman"),
        "#!/bin/sh\nexit 0\n",
    );
    executable(
        &mock_bin.join("pacman"),
        "#!/bin/sh\n[ \"$1\" = -Qqe ] && printf '%s\\n' demo-pacman\n",
    );
    executable(
        &mock_bin.join("pacman-conf"),
        &format!(
            "#!/bin/sh\nif [ \"$1\" = RootDir ]; then printf '%s\\n' '{}'; elif [ \"$1\" = DBPath ]; then printf '%s\\n' '{}'; else exit 2; fi\n",
            pacman_root.display(),
            pacman_db.display()
        ),
    );

    let snap_mount = temp.path().join("snap-mount");
    let snap_state = temp.path().join("snap-state");
    fs::create_dir_all(snap_mount.join("demo-snap/current/meta")).unwrap();
    fs::write(
        snap_mount.join("demo-snap/current/meta/snap.yaml"),
        "name: demo-snap\nversion: '4.0'\nsummary: Snap demo\ndescription: Local Snap demo\nwebsite: https://snap.example\nbase: core24\narchitectures: [amd64]\napps:\n  demo-snap:\n    command: bin/demo\n",
    )
    .unwrap();
    fs::create_dir_all(snap_mount.join("core24/current/meta")).unwrap();
    fs::write(
        snap_mount.join("core24/current/meta/snap.yaml"),
        "name: core24\ntype: base\n",
    )
    .unwrap();
    executable(&snap_mount.join("bin/demo-snap"), "#!/bin/sh\nexit 0\n");
    fs::create_dir_all(snap_state.join("snaps")).unwrap();
    fs::write(snap_state.join("snaps/demo-snap_10.snap"), b"snap-bytes").unwrap();
    executable(
        &mock_bin.join("snap"),
        "#!/bin/sh\nprintf 'Name Version Rev Tracking Publisher Notes\\ndemo-snap 4.0 10 stable demo -\\ncore24 1 20 latest canonical base\\n'\n",
    );

    let flatpak_root = temp.path().join("flatpak-app");
    fs::create_dir_all(flatpak_root.join("files/share/metainfo")).unwrap();
    fs::write(
        flatpak_root.join("files/share/metainfo/org.demo.App.metainfo.xml"),
        "<component><url type=\"homepage\">https://flatpak.example</url></component>",
    )
    .unwrap();
    executable(
        &mock_bin.join("flatpak"),
        &format!(
            "#!/bin/sh\ncase \"$*\" in\n  'list --app --columns=application,version,arch,installation,origin,ref,size,name,description,runtime') printf 'Application\\tVersion\\tArch\\tInstallation\\tOrigin\\tRef\\tSize\\tName\\tDescription\\tRuntime\\norg.demo.App\\t5.0\\tx86_64\\tuser\\tlocal\\tapp/org.demo.App/x86_64/stable\\t1.5 MB\\tDemo\\tFlatpak demo\\torg.demo.Runtime/x86_64/1\\norg.demo.System\\t6.0\\taarch64\\textra\\tlocal\\tapp/org.demo.System/aarch64/stable\\t2 MB\\tSystem Demo\\tSystem Flatpak demo\\torg.demo.Runtime/aarch64/1\\n' ;;\n  '--user info --show-location app/org.demo.App/x86_64/stable') printf '%s\\n' '{}' ;;\n  '--installation=extra info --show-location app/org.demo.System/aarch64/stable') printf '%s\\n' '{}' ;;\n  *) exit 2 ;;\nesac\n",
            flatpak_root.display(),
            flatpak_root.display()
        ),
    );

    let mut command = pkgscope_command(&home, &mock_bin, &cargo_home);
    let output = command
        .env("SNAP_MOUNT_DIR", &snap_mount)
        .env("SNAPD_STATE_DIR", &snap_state)
        .args([
            "scan",
            "--manager",
            "apt",
            "--manager",
            "dnf",
            "--manager",
            "pacman",
            "--manager",
            "snap",
            "--manager",
            "flatpak",
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
    assert_eq!(snapshot["schema_version"], 2);
    assert_eq!(snapshot["partial"], false);
    let records = snapshot["installations"].as_array().unwrap();
    let names = records
        .iter()
        .map(|record| record["identity"]["name"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "demo-apt",
            "demo-dnf",
            "demo-pacman",
            "demo-snap",
            "org.demo.App",
            "org.demo.System"
        ])
    );
    assert!(!names.contains("core24"));
    let snap = records
        .iter()
        .find(|record| record["identity"]["name"] == "demo-snap")
        .unwrap();
    assert_eq!(snap["metadata"]["dependencies"], json!(["core24"]));
    let flatpak_scopes = records
        .iter()
        .filter(|record| record["identity"]["ecosystem"] == "flatpak")
        .map(|record| record["environment"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(flatpak_scopes, BTreeSet::from(["system:extra", "user"]));
    let apt = records
        .iter()
        .find(|record| record["identity"]["name"] == "demo-apt")
        .unwrap();
    assert_eq!(apt["intent"], "explicit");
    assert_eq!(apt["metadata"]["homepage"], "https://apt.example");
    assert_eq!(apt["metadata"]["description"], "APT demo");
    assert_eq!(apt["sizes"]["owned_apparent_bytes"], 12 * 1024);
    assert_eq!(
        apt["metadata"]["dependencies"],
        json!(["libc6", "ca-certificates"])
    );
    let dnf = records
        .iter()
        .find(|record| record["identity"]["name"] == "demo-dnf")
        .unwrap();
    assert_eq!(dnf["metadata"]["description"], "DNF demo");
    assert_eq!(dnf["sizes"]["owned_apparent_bytes"], 2048);
    let pacman = records
        .iter()
        .find(|record| record["identity"]["name"] == "demo-pacman")
        .unwrap();
    assert_eq!(pacman["metadata"]["description"], "Pacman demo");
    assert_eq!(pacman["metadata"]["dependencies"], json!(["glibc"]));
    assert_eq!(pacman["command_ids"].as_array().unwrap().len(), 1);
    assert_eq!(snap["metadata"]["description"], "Local Snap demo");
    assert!(snap["sizes"]["owned_apparent_bytes"].as_u64().unwrap() > 0);
    let user_flatpak = records
        .iter()
        .find(|record| record["identity"]["name"] == "org.demo.App")
        .unwrap();
    assert_eq!(user_flatpak["metadata"]["description"], "Flatpak demo");
    assert_eq!(
        user_flatpak["metadata"]["runtime"],
        "org.demo.Runtime/x86_64/1"
    );
    assert_eq!(user_flatpak["metadata"]["delete_user_data"], false);

    let mut plan = pkgscope_command(&home, &mock_bin, &cargo_home);
    plan.env("SNAP_MOUNT_DIR", &snap_mount)
        .env("SNAPD_STATE_DIR", &snap_state)
        .args(["removal-plan", "demo-snap", "--manager", "snap", "--quiet"])
        .assert()
        .success()
        .stdout(predicates::str::contains("snap remove demo-snap"))
        .stdout(predicates::str::contains("--purge is never used"));
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
fn missing_manager_is_a_successful_unused_environment() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let empty_path = temp.path().join("empty-path");
    let cargo_home = temp.path().join("cargo-home");
    fs::create_dir_all(&empty_path).unwrap();
    let mut command = pkgscope_command(&home, &empty_path, &cargo_home);
    let output = command
        .args([
            "scan",
            "--manager",
            "flatpak",
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(snapshot["partial"], false);
    assert_eq!(snapshot["manager_instances"], json!([]));
    assert_eq!(snapshot["installations"], json!([]));
}

#[test]
fn all_managers_bound_and_sanitize_malformed_future_output_without_panicking() {
    for (manager, executable_name) in [
        ("brew", "brew"),
        ("npm", "npm"),
        ("pnpm", "pnpm"),
        ("pipx", "pipx"),
        ("uv", "uv"),
        ("cargo", "cargo"),
        ("apt", "apt-get"),
        ("dnf", "dnf"),
        ("pacman", "pacman"),
        ("snap", "snap"),
        ("flatpak", "flatpak"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let mock_bin = temp.path().join("mock-bin");
        let cargo_home = temp.path().join("cargo-home");
        fs::create_dir_all(&mock_bin).unwrap();
        executable(
            &mock_bin.join(executable_name),
            "#!/bin/sh\nprintf 'future-field\\tbroken\\033[2Jvalue\\n'\n",
        );
        let mut command = pkgscope_command(&home, &mock_bin, &cargo_home);
        let output = command
            .args(["scan", "--manager", manager, "--format", "json", "--quiet"])
            .output()
            .unwrap();
        assert!(
            matches!(output.status.code(), Some(0 | 3)),
            "{manager} exited unexpectedly: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.len() < 16 * 1024 * 1024);
        let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(snapshot["schema_version"], 2, "manager {manager}");
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("\u{1b}"),
            "manager {manager} leaked terminal controls"
        );
    }
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
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
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
