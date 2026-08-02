#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    thread,
    time::{Duration, Instant},
};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

#[test]
fn tui_keyboard_flow_and_disposable_uninstall_work_in_a_pseudo_terminal() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let mock_bin = temp.path().join("mock-bin");
    let cargo_home = temp.path().join("cargo-home");
    let marker = temp.path().join("uninstalled.args");
    fs::create_dir_all(&home).unwrap();
    executable(&cargo_home.join("bin/demo-cargo"), "#!/bin/sh\nexit 0\n");
    fs::write(
        cargo_home.join(".crates2.json"),
        r#"{"installs":{"another-cargo 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)":{"bins":["another-cargo"]},"demo-cargo 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)":{"bins":["demo-cargo"]}}}"#,
    )
    .unwrap();
    executable(&cargo_home.join("bin/another-cargo"), "#!/bin/sh\nexit 0\n");
    executable(
        &mock_bin.join("cargo"),
        &format!(
            "#!/bin/sh\nif [ \"$1\" = uninstall ]; then printf '%s\\n' \"$@\" > '{}'; printf '%s\\n' '{{\"installs\":{{\"another-cargo 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)\":{{\"bins\":[\"another-cargo\"]}}}}}}' > \"$CARGO_INSTALL_ROOT/.crates2.json\"; /bin/rm -f \"$CARGO_INSTALL_ROOT/bin/demo-cargo\"; fi\n",
            marker.display()
        ),
    );

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 40,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let binary = std::env::var_os("PKGSCOPE_TEST_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| assert_cmd::cargo::cargo_bin!("pkgscope").to_path_buf());
    let mut command = CommandBuilder::new(binary);
    command.arg("tui");
    command.args(["--manager", "cargo", "--quiet"]);
    command.env("HOME", &home);
    command.env("XDG_CONFIG_HOME", home.join(".config"));
    command.env("XDG_DATA_HOME", home.join(".local/share"));
    command.env("PATH", &mock_bin);
    command.env("CARGO_HOME", &cargo_home);
    command.env("TERM", "xterm-256color");
    command.env("NO_COLOR", "1");
    let mut child = pair.slave.spawn_command(command).unwrap();
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let reader_thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let mut writer = pair.master.take_writer().unwrap();

    thread::sleep(Duration::from_millis(1_500));
    // Change sort column/order, search, open details, and scroll.
    writer
        .write_all(b"\x1b[B\x1b[A\x1b[Css/demo-cargo\r")
        .unwrap();
    thread::sleep(Duration::from_millis(250));
    writer.write_all(b"\r\x1b[6~uwrong\r").unwrap();
    thread::sleep(Duration::from_millis(250));
    // Cancel after an incorrect typed confirmation, then confirm exactly.
    writer.write_all(b"\x1b").unwrap();
    thread::sleep(Duration::from_millis(250));
    writer.write_all(b"udemo-cargo\r").unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    while !marker.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    if !marker.exists() {
        writer.write_all(b"\x03").unwrap();
        drop(writer);
        let _ = child.wait();
        let output = String::from_utf8_lossy(&reader_thread.join().unwrap()).into_owned();
        panic!("the TUI did not execute the disposable uninstall; output: {output}");
    }
    // Crossterm asks the terminal emulator for the cursor position after
    // returning from the temporarily suspended uninstall screen.
    writer.write_all(b"\x1b[1;1R").unwrap();
    thread::sleep(Duration::from_millis(200));
    writer.write_all(b"\x1b[1;1R").unwrap();
    thread::sleep(Duration::from_millis(300));
    writer.write_all(b"q").unwrap();
    drop(writer);
    let status = child.wait().unwrap();
    let output = String::from_utf8_lossy(&reader_thread.join().unwrap()).into_owned();
    assert!(status.success(), "TUI output: {output}");
    assert!(output.contains("ASCENDING"), "TUI output: {output}");
    assert!(output.contains("DESCENDING"), "TUI output: {output}");
    assert_eq!(
        fs::read_to_string(&marker).unwrap(),
        "uninstall\ndemo-cargo\n"
    );
    assert_eq!(
        fs::read_to_string(cargo_home.join(".crates2.json")).unwrap(),
        "{\"installs\":{\"another-cargo 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)\":{\"bins\":[\"another-cargo\"]}}}\n"
    );
}

fn executable(path: &std::path::Path, contents: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}
