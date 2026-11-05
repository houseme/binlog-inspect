// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

use std::{fs, process::Command};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
}

#[test]
fn output_is_created_and_existing_input_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("result");
    fs::write(&input, b"\xfebin").unwrap();
    let result = command()
        .args([input.as_os_str(), "--output".as_ref(), output.as_os_str()])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(fs::read(&output).unwrap(), b"");
    let result = command()
        .args([input.as_os_str(), "--output".as_ref(), input.as_os_str()])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(&input).unwrap(), b"\xfebin");
    let link = dir.path().join("hardlink");
    fs::hard_link(&input, &link).unwrap();
    let result = command()
        .args([input.as_os_str(), "--output".as_ref(), link.as_os_str()])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(&input).unwrap(), b"\xfebin");
    let result = command()
        .args([input.as_os_str(), "--output".as_ref(), output.as_os_str()])
        .output()
        .unwrap();
    assert!(!result.status.success());
}

#[cfg(feature = "remote")]
fn serve_once(response: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
    use std::{
        io::Write,
        net::TcpListener,
        time::{Duration, Instant},
    };
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    server.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            match server.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    drain_request(&mut stream);
                    let _ = stream.write_all(response);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("test server accept failed: {e}"),
            }
        }
    });
    (
        format!("http://{addr}/file?token=secret-test-value"),
        handle,
    )
}

#[cfg(feature = "remote")]
fn serve_bytes(body: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
    use std::{
        io::Write,
        net::TcpListener,
        time::{Duration, Instant},
    };
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    server.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            match server.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    drain_request(&mut stream);
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    );
                    let _ = stream.write_all(body);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("test server accept failed: {e}"),
            }
        }
    });
    (
        format!("http://{addr}/file?token=secret-test-value"),
        handle,
    )
}

/// Reads until the end of the request headers before responding.
///
/// A single `read` may return early and leave request bytes unread; closing
/// the socket with unread data sends an RST that can clobber the client's
/// in-flight body read (a real macOS loopback flake), so drain the GET
/// request first — it has no body, so the header terminator is the end.
#[cfg(feature = "remote")]
fn drain_request(stream: &mut std::net::TcpStream) {
    use std::io::Read;
    let mut received = Vec::new();
    let mut chunk = [0; 2048];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                received.extend_from_slice(&chunk[..n]);
                if received.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(feature = "remote")]
#[test]
fn remote_rejects_partial_or_interrupted_responses_without_leaking_url() {
    for response in [
        b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\xfebin"
            .as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n\xfebin".as_slice(),
    ] {
        let (url, server) = serve_once(response);
        let out = command().args(["--url", &url]).output().unwrap();
        server.join().unwrap();
        assert!(!out.status.success());
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(!error.contains("secret-test-value"), "URL leaked in error");
    }
}

#[cfg(feature = "remote")]
#[test]
fn remote_download_size_limit_aborts_oversized_bodies() {
    let body: &'static [u8] = Box::leak(vec![0xa5u8; 64].into_boxed_slice());
    let (url, server) = serve_bytes(body);
    // The server sends 64 bytes; a 32-byte cap must abort the download.
    let out = command()
        .args(["--url", &url, "--max-download-size", "32"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!out.status.success());
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(
        error.contains("exceeded the maximum allowed size"),
        "{error}"
    );
    assert!(!error.contains("secret-test-value"), "URL leaked in error");

    // Exactly at the cap is accepted (the limit is "would exceed").
    let (url, server) = serve_bytes(body);
    let out = command()
        .args(["--url", &url, "--max-download-size", "64"])
        .output()
        .unwrap();
    server.join().unwrap();
    // The garbage body downloads fine but has no binlog magic: hard error
    // (exit 1), and crucially not the size-limit error.
    assert_eq!(out.status.code(), Some(1));
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(
        !error.contains("exceeded the maximum allowed size"),
        "{error}"
    );
}

#[cfg(feature = "remote")]
#[test]
fn remote_download_within_limit_is_parsed() {
    fn xid_event(xid: u64) -> Vec<u8> {
        let size = 19u32 + 8;
        let mut event = Vec::new();
        event.extend(1u32.to_le_bytes());
        event.push(16);
        event.extend(7u32.to_le_bytes());
        event.extend(size.to_le_bytes());
        event.extend((4 + size).to_le_bytes());
        event.extend(0u16.to_le_bytes());
        event.extend(xid.to_le_bytes());
        event
    }
    let body: &'static [u8] = Box::leak({
        let mut bytes = b"\xfebin".to_vec();
        bytes.extend(xid_event(55));
        bytes.into_boxed_slice()
    });
    let (url, server) = serve_bytes(body);
    let out = command()
        .args(["--url", &url, "--max-download-size", "1048576"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["payload"]["xid"], 55);
}

#[cfg(feature = "remote")]
#[test]
fn malformed_url_does_not_leak_credentials() {
    let out = command()
        .args(["--url", "http://bad host/?token=secret-test-value"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("secret-test-value"));
}
