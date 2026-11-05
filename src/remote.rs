// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, anyhow, bail};
use std::{
    io::{Read, Write},
    time::Duration,
};

/// Download buffer size; the body is copied and bounded one chunk at a time.
const COPY_CHUNK_SIZE: usize = 1 << 20;

// Do not include ureq's arbitrary error strings: some variants contain the URI,
// which can carry signed query parameters or credentials.
fn request_error(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::StatusCode(status) => {
            anyhow!("HTTP download failed: server returned status {status}")
        }
        ureq::Error::Timeout(_) => anyhow!("HTTP download timed out"),
        ureq::Error::HostNotFound => anyhow!("HTTP download failed: host not found"),
        ureq::Error::TooManyRedirects => anyhow!("HTTP download failed: too many redirects"),
        ureq::Error::RequireHttpsOnly(_) => anyhow!("HTTP download refused an insecure redirect"),
        ureq::Error::BadUri(_) | ureq::Error::Http(_) => {
            anyhow!("HTTP download failed: invalid URL or request")
        }
        _ => anyhow!("HTTP download failed: network or protocol error"),
    }
}

/// Streams the response body into a temporary file, aborting once it would
/// exceed `max_bytes`.
///
/// The URL is never part of an error: query parameters can carry credentials.
pub fn download(url: &str, max_bytes: u64) -> Result<tempfile::TempPath> {
    let https = url.starts_with("https://");
    anyhow::ensure!(
        https || url.starts_with("http://"),
        "URL must use HTTP or HTTPS"
    );
    // Per-read deadlines allow arbitrarily large, steadily progressing downloads.
    // HTTPS-only applies to redirects as well and prevents transport downgrade.
    let config = ureq::Agent::config_builder()
        .https_only(https)
        .timeout_resolve(Some(Duration::from_secs(15)))
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_per_read(Some(Duration::from_secs(60)))
        .timeout_per_write(Some(Duration::from_secs(30)))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent.get(url).call().map_err(request_error)?;
    if response.status().as_u16() != 200 {
        bail!(
            "HTTP download failed: unexpected status {}",
            response.status().as_u16()
        );
    }
    let mut file = tempfile::NamedTempFile::new().context("cannot create temporary file")?;
    let mut body = response.body_mut().as_reader();
    // Bounded copy in fixed chunks: never trust Content-Length, and stop as
    // soon as one more chunk would exceed the limit.
    let mut copied: u64 = 0;
    let mut chunk = [0u8; COPY_CHUNK_SIZE];
    loop {
        let read = body.read(&mut chunk).map_err(|_| {
            anyhow!("HTTP download failed while reading body or writing temporary file")
        })?;
        if read == 0 {
            break;
        }
        if copied.saturating_add(read as u64) > max_bytes {
            bail!("download exceeded the maximum allowed size");
        }
        file.write_all(&chunk[..read]).map_err(|_| {
            anyhow!("HTTP download failed while reading body or writing temporary file")
        })?;
        copied += read as u64;
    }
    file.flush().context("cannot flush temporary download")?;
    Ok(file.into_temp_path())
}
