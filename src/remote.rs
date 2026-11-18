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

/// Validates the URL scheme and normalizes it to lowercase.
///
/// RFC 3986 schemes are case-insensitive, so `HTTPS://` and `Http://` are
/// accepted like their lowercase forms; only the scheme segment is rewritten,
/// leaving the authority, path, and query (which can carry credentials)
/// untouched. Anything but HTTP/HTTPS is rejected.
fn normalized_url(url: &str) -> Result<String> {
    // A scheme cannot itself contain `://`, so the first occurrence delimits it.
    match url.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => {
            Ok(format!("https://{rest}"))
        }
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => Ok(format!("http://{rest}")),
        _ => bail!("URL must use HTTP or HTTPS"),
    }
}

/// Streams the response body into a temporary file, aborting once it would
/// exceed `max_bytes`.
///
/// The URL is never part of an error: query parameters can carry credentials.
pub fn download(url: &str, max_bytes: u64) -> Result<tempfile::TempPath> {
    let url = normalized_url(url)?;
    let https = url.starts_with("https://");
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
    let mut response = agent.get(&url).call().map_err(request_error)?;
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
    // Heap-allocate the chunk: a 1 MiB stack array overflows the default
    // 1 MiB main-thread stack on Windows (MSVC PE header) as soon as the
    // download path runs.
    let mut chunk = vec![0u8; COPY_CHUNK_SIZE];
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

#[cfg(test)]
mod tests {
    use super::normalized_url;

    #[test]
    fn schemes_match_case_insensitively_and_are_normalized() {
        assert_eq!(
            normalized_url("https://example.com/a").unwrap(),
            "https://example.com/a"
        );
        assert_eq!(
            normalized_url("HTTPS://example.com/a").unwrap(),
            "https://example.com/a"
        );
        assert_eq!(
            normalized_url("Http://example.com").unwrap(),
            "http://example.com"
        );
        // The first `://` delimits the scheme; everything after it —
        // authority, path, and query — is passed through untouched.
        assert_eq!(
            normalized_url("https://user@example.com/x?u=https://other").unwrap(),
            "https://user@example.com/x?u=https://other"
        );
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        for url in ["ftp://example.com", "example.com", "", "https:/one-slash"] {
            let error = normalized_url(url).unwrap_err().to_string();
            assert!(error.contains("HTTP or HTTPS"), "{url}: {error}");
        }
    }
}
