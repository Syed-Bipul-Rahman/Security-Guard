//! HTTP for the updater and the advisory feed (rustls, bundled roots).

use std::time::Duration;

/// Largest body we read (a release binary is the biggest thing fetched).
const MAX_BODY: u64 = 512 * 1024 * 1024;

/// `http://` to this machine (tests, local collectors).
pub fn is_loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = if host.starts_with('[') {
        host.split(']').next().map(|h| &h[1..]).unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Client {
    agent: ureq::Agent,
}

impl Client {
    /// `https_only`: refuse plain http (except to loopback) and http redirects.
    pub fn new(
        url: &str,
        user_agent: &str,
        timeout: Duration,
        https_only: bool,
        status_errors: bool,
    ) -> Result<Self, String> {
        let loopback = is_loopback_http(url);
        if https_only && !url.starts_with("https://") && !loopback {
            return Err(format!("refusing non-HTTPS URL {url}"));
        }
        let mut cfg = ureq::Agent::config_builder()
            .user_agent(user_agent)
            .timeout_connect(Some(timeout.min(Duration::from_secs(30))))
            .timeout_recv_response(Some(timeout.min(Duration::from_secs(30))))
            .timeout_global(Some(timeout))
            .http_status_as_error(status_errors)
            .https_only(https_only && !loopback);
        if loopback {
            cfg = cfg.proxy(None); // a local fetch never goes through a proxy
        }
        Ok(Client {
            agent: cfg.build().into(),
        })
    }

    fn finish(
        resp: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<Response, String> {
        let mut resp = resp.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|e| e.to_string())?;
        Ok(Response {
            status,
            headers,
            body,
        })
    }

    pub fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Response, String> {
        let mut req = self.agent.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        Self::finish(req.call())
    }
}

/// GET a body, any non-2xx being an error.
pub fn fetch(
    url: &str,
    user_agent: &str,
    timeout: Duration,
    https_only: bool,
) -> Result<Vec<u8>, String> {
    Ok(Client::new(url, user_agent, timeout, https_only, true)?
        .get(url, &[])?
        .body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_http_only() {
        assert!(is_loopback_http("http://127.0.0.1:8000/x"));
        assert!(is_loopback_http("http://localhost/x"));
        assert!(is_loopback_http("http://[::1]:9/x"));
        assert!(!is_loopback_http("http://example.com/x"));
        assert!(!is_loopback_http("http://127.0.0.1.evil.com/x"));
        assert!(!is_loopback_http("https://127.0.0.1/x"));
        let e = fetch("http://example.com/m", "t", Duration::from_secs(1), true).unwrap_err();
        assert!(e.contains("non-HTTPS"));
    }
}
