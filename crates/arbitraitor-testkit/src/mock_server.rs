//! Local adversarial HTTP server helpers for integration tests.

use std::sync::atomic::{AtomicUsize, Ordering};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Local deterministic HTTP server with common adversarial routes.
pub struct MockHttpServer {
    server: MockServer,
    next_route: AtomicUsize,
}

impl MockHttpServer {
    /// Starts a new local mock HTTP server.
    pub async fn start() -> Self {
        Self {
            server: MockServer::start().await,
            next_route: AtomicUsize::new(0),
        }
    }

    /// Returns the server base URL.
    #[must_use]
    pub fn url(&self) -> String {
        self.server.uri()
    }

    /// Configures a chain of `count` HTTP redirects and returns the first URL.
    pub async fn redirect_chain(&self, count: usize) -> String {
        let prefix = self.unique_prefix("redirect-chain");
        let terminal = format!("/{prefix}/terminal");

        Mock::given(method("GET"))
            .and(path(terminal.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("redirect complete"))
            .mount(&self.server)
            .await;

        for index in (0..count).rev() {
            let current = format!("/{prefix}/{index}");
            let next = if index + 1 == count {
                terminal.clone()
            } else {
                format!("/{prefix}/{}", index + 1)
            };
            let location = self.absolute_url(&next);

            Mock::given(method("GET"))
                .and(path(current.as_str()))
                .respond_with(ResponseTemplate::new(302).insert_header("Location", location))
                .mount(&self.server)
                .await;
        }

        if count == 0 {
            self.absolute_url(&terminal)
        } else {
            self.absolute_url(&format!("/{prefix}/0"))
        }
    }

    /// Configures an HTTP redirect chain.
    ///
    /// NOTE: `WireMock` serves HTTP only. This tests redirect handling logic, NOT TLS downgrade
    /// detection. TLS downgrade tests require a real HTTPS server.
    ///
    /// TODO(#324): real HTTPS downgrade testing requires a custom HTTPS server.
    pub async fn http_redirect_chain(&self) -> String {
        let route_path = self.unique_path("http-redirect-chain");
        let target = self.absolute_url("/downgraded-target");
        Mock::given(method("GET"))
            .and(path(route_path.as_str()))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", target))
            .mount(&self.server)
            .await;
        self.absolute_url(&route_path)
    }

    /// Configures a redirect to a different origin.
    pub async fn cross_origin_redirect(&self) -> String {
        let route_path = self.unique_path("cross-origin-redirect");
        Mock::given(method("GET"))
            .and(path(route_path.as_str()))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "http://example.invalid/payload"),
            )
            .mount(&self.server)
            .await;
        self.absolute_url(&route_path)
    }

    /// Configures a response carrying metadata that identifies a private peer address.
    ///
    /// This provides metadata for header-based private-address detection tests only. `WireMock`
    /// still accepts the TCP connection on the mock server address; it does not bind to a private
    /// IP and does not exercise real SSRF network controls.
    ///
    /// TODO(#324): real SSRF network tests require a custom TCP server.
    pub async fn private_ip_metadata_headers(&self) -> String {
        let route_path = self.unique_path("private-ip-metadata-headers");
        Mock::given(method("GET"))
            .and(path(route_path.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Arbitraitor-Test-Peer-IP", "10.0.0.7")
                    .set_body_string("private-address response"),
            )
            .mount(&self.server)
            .await;
        self.absolute_url(&route_path)
    }

    /// Configures a route whose body differs from the caller's expected bytes.
    pub async fn content_mismatch(&self, expected: &str, actual: &str) -> String {
        let route_path = self.unique_path("content-mismatch");
        Mock::given(method("GET"))
            .and(path(route_path.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Arbitraitor-Expected-Content", expected)
                    .set_body_string(actual),
            )
            .mount(&self.server)
            .await;
        self.absolute_url(&route_path)
    }

    /// Configures a response body with intentionally short content.
    ///
    /// `WireMock` and Hyper reject mismatched `Content-Length` responses, so this tests small-body
    /// handling rather than TCP-level truncation.
    ///
    /// TODO(#324): raw TCP-level truncation tests require a custom TCP server.
    pub async fn short_content_response(&self) -> String {
        let route_path = self.unique_path("short-content-response");
        Mock::given(method("GET"))
            .and(path(route_path.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Arbitraitor-Short-Content", "true")
                    .set_body_bytes(b"partial".to_vec()),
            )
            .mount(&self.server)
            .await;
        self.absolute_url(&route_path)
    }

    /// Configures a response with exactly `size` bytes.
    pub async fn large_response(&self, size: usize) -> String {
        let route_path = self.unique_path("large-response");
        Mock::given(method("GET"))
            .and(path(route_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; size]))
            .mount(&self.server)
            .await;
        self.absolute_url(&route_path)
    }

    /// Configures a binary response with an explicit content type.
    pub async fn binary_response(&self, data: &[u8], content_type: &str) -> String {
        let route_path = self.unique_path("binary-response");
        Mock::given(method("GET"))
            .and(path(route_path.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", content_type)
                    .set_body_bytes(data.to_vec()),
            )
            .mount(&self.server)
            .await;
        self.absolute_url(&route_path)
    }

    /// Configures headers mimicking a cloud instance metadata service response.
    ///
    /// This provides metadata for header-based SSRF detection tests only. `WireMock` still accepts
    /// the TCP connection on the mock server address; it does not bind to a metadata IP and does
    /// not exercise real SSRF network controls.
    ///
    /// TODO(#324): real SSRF network tests require a custom TCP server.
    pub async fn ssrf_metadata_headers(&self) -> String {
        let route_path = self.unique_path("ssrf-metadata-headers");
        Mock::given(method("GET"))
            .and(path(route_path.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Metadata-Flavor", "Arbitraitor-Test")
                    .insert_header("X-Arbitraitor-Test-Target-IP", "169.254.169.254")
                    .set_body_string("instance-id: i-arbitraitor-test\nrole: synthetic\n"),
            )
            .mount(&self.server)
            .await;
        self.absolute_url(&route_path)
    }

    fn unique_prefix(&self, name: &str) -> String {
        let route = self.next_route.fetch_add(1, Ordering::Relaxed);
        format!("{name}-{route}")
    }

    fn unique_path(&self, name: &str) -> String {
        format!("/{}", self.unique_prefix(name))
    }

    fn absolute_url(&self, route_path: &str) -> String {
        format!("{}{route_path}", self.url())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use super::MockHttpServer;

    #[tokio::test]
    async fn mock_server_serves_configured_binary_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockHttpServer::start().await;
        let url = server
            .binary_response(b"abc", "application/octet-stream")
            .await;

        let response = fetch(&url)?;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("content-type: application/octet-stream"));
        assert!(response.ends_with("abc"));
        Ok(())
    }

    #[tokio::test]
    async fn mock_server_serves_adversarial_routes() -> Result<(), Box<dyn std::error::Error>> {
        let server = MockHttpServer::start().await;
        let urls = [
            server.redirect_chain(2).await,
            server.http_redirect_chain().await,
            server.cross_origin_redirect().await,
            server.private_ip_metadata_headers().await,
            server.content_mismatch("expected", "actual").await,
            server.short_content_response().await,
            server.large_response(16).await,
            server.ssrf_metadata_headers().await,
        ];

        for url in urls {
            let response = fetch(&url)?;
            assert!(response.starts_with("HTTP/1.1 "));
        }
        Ok(())
    }

    #[tokio::test]
    async fn redirect_chain_zero_serves_terminal_route() -> Result<(), Box<dyn std::error::Error>> {
        let server = MockHttpServer::start().await;
        let url = server.redirect_chain(0).await;

        let response = fetch(&url)?;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("redirect complete"));
        Ok(())
    }

    fn fetch(url: &str) -> Result<String, Box<dyn std::error::Error>> {
        let without_scheme = url
            .strip_prefix("http://")
            .ok_or("url must use http scheme")?;
        let (authority, path) = without_scheme
            .split_once('/')
            .ok_or("url must include path")?;
        let mut stream = TcpStream::connect(authority)?;
        let request =
            format!("GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes())?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }
}
