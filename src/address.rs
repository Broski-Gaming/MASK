//! Address bar input handling.
//!
//! Only `http` and `https` URLs are accepted. Input without a scheme is
//! treated as an HTTPS address. Other schemes (`file:`, `javascript:`,
//! `data:`, ...) are rejected, and `.mask` addresses are recognised but not
//! supported until the MASK network exists.

use std::fmt;

use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    Invalid,
    UnsupportedScheme(String),
    MaskNotSupported,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Enter a web address."),
            Self::Invalid => write!(f, "That is not a valid web address."),
            Self::UnsupportedScheme(scheme) => {
                write!(
                    f,
                    "\"{scheme}:\" addresses are not supported. Use https://."
                )
            }
            Self::MaskNotSupported => write!(
                f,
                ".mask addresses are not available yet: the MASK network has not been built."
            ),
        }
    }
}

impl std::error::Error for AddressError {}

/// Turn address bar input into a URL the browser may load.
pub fn parse_address(input: &str) -> Result<Url, AddressError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(AddressError::Empty);
    }
    if input.chars().any(char::is_whitespace) {
        return Err(AddressError::Invalid);
    }

    let url = if input.contains("://") || has_explicit_scheme(input) {
        Url::parse(input)
    } else {
        Url::parse(&format!("https://{input}"))
    }
    .map_err(|_| AddressError::Invalid)?;

    match url.scheme() {
        "http" | "https" => {}
        other => return Err(AddressError::UnsupportedScheme(other.to_owned())),
    }

    let host = url.host_str().ok_or(AddressError::Invalid)?;
    let host = host.trim_end_matches('.');
    if host == "mask" || host.ends_with(".mask") {
        return Err(AddressError::MaskNotSupported);
    }

    Ok(url)
}

/// True for inputs like `mailto:x` or `about:blank`, false for `localhost:8080`.
fn has_explicit_scheme(input: &str) -> bool {
    let Some((scheme, rest)) = input.split_once(':') else {
        return false;
    };
    let valid_scheme = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    let port = rest.split(['/', '?', '#']).next().unwrap_or("");
    let looks_like_port = !port.is_empty() && port.chars().all(|c| c.is_ascii_digit());
    valid_scheme && !looks_like_port
}

/// Text to show in the address bar for the page currently loaded.
/// Internal pages (the start page, `about:blank`) show an empty bar.
pub fn display_text(uri: &str) -> &str {
    if uri.starts_with("https://") || uri.starts_with("http://") {
        uri
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> String {
        parse_address(input).unwrap().to_string()
    }

    #[test]
    fn bare_domain_defaults_to_https() {
        assert_eq!(ok("example.com"), "https://example.com/");
        assert_eq!(
            ok("  example.com/path?q=1  "),
            "https://example.com/path?q=1"
        );
    }

    #[test]
    fn explicit_http_and_https_are_kept() {
        assert_eq!(ok("https://example.com"), "https://example.com/");
        assert_eq!(ok("http://example.com"), "http://example.com/");
        assert_eq!(ok("HTTPS://EXAMPLE.COM"), "https://example.com/");
    }

    #[test]
    fn host_with_port_is_not_a_scheme() {
        assert_eq!(ok("localhost:8080"), "https://localhost:8080/");
        assert_eq!(ok("example.com:8443/a"), "https://example.com:8443/a");
        assert_eq!(ok("[::1]:8080"), "https://[::1]:8080/");
    }

    #[test]
    fn dangerous_or_unsupported_schemes_are_rejected() {
        for (input, scheme) in [
            ("file:///etc/passwd", "file"),
            ("javascript:alert(1)", "javascript"),
            ("data:text/html,hi", "data"),
            ("about:blank", "about"),
            ("mailto:a@example.com", "mailto"),
            ("ftp://example.com", "ftp"),
        ] {
            assert_eq!(
                parse_address(input),
                Err(AddressError::UnsupportedScheme(scheme.into())),
                "{input}"
            );
        }
    }

    #[test]
    fn mask_addresses_are_not_supported_yet() {
        for input in ["abc.mask", "https://abc.mask/page", "ABC.MASK.", "mask"] {
            assert_eq!(
                parse_address(input),
                Err(AddressError::MaskNotSupported),
                "{input}"
            );
        }
    }

    #[test]
    fn empty_and_malformed_input_is_rejected() {
        assert_eq!(parse_address("   "), Err(AddressError::Empty));
        assert_eq!(parse_address("two words"), Err(AddressError::Invalid));
        assert_eq!(parse_address("https://"), Err(AddressError::Invalid));
    }

    #[test]
    fn display_text_hides_internal_pages() {
        assert_eq!(display_text("https://example.com/"), "https://example.com/");
        assert_eq!(display_text("about:blank"), "");
        assert_eq!(display_text("data:text/html,x"), "");
    }
}
