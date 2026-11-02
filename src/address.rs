//! Address bar input handling.
//!
//! Two kinds of address are accepted:
//! - `http://` / `https://` websites (bare domains default to `https://`);
//! - cryptographic MORP services: `morp://<56-char id>.morp/...` or just
//!   `<56-char id>.morp`. These are validated (length, Base32, version,
//!   checksum, public key) before anything is loaded.
//!
//! A `.morp` name is never sent over `http(s)`, which would hand it to public
//! DNS. Other schemes (`file:`, `javascript:`, `data:`, ...) are rejected.
//! MASK has no human-readable service names: `.mask` and any other alias
//! scheme are refused.

use std::fmt;

use mask_net::address::{SUFFIX as MORP_SUFFIX, parse_url as parse_morp_url};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    Invalid,
    UnsupportedScheme(String),
    /// A `.morp` address failed validation.
    InvalidMorp(String),
    /// A `.morp` host was given with `http://` or `https://`.
    MorpOverHttp,
    /// `.mask` names: MASK only supports cryptographic `.morp` addresses.
    MaskNamesUnsupported,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Enter a web address or a .morp address."),
            Self::Invalid => write!(f, "That is not a valid web address."),
            Self::UnsupportedScheme(scheme) => write!(
                f,
                "\"{scheme}:\" addresses are not supported. Use https:// or morp://."
            ),
            Self::InvalidMorp(why) => write!(f, "Invalid .morp address: {why}"),
            Self::MorpOverHttp => write!(
                f,
                ".morp addresses are only opened with morp://, never over http(s) or public DNS."
            ),
            Self::MaskNamesUnsupported => write!(
                f,
                "MASK has no named services. Use a cryptographic morp://<id>.morp address."
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

    if input
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("morp://"))
    {
        return parse_morp(&format!("morp://{}", &input[7..]));
    }
    if !input.contains("://") && bare_host(input).ends_with(MORP_SUFFIX) {
        return parse_morp(&format!("morp://{input}"));
    }

    let url = if input.contains("://") || has_explicit_scheme(input) {
        Url::parse(input)
    } else {
        Url::parse(&format!("https://{input}"))
    }
    .map_err(|_| AddressError::Invalid)?;

    match url.scheme() {
        "http" | "https" => {}
        "morp" => {
            return Err(AddressError::InvalidMorp(
                "write it as morp://<id>.morp/".into(),
            ));
        }
        other => return Err(AddressError::UnsupportedScheme(other.to_owned())),
    }

    let host = url.host_str().ok_or(AddressError::Invalid)?;
    let host = host.trim_end_matches('.');
    if host == "morp" || host.ends_with(MORP_SUFFIX) {
        return Err(AddressError::MorpOverHttp);
    }
    if host == "mask" || host.ends_with(".mask") {
        return Err(AddressError::MaskNamesUnsupported);
    }

    Ok(url)
}

fn parse_morp(text: &str) -> Result<Url, AddressError> {
    let (address, path) =
        parse_morp_url(text).map_err(|e| AddressError::InvalidMorp(e.to_string()))?;
    Url::parse(&format!("morp://{}{path}", address.host()))
        .map_err(|e| AddressError::InvalidMorp(e.to_string()))
}

/// The host part of scheme-less input, without port, lowercased.
fn bare_host(input: &str) -> String {
    let authority = input.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    host.trim_end_matches('.').to_ascii_lowercase()
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
    if uri.starts_with("https://") || uri.starts_with("http://") || uri.starts_with("morp://") {
        uri
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mask_net::service::keys::ServiceKeys;

    fn ok(input: &str) -> String {
        parse_address(input).unwrap().to_string()
    }

    fn morp_host() -> String {
        ServiceKeys::generate().address().host()
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
    fn morp_addresses_open_with_the_morp_scheme() {
        let host = morp_host();
        assert_eq!(ok(&format!("morp://{host}")), format!("morp://{host}/"));
        assert_eq!(ok(&format!("morp://{host}/")), format!("morp://{host}/"));
        assert_eq!(ok(&host), format!("morp://{host}/"));
        assert_eq!(
            ok(&format!("{host}/blog/post.html?x=1")),
            format!("morp://{host}/blog/post.html?x=1")
        );
        assert_eq!(ok(&format!("MORP://{host}/")), format!("morp://{host}/"));
    }

    #[test]
    fn invalid_morp_addresses_are_rejected_before_loading() {
        let host = morp_host();
        let mut typo = host.clone().into_bytes();
        typo[3] = if typo[3] == b'a' { b'b' } else { b'a' };
        let typo = String::from_utf8(typo).unwrap();
        for input in [
            "morp://example.morp/".to_owned(),
            "shop.morp".to_owned(),
            format!("morp://{}/", host.to_ascii_uppercase()),
            typo,
            format!("morp://{host}:80/"),
            format!("{host}:80"),
            format!("morp://user@{host}/"),
            "morp:something".to_owned(),
        ] {
            assert!(
                matches!(parse_address(&input), Err(AddressError::InvalidMorp(_))),
                "{input}: {:?}",
                parse_address(&input)
            );
        }
    }

    #[test]
    fn morp_names_never_go_over_http() {
        let host = morp_host();
        for input in [
            format!("https://{host}/"),
            format!("http://{host}/"),
            "https://anything.morp/".to_owned(),
        ] {
            assert_eq!(
                parse_address(&input),
                Err(AddressError::MorpOverHttp),
                "{input}"
            );
        }
    }

    #[test]
    fn named_mask_addresses_are_not_supported() {
        for input in ["abc.mask", "https://abc.mask/page", "ABC.MASK.", "mask"] {
            assert_eq!(
                parse_address(input),
                Err(AddressError::MaskNamesUnsupported),
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
    fn display_text_shows_web_and_morp_pages_only() {
        assert_eq!(display_text("https://example.com/"), "https://example.com/");
        let morp = format!("morp://{}/", morp_host());
        assert_eq!(display_text(&morp), morp);
        assert_eq!(display_text("about:blank"), "");
        assert_eq!(display_text("data:text/html,x"), "");
    }
}
