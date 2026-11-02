//! Static website serving from a folder, without escaping it.
//!
//! Request paths are percent-decoded and split into segments. `..`
//! segments are refused, hidden files (`.name`) are not served, and the
//! final path is canonicalised and must still lie inside the site folder
//! (so symlinks cannot point outside it).

use std::io;
use std::path::{Path, PathBuf};

use percent_encoding::percent_decode_str;

use super::channel::{MAX_BODY, Request, Response};

pub struct Site {
    root: PathBuf,
}

impl Site {
    pub fn new(root: &Path) -> io::Result<Self> {
        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a folder", root.display()),
            ));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Map a request path to a file inside the site, or an HTTP status.
    pub fn resolve(&self, request_path: &str) -> Result<PathBuf, u16> {
        let path = request_path.split(['?', '#']).next().unwrap_or("/");
        if !path.starts_with('/') {
            return Err(400);
        }
        let decoded = percent_decode_str(path).decode_utf8().map_err(|_| 400u16)?;
        if decoded.contains(['\0', '\\']) {
            return Err(400);
        }

        let mut full = self.root.clone();
        for segment in decoded.split('/') {
            match segment {
                "" | "." => {}
                ".." => return Err(403),
                hidden if hidden.starts_with('.') => return Err(404),
                name => full.push(name),
            }
        }
        if full.is_dir() {
            full.push("index.html");
        }
        let canonical = full.canonicalize().map_err(|_| 404u16)?;
        if !canonical.starts_with(&self.root) {
            return Err(403);
        }
        if !canonical.is_file() {
            return Err(404);
        }
        Ok(canonical)
    }

    pub async fn handle(&self, request: &Request) -> Response {
        if request.method != "GET" {
            return error(405, "Only GET is supported.");
        }
        let path = match self.resolve(&request.path) {
            Ok(path) => path,
            Err(status) => return error(status, reason(status)),
        };
        match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.len() > MAX_BODY => return error(413, "File too large."),
            Ok(_) => {}
            Err(_) => return error(404, reason(404)),
        }
        match tokio::fs::read(&path).await {
            Ok(body) => Response {
                status: 200,
                content_type: content_type(&path).to_owned(),
                body,
            },
            Err(_) => error(500, "The file could not be read."),
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        400 => "Bad request.",
        403 => "Forbidden.",
        404 => "Not found.",
        _ => "Error.",
    }
}

fn error(status: u16, message: &str) -> Response {
    Response {
        status,
        content_type: "text/plain; charset=utf-8".into(),
        body: format!("{status} {message}\n").into_bytes(),
    }
}

/// Content type by file extension.
pub fn content_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn site() -> (tempfile::TempDir, Site) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("site");
        fs::create_dir_all(root.join("css")).unwrap();
        fs::write(root.join("index.html"), "<h1>home</h1>").unwrap();
        fs::write(root.join("css/site.css"), "body{}").unwrap();
        fs::write(root.join("my page.html"), "spaces").unwrap();
        fs::write(root.join(".secret"), "hidden").unwrap();
        fs::write(dir.path().join("outside.txt"), "outside").unwrap();
        std::os::unix::fs::symlink(dir.path().join("outside.txt"), root.join("escape.txt"))
            .unwrap();
        let site = Site::new(&root).unwrap();
        (dir, site)
    }

    #[test]
    fn serves_files_and_index() {
        let (_dir, site) = site();
        assert!(site.resolve("/").unwrap().ends_with("index.html"));
        assert!(
            site.resolve("/css/site.css?v=1")
                .unwrap()
                .ends_with("site.css")
        );
        assert!(
            site.resolve("/my%20page.html")
                .unwrap()
                .ends_with("my page.html")
        );
        assert!(site.resolve("/css/").is_err());
    }

    #[test]
    fn refuses_to_leave_the_site_folder() {
        let (_dir, site) = site();
        assert_eq!(site.resolve("/../outside.txt"), Err(403));
        assert_eq!(site.resolve("/css/../../outside.txt"), Err(403));
        assert_eq!(site.resolve("/%2e%2e/outside.txt"), Err(403));
        assert_eq!(site.resolve("/escape.txt"), Err(403));
        assert_eq!(site.resolve("/..%5coutside.txt"), Err(400));
        assert_eq!(site.resolve("/a%00b"), Err(400));
        assert_eq!(site.resolve("relative"), Err(400));
    }

    #[test]
    fn hides_dotfiles_and_missing_files() {
        let (_dir, site) = site();
        assert_eq!(site.resolve("/.secret"), Err(404));
        assert_eq!(site.resolve("/nope.html"), Err(404));
    }

    #[tokio::test]
    async fn responses_have_content_types_and_statuses() {
        let (_dir, site) = site();
        let get = |path: &str| Request {
            method: "GET".into(),
            path: path.into(),
        };
        let page = site.handle(&get("/")).await;
        assert_eq!(page.status, 200);
        assert_eq!(page.content_type, "text/html; charset=utf-8");
        assert_eq!(page.body, b"<h1>home</h1>");
        assert_eq!(
            site.handle(&get("/css/site.css")).await.content_type,
            "text/css; charset=utf-8"
        );
        assert_eq!(site.handle(&get("/missing")).await.status, 404);
        let post = Request {
            method: "POST".into(),
            path: "/".into(),
        };
        assert_eq!(site.handle(&post).await.status, 405);
    }
}
