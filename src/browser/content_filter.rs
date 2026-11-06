//! Installs MASK's content-blocking rules ([`crate::privacy::content_rules`])
//! into a WebKit view.
//!
//! WebKit compiles the rules (Safari's content-blocker format) and then
//! enforces them inside the engine for every load a page makes. The safe
//! `webkit2gtk` 2.0 crate does not wrap this API, so this module calls the
//! C functions from `webkit2gtk-sys` directly. Everything unsafe is here.
//!
//! Compilation is asynchronous; [`install`] runs the GLib main loop until
//! it finishes and returns an error if it fails or takes too long. The
//! browser refuses to start without the rules (fail closed): it never shows
//! a page that the rules should have constrained.

use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr;
use std::time::{Duration, Instant};

use gtk::glib;
use gtk::glib::translate::ToGlibPtr;
use webkit2gtk::WebViewExt;
use webkit2gtk::ffi;

const IDENTIFIER: &str = "mask-privacy";
const COMPILE_TIMEOUT: Duration = Duration::from_secs(20);

type Outcome = Option<Result<*mut ffi::WebKitUserContentFilter, String>>;

/// Called by WebKit when compilation finishes.
///
/// # Safety
/// `data` is the `Box<Outcome>` pointer passed to `save`; `source` is the
/// filter store and `result` the async result, as GIO guarantees.
unsafe extern "C" fn compiled(
    source: *mut glib::gobject_ffi::GObject,
    result: *mut gtk::gio::ffi::GAsyncResult,
    data: glib::ffi::gpointer,
) {
    // SAFETY: see the function's contract above.
    unsafe {
        let outcome = &mut *(data as *mut Outcome);
        let mut error: *mut glib::ffi::GError = ptr::null_mut();
        let filter = ffi::webkit_user_content_filter_store_save_finish(
            source as *mut ffi::WebKitUserContentFilterStore,
            result,
            &mut error,
        );
        *outcome = Some(if filter.is_null() {
            let message = if error.is_null() {
                "unknown error".to_owned()
            } else {
                let text = CStr::from_ptr((*error).message)
                    .to_string_lossy()
                    .into_owned();
                glib::ffi::g_error_free(error);
                text
            };
            Err(message)
        } else {
            Ok(filter)
        });
    }
}

/// Compile `rules_json` (stored under `store_dir`) and add it to `view`.
pub fn install(
    view: &webkit2gtk::WebView,
    rules_json: &str,
    store_dir: &Path,
) -> Result<(), String> {
    let manager = view
        .user_content_manager()
        .ok_or("the web view has no user content manager")?;
    let dir = CString::new(store_dir.to_str().ok_or("store path is not UTF-8")?)
        .map_err(|_| "store path contains NUL")?;
    let identifier = CString::new(IDENTIFIER).expect("no NUL");
    let source = glib::Bytes::from_owned(rules_json.as_bytes().to_vec());

    // SAFETY: valid NUL-terminated path; returns a new reference (or NULL).
    let store = unsafe { ffi::webkit_user_content_filter_store_new(dir.as_ptr()) };
    if store.is_null() {
        return Err("WebKit could not create a content filter store".into());
    }
    let outcome: *mut Outcome = Box::into_raw(Box::new(None));
    // SAFETY: `store`, `identifier` and `source` stay alive until the
    // callback has run (we wait for it below); `outcome` is a valid,
    // exclusively owned pointer that only the callback writes.
    unsafe {
        ffi::webkit_user_content_filter_store_save(
            store,
            identifier.as_ptr(),
            ToGlibPtr::<*const glib::ffi::GBytes>::to_glib_none(&source).0 as *mut _,
            ptr::null_mut(),
            Some(compiled),
            outcome as glib::ffi::gpointer,
        );
    }
    let context = glib::MainContext::default();
    let deadline = Instant::now() + COMPILE_TIMEOUT;
    // SAFETY: `outcome` is valid; the callback runs on this (main) thread
    // during `iteration`, never concurrently with this read.
    while unsafe { (*outcome).is_none() } {
        if Instant::now() > deadline {
            // The callback may still run later: leak `outcome` and the store
            // on purpose rather than free memory it could write to.
            return Err("WebKit took too long to compile the content rules".into());
        }
        context.iteration(true);
    }
    // SAFETY: the callback has run; nothing else references `outcome`.
    let outcome = unsafe { Box::from_raw(outcome) };
    let result = match outcome.expect("checked above") {
        Ok(filter) => {
            // SAFETY: `manager` is a live UserContentManager and `filter` a
            // valid filter we own one reference to; add_filter takes its own.
            unsafe {
                ffi::webkit_user_content_manager_add_filter(
                    ToGlibPtr::<*mut ffi::WebKitUserContentManager>::to_glib_none(&manager).0,
                    filter,
                );
                ffi::webkit_user_content_filter_unref(filter);
            }
            Ok(())
        }
        Err(message) => Err(format!("WebKit rejected the content rules: {message}")),
    };
    // SAFETY: we own the reference returned by `_new`.
    unsafe { glib::gobject_ffi::g_object_unref(store as *mut glib::gobject_ffi::GObject) };
    result
}
