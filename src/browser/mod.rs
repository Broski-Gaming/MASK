//! The MASK Browser window: a native GTK toolbar above a Wry/WebKitGTK view.
//!
//! The toolbar is native GTK rather than HTML so that web content can never
//! script or restyle the browser's own controls.

mod start_page;
mod theme;

use std::error::Error;

use gtk::glib;
use gtk::prelude::*;
use webkit2gtk::WebViewExt;
use wry::{WebViewBuilder, WebViewBuilderExtUnix, WebViewExtUnix};

use crate::address::{display_text, parse_address};

pub const WINDOW_TITLE: &str = "MASK Browser";

/// Honest description of the current connection, shown in the toolbar.
const CONNECTION_STATUS: &str = "Direct connection · not anonymous";

/// Build the window and run the GTK main loop until it is closed.
pub fn run() -> Result<(), Box<dyn Error>> {
    gtk::init()?;
    theme::apply()?;

    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title(WINDOW_TITLE);
    window.set_default_size(1200, 800);

    let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
    window.add(&root);

    // Toolbar: back, forward, reload, address bar, connection status.
    let toolbar = gtk::Box::new(gtk::Orientation::Horizontal, 4);
    toolbar.style_context().add_class("mask-toolbar");
    let back = icon_button("go-previous-symbolic", "Back");
    let forward = icon_button("go-next-symbolic", "Forward");
    let reload = icon_button("view-refresh-symbolic", "Reload");
    let address = gtk::Entry::new();
    address.style_context().add_class("mask-address");
    address.set_hexpand(true);
    address.set_placeholder_text(Some("Enter an address, e.g. example.com"));
    let status = gtk::Label::new(Some(CONNECTION_STATUS));
    status.style_context().add_class("mask-status");
    status.set_tooltip_text(Some(
        "MASK 0.1 has no onion routing. Websites see your real IP address.",
    ));
    toolbar.pack_start(&back, false, false, 0);
    toolbar.pack_start(&forward, false, false, 0);
    toolbar.pack_start(&reload, false, false, 0);
    toolbar.pack_start(&address, true, true, 4);
    toolbar.pack_start(&status, false, false, 0);
    root.pack_start(&toolbar, false, false, 0);

    // Error bar for rejected addresses; hidden until needed.
    let notice = gtk::Label::new(None);
    notice.style_context().add_class("mask-notice");
    notice.set_xalign(0.0);
    root.pack_start(&notice, false, false, 0);

    // Web content area.
    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    root.pack_start(&content, true, true, 0);
    let wry_view = WebViewBuilder::new()
        // Ephemeral session: cookies, cache and storage are discarded on exit.
        .with_incognito(true)
        .with_html(start_page::HTML)
        .build_gtk(&content)?;
    let view = wry_view.webview();

    back.set_sensitive(false);
    forward.set_sensitive(false);

    back.connect_clicked(glib::clone!(@weak view => move |_| view.go_back()));
    forward.connect_clicked(glib::clone!(@weak view => move |_| view.go_forward()));
    reload.connect_clicked(glib::clone!(@weak view => move |_| view.reload()));

    address.connect_activate(glib::clone!(@weak view, @weak notice => move |entry| {
        match parse_address(&entry.text()) {
            Ok(url) => {
                notice.hide();
                view.load_uri(url.as_str());
                view.grab_focus();
            }
            Err(err) => {
                notice.set_text(&err.to_string());
                notice.show();
            }
        }
    }));

    // Keep the address bar in sync with the page, including link clicks.
    view.connect_uri_notify(glib::clone!(@weak address => move |view| {
        let uri = view.uri().unwrap_or_default();
        address.set_text(display_text(&uri));
    }));

    view.connect_title_notify(glib::clone!(@weak window => move |view| {
        let title = view.title();
        window.set_title(&window_title(title.as_deref()));
    }));

    view.connect_load_changed(glib::clone!(@weak back, @weak forward => move |view, _| {
        back.set_sensitive(view.can_go_back());
        forward.set_sensitive(view.can_go_forward());
    }));

    window.connect_destroy(|_| gtk::main_quit());
    window.show_all();
    notice.hide();
    address.grab_focus();

    gtk::main();

    // The wry WebView must stay alive for as long as the window is shown.
    drop(wry_view);
    Ok(())
}

fn icon_button(icon: &str, tooltip: &str) -> gtk::Button {
    let button = gtk::Button::from_icon_name(Some(icon), gtk::IconSize::Button);
    button.set_tooltip_text(Some(tooltip));
    button
}

/// Window title for a page: "Page title — MASK Browser".
fn window_title(page_title: Option<&str>) -> String {
    match page_title.map(str::trim) {
        Some(title) if !title.is_empty() && title != WINDOW_TITLE => {
            format!("{title} — {WINDOW_TITLE}")
        }
        _ => WINDOW_TITLE.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_title_includes_page_title() {
        assert_eq!(window_title(Some("Example")), "Example — MASK Browser");
    }

    #[test]
    fn window_title_falls_back_to_browser_name() {
        assert_eq!(window_title(None), "MASK Browser");
        assert_eq!(window_title(Some("   ")), "MASK Browser");
        assert_eq!(window_title(Some("MASK Browser")), "MASK Browser");
    }
}
