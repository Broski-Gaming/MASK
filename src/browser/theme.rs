//! Dark theme for the browser's own controls. Website content is not restyled.

use gtk::prelude::*;

const CSS: &str = r#"
window {
    background-color: #111318;
}

.mask-toolbar {
    background-color: #1a1d24;
    border-bottom: 1px solid #2a2f3a;
    padding: 6px 8px;
}

.mask-toolbar button {
    background-image: none;
    background-color: transparent;
    border: none;
    box-shadow: none;
    border-radius: 6px;
    color: #c9d1d9;
    padding: 4px 8px;
}

.mask-toolbar button:hover {
    background-color: #2a2f3a;
}

.mask-toolbar button:disabled {
    color: #4b5260;
}

.mask-address {
    background-image: none;
    background-color: #0d0f13;
    color: #e6edf3;
    border: 1px solid #2f3540;
    border-radius: 8px;
    box-shadow: none;
    padding: 6px 12px;
    caret-color: #8b6cff;
}

.mask-address:focus {
    border-color: #8b6cff;
}

.mask-status {
    color: #e3b341;
    padding: 0 6px;
}

.mask-notice {
    background-color: #3a1d22;
    color: #ffb4b4;
    padding: 6px 12px;
}
"#;

pub fn apply() -> Result<(), gtk::glib::Error> {
    if let Some(settings) = gtk::Settings::default() {
        settings.set_gtk_application_prefer_dark_theme(true);
    }

    let provider = gtk::CssProvider::new();
    provider.load_from_data(CSS.as_bytes())?;
    if let Some(screen) = gtk::gdk::Screen::default() {
        gtk::StyleContext::add_provider_for_screen(
            &screen,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
    Ok(())
}
