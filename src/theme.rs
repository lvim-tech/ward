//! The palette the window is painted with.
//!
//! One file, `~/.config/ward/theme.conf`, and it is GENERATED — written by lvim-colorscheme
//! from whatever scheme is active, so the prompt matches the editor that raised it. Nobody
//! edits it by hand and ward never writes it.
//!
//! There is deliberately no configuration file beside it. A pinentry is a program you meet
//! at the moment you are least able to reason about it; one whose behaviour depends on a
//! file you wrote months ago is one you cannot predict from how it was invoked. Colour is
//! the exception because colour is not behaviour: it changes what the prompt looks like and
//! nothing about what it does, and matching the desktop is the difference between a prompt
//! you recognise and one you have to stop and examine.
//!
//! That distinction is worth keeping sharp, because recognising the prompt is a security
//! property. A fake pinentry is a real attack and nothing in any protocol prevents it; the
//! only defence anyone has ever had is knowing what the real one looks like.
//!
//! Parsed by hand — `key = #RRGGBB`, `#` starts a comment. A format with a parser crate
//! behind it would be more dependency than grammar, in a program whose dependency list is
//! an argument it is making.

use std::path::PathBuf;

/// Defaults are Everforest, the palette the rest of the lvim-tech set paints with, so ward
/// looks like it belongs even before anything has generated a theme for it.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub bg: u32,
    pub fg: u32,
    pub dim: u32,
    pub accent: u32,
    pub error: u32,
    pub border: u32,
    pub field: u32,
}

impl Default for Theme {
    fn default() -> Self {
        Theme {
            bg: 0x2f383e,
            fg: 0xd3c6aa,
            dim: 0x859289,
            accent: 0x7fbbb3,
            error: 0xe67e80,
            border: 0x4f585e,
            field: 0x374247,
        }
    }
}

/// Where the generated palette lives.
pub fn path() -> PathBuf {
    let base = match std::env::var("XDG_CONFIG_HOME") {
        Ok(d) if !d.is_empty() => PathBuf::from(d),
        _ => match std::env::var("HOME") {
            Ok(h) => PathBuf::from(h).join(".config"),
            Err(_) => PathBuf::from(".config"),
        },
    };
    base.join("ward").join("theme.conf")
}

fn colour(s: &str) -> Option<u32> {
    // The first token, so `bg = #101010   # the window` can carry a trailing comment
    // without the comment becoming part of the value.
    let s = s.split_whitespace().next().unwrap_or("");
    let s = s.trim_start_matches('#');
    if s.len() != 6 {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

impl Theme {
    /// Loads the generated palette, falling back to the built-in one key by key.
    ///
    /// Per key rather than all-or-nothing: a generator that learns a new colour later, or
    /// one that omits a key ward has since added, should shift what it knows about and
    /// leave the rest alone. An unreadable file is not an error either — it means no theme
    /// has been generated yet, which is the state every machine starts in.
    pub fn load() -> Theme {
        Theme::load_from(&path())
    }

    /// The parse, separated from where the file lives so a test can point at one without
    /// touching the process environment — `set_var` under a parallel harness is a race by
    /// construction, and `XDG_CONFIG_HOME` is read by more than this module.
    pub fn load_from(file: &std::path::Path) -> Theme {
        let mut t = Theme::default();
        let Ok(text) = std::fs::read_to_string(file) else {
            return t;
        };
        for line in text.lines() {
            // A comment is a line that STARTS with `#`. Splitting on `#` anywhere threw
            // away every value written in the `#RRGGBB` form this file documents — which
            // was every value a generator would produce.
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let Some(c) = colour(v) else { continue };
            match k.trim().to_ascii_lowercase().as_str() {
                "bg" | "background" => t.bg = c,
                "fg" | "foreground" => t.fg = c,
                "dim" | "comment" => t.dim = c,
                "accent" | "blue" => t.accent = c,
                "error" | "red" => t.error = c,
                "border" => t.border = c,
                "field" => t.field = c,
                _ => {}
            }
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colours_with_or_without_a_hash() {
        assert_eq!(colour("#2f383e"), Some(0x2f383e));
        assert_eq!(colour("2f383e"), Some(0x2f383e));
        assert_eq!(colour("#fff"), None);
        assert_eq!(colour("not a colour"), None);
    }

    #[test]
    fn an_absent_theme_is_not_a_failure() {
        // Every machine starts here, and a prompt that refused to appear until somebody had
        // generated a palette would be a prompt that fails for the most ordinary reason.
        let t = Theme::load_from(std::path::Path::new(
            "/nonexistent-for-this-test/theme.conf",
        ));
        assert_eq!(t.bg, Theme::default().bg);
    }

    /// Writes `body` to a private file and parses it.
    fn parse(name: &str, body: &str) -> Theme {
        let dir =
            std::env::temp_dir().join(format!("ward-theme-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("theme.conf");
        std::fs::write(&file, body).unwrap();
        let t = Theme::load_from(&file);
        let _ = std::fs::remove_dir_all(&dir);
        t
    }

    #[test]
    fn loads_the_hash_form_the_file_documents() {
        // The regression this exists for: `#` was treated as a comment marker ANYWHERE on
        // the line, so `bg = #101010` parsed as `bg = ` and every generated colour was
        // silently dropped back to the default. Testing `colour()` alone never saw it,
        // because the `#` did not survive as far as `colour()`.
        let t = parse("hash", "bg = #101010\nfg = #ff0000\n");
        assert_eq!(t.bg, 0x101010);
        assert_eq!(t.fg, 0xff0000);
    }

    #[test]
    fn a_whole_line_comment_is_still_a_comment() {
        let t = parse("comment", "# generated by lvim-colorscheme\nbg = #101010\n");
        assert_eq!(t.bg, 0x101010);
    }

    #[test]
    fn a_trailing_comment_does_not_eat_the_value() {
        let t = parse("trailing", "bg = #101010  # the window\n");
        assert_eq!(t.bg, 0x101010);
    }

    #[test]
    fn unknown_keys_leave_the_rest_alone() {
        let t = parse("unknown", "nonsense = #010101\nbg = 101010\n");
        assert_eq!(t.bg, 0x101010);
        assert_eq!(t.fg, Theme::default().fg);
    }
}
