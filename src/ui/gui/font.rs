//! Text, drawn a glyph at a time onto a plain pixel buffer.
//!
//! The face is compiled into the binary rather than looked up at runtime. A pinentry that
//! searches for a font can fail to find one, and a prompt that does not appear is the exact
//! failure ward exists to remove — trading it for a smaller binary would be a poor bargain.
//! It is DejaVu Sans because coverage here is correctness, not taste: the incident that
//! created this project was a Cyrillic passphrase, and a field that drew empty boxes for the
//! user's own alphabet would be worse than useless.

use std::collections::HashMap;

use fontdue::{Font, FontSettings};

/// The whole face, unsubsetted.
///
/// Around 750 KB, where a Latin-plus-Cyrillic subset would be closer to 250 KB. Subsetting
/// needs a tool this machine does not have, and installing one to save half a megabyte in a
/// program that is otherwise 350 KB is not a trade worth making today. Recorded as an open
/// item rather than quietly accepted.
const FACE: &[u8] = include_bytes!("../../../assets/DejaVuSans.ttf");

pub struct Text {
    font: Font,
    /// Rasterised glyphs, keyed by character and integral pixel size. A passphrase field
    /// redraws on every keystroke and the same handful of glyphs recur; rasterising them
    /// afresh each time would be work done over and over for an identical answer.
    cache: HashMap<(char, u32), (fontdue::Metrics, Vec<u8>)>,
}

impl Text {
    pub fn new() -> Result<Self, String> {
        let font = Font::from_bytes(FACE, FontSettings::default())?;
        Ok(Text {
            font,
            cache: HashMap::new(),
        })
    }

    fn glyph(&mut self, ch: char, px: f32) -> &(fontdue::Metrics, Vec<u8>) {
        let key = (ch, px as u32);
        self.cache
            .entry(key)
            .or_insert_with(|| self.font.rasterize(ch, px))
    }

    /// How wide a string will be, so it can be centred or fitted before it is drawn.
    pub fn width(&mut self, s: &str, px: f32) -> i32 {
        let mut w = 0.0f32;
        for ch in s.chars() {
            w += self.glyph(ch, px).0.advance_width;
        }
        w.ceil() as i32
    }

    /// Draws a string with its BASELINE at `y`.
    ///
    /// Baseline rather than top edge, because that is the only reference that keeps mixed
    /// scripts on the same line: Cyrillic and Latin have different cap heights, and aligning
    /// by the top would make one of them float.
    #[allow(clippy::too_many_arguments)]
    pub fn draw(
        &mut self,
        buf: &mut [u32],
        stride: usize,
        height: usize,
        x: i32,
        y: i32,
        s: &str,
        px: f32,
        colour: u32,
    ) -> i32 {
        let mut pen = x;
        for ch in s.chars() {
            let (m, bitmap) = self.glyph(ch, px);
            let (gw, gh) = (m.width, m.height);
            let gx = pen + m.xmin;
            let gy = y - m.height as i32 - m.ymin;
            for row in 0..gh {
                let py = gy + row as i32;
                if py < 0 || py as usize >= height {
                    continue;
                }
                for col in 0..gw {
                    let pxx = gx + col as i32;
                    if pxx < 0 || pxx as usize >= stride {
                        continue;
                    }
                    let a = bitmap[row * gw + col] as u32;
                    if a == 0 {
                        continue;
                    }
                    let idx = py as usize * stride + pxx as usize;
                    buf[idx] = blend(buf[idx], colour, a);
                }
            }
            pen += m.advance_width.round() as i32;
        }
        pen
    }
}

/// Mixes `fg` into `bg` by coverage. Plain integer arithmetic per channel: the buffer is
/// 0RGB with no alpha channel of its own, so the blend has to happen here or the glyph edges
/// come out as hard steps.
fn blend(bg: u32, fg: u32, a: u32) -> u32 {
    let mix = |shift: u32| {
        let b = (bg >> shift) & 0xff;
        let f = (fg >> shift) & 0xff;
        ((f * a + b * (255 - a)) / 255) & 0xff
    };
    (mix(16) << 16) | (mix(8) << 8) | mix(0)
}
