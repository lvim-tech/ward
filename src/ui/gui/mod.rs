//! The window.
//!
//! This is the front-end that makes ward usable at all from a menu, a browser, or anything
//! else launched without a terminal — the situation in which the previously configured
//! pinentry produced no prompt and no message, only a GPG operation that quietly did not
//! work.
//!
//! Drawn pixel by pixel: `winit` supplies a window and keystrokes on both Wayland and X11,
//! `softbuffer` hands over a plain buffer of pixels, and the glyphs come from a font
//! compiled into the binary. No widget toolkit, and the reason is narrow: the text widgets
//! of the usual toolkits own their contents as a heap string that reallocates as it grows
//! and is never wiped. No wrapper fixes a widget that owns the buffer, and the buffer is
//! the whole argument this program makes.
//!
//! What that still does not buy, said plainly: every keystroke passes through the
//! compositor and through winit's event structures as a short-lived per-character value
//! before it reaches locked memory. That is true of every graphical pinentry, including
//! GNU's own, because something has to translate keycodes. The guarantee ward can actually
//! make is narrower and worth stating exactly: the ASSEMBLED passphrase exists only in the
//! locked buffer.

mod font;

use std::num::NonZeroU32;
use std::rc::Rc;
use std::time::{Duration, Instant};

use winit::application::ApplicationHandler;
use winit::dpi::PhysicalSize;
use winit::event::{ElementState, StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, EventLoop};
use winit::keyboard::{Key, NamedKey};
use winit::platform::pump_events::EventLoopExtPumpEvents;
use winit::window::{Window, WindowLevel};

use crate::secret::Secret;
use crate::server::State;
use crate::theme::Theme;
use crate::ui::{Frontend, Outcome};

/// Not settable, on purpose: a pinentry with a configuration file is one whose behaviour you
/// cannot predict from how it was invoked. The size is not guessed either — it is measured
/// from what is actually being drawn, because a fixed height is wrong for every prompt
/// except the one it was picked for, and gpg's descriptions run from one line to five.
const FONT_PX: f32 = 15.0;
const PAD: i32 = 20;
const MIN_WIDTH: u32 = 420;
const MAX_WIDTH: u32 = 760;

pub struct GuiFrontend {
    events: EventLoop<()>,
    theme: Theme,
    text: font::Text,
}

impl GuiFrontend {
    /// Builds the front-end, or explains why there is no window to be had.
    ///
    /// Creating the event loop is the probe: it connects to the compositor or the X server,
    /// so a `WAYLAND_DISPLAY` naming a socket that no longer exists fails here rather than
    /// being believed. Trusting the variable instead is precisely how the previous pinentry
    /// failed silently.
    ///
    /// Callable ONCE per process, and not by choice: winit sets a global flag on the first
    /// attempt — successful or not — and answers `RecreationAttempt` to every later one.
    /// `ui::Frontends` is what keeps this honest by holding the result for the whole
    /// connection; calling it per prompt is what made the retry after a wrong passphrase
    /// fall through to the terminal.
    pub fn new() -> Result<Self, String> {
        let events = EventLoop::new().map_err(|e| format!("no display could be opened: {e}"))?;
        let text = font::Text::new()?;
        Ok(GuiFrontend {
            events,
            theme: Theme::load(),
            text,
        })
    }

    fn run(events: &mut EventLoop<()>, mut app: App<'_>) -> Outcome {
        // pump_app_events rather than run_app: the agent may ask more than once on the same
        // connection — a wrong passphrase means another GETPIN — and an event loop that is
        // consumed by running cannot be asked a second time.
        loop {
            events.pump_app_events(Some(Duration::from_millis(50)), &mut app);
            if let Some(o) = app.outcome.take() {
                return o;
            }
            if let Some(d) = app.deadline {
                if Instant::now() >= d {
                    return Outcome::Cancelled;
                }
            }
        }
    }
}

/// What a line is for, which decides its colour and how much room it gets.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Role {
    Title,
    Body,
    Error,
}

/// What the window is currently asking.
enum Ask {
    Pin,
    Confirm { one_button: bool },
}

struct App<'a> {
    theme: &'a Theme,
    st: &'a State,
    text: &'a mut font::Text,
    ask: Ask,
    secret: Option<&'a mut Secret>,
    repeat_buf: Option<Secret>,
    on_repeat: bool,
    note: Option<String>,

    window: Option<Rc<Window>>,
    surface: Option<softbuffer::Surface<Rc<Window>, Rc<Window>>>,
    outcome: Option<Outcome>,
    deadline: Option<Instant>,
}

impl App<'_> {
    /// The lines the prompt will occupy, in the order they are drawn.
    ///
    /// Measured once and used for both the window size and the drawing, so the two cannot
    /// disagree — a layout computed twice is a layout that eventually differs from itself.
    fn lines(&self) -> Vec<(String, f32, Role)> {
        let px = FONT_PX;
        let small = px * 0.85;
        let mut v = Vec::new();
        if let Some(t) = self.st.title.as_deref() {
            v.push((t.to_string(), px, Role::Title));
        }
        if let Some(d) = self.st.desc.as_deref() {
            for l in d.lines() {
                v.push((l.to_string(), small, Role::Body));
            }
        }
        if let Some(e) = self.st.error.as_deref() {
            v.push((e.to_string(), small, Role::Error));
        }
        if let Some(n) = self.note.as_deref() {
            v.push((n.to_string(), small, Role::Error));
        }
        v
    }

    /// The window size this prompt needs.
    fn size(&mut self) -> (u32, u32) {
        let px = FONT_PX;
        let small = px * 0.85;
        let lines = self.lines();

        let mut w = MIN_WIDTH as i32;
        for (text, size, _) in &lines {
            w = w.max(self.text.width(text, *size) + PAD * 2);
        }
        let w = (w as u32).clamp(MIN_WIDTH, MAX_WIDTH);

        let mut h = PAD;
        for (_, size, role) in &lines {
            h += (size * if *role == Role::Title { 2.0 } else { 1.6 }) as i32;
        }
        if matches!(self.ask, Ask::Pin) {
            // The field, and the count that sits under its right edge.
            h += (px * 2.0) as i32 + (small * 1.6) as i32;
        }
        // The hint line and the breathing room around it.
        h += (small * 2.2) as i32 + PAD;
        (w, h.max(96) as u32)
    }

    fn entered(&self) -> usize {
        if self.on_repeat {
            self.repeat_buf.as_ref().map(|s| s.chars()).unwrap_or(0)
        } else {
            self.secret.as_ref().map(|s| s.chars()).unwrap_or(0)
        }
    }

    fn push(&mut self, text: &str) {
        let target = if self.on_repeat {
            self.repeat_buf.as_mut()
        } else {
            self.secret.as_deref_mut()
        };
        if let Some(buf) = target {
            // `Secret::push` truncates in silence and documents that the front-end stops
            // before the capacity — kept here, so the buffer can never end mid-character
            // and leave the count claiming a letter that is not there.
            if buf.len() + text.len() <= buf.capacity() {
                buf.push(text.as_bytes());
            }
        }
    }

    fn backspace(&mut self) {
        if self.on_repeat {
            if let Some(b) = self.repeat_buf.as_mut() {
                b.pop_char();
            }
        } else if let Some(b) = self.secret.as_deref_mut() {
            b.pop_char();
        }
    }

    fn clear_entry(&mut self) {
        if self.on_repeat {
            if let Some(b) = self.repeat_buf.as_mut() {
                b.clear();
            }
        } else if let Some(b) = self.secret.as_deref_mut() {
            b.clear();
        }
    }

    /// Asks the window for the size the current content needs.
    ///
    /// The size is measured once in `resumed()`, but the content changes after that: the
    /// "they do not match" note adds a line. Without this the window kept its old height
    /// and everything below the note slid under the bottom edge — the field and the counter
    /// ended up on the hint line, at the exact moment the user had mistyped and most needed
    /// to be able to read the thing.
    fn resize_to_content(&mut self) {
        let (w, h) = self.size();
        if let Some(win) = self.window.as_ref() {
            let _ = win.request_inner_size(PhysicalSize::new(w, h));
        }
    }

    fn accept(&mut self) {
        match self.ask {
            Ask::Confirm { .. } => self.outcome = Some(Outcome::Ok),
            Ask::Pin => {
                if self.repeat_buf.is_none() {
                    self.outcome = Some(Outcome::Ok);
                    return;
                }
                if !self.on_repeat {
                    self.on_repeat = true;
                    let had_note = self.note.take().is_some();
                    if had_note {
                        self.resize_to_content();
                    }
                    return;
                }
                let agreed = match (self.secret.as_deref(), self.repeat_buf.as_ref()) {
                    // Constant time: the comparison is between a passphrase and its
                    // confirmation, and how long it takes should not say how far they agree.
                    (Some(a), Some(b)) => a.eq_constant_time(b),
                    _ => false,
                };
                if agreed {
                    self.outcome = Some(Outcome::Ok);
                } else {
                    self.note = Some(
                        self.st
                            .repeat_error
                            .clone()
                            .unwrap_or_else(|| "the two entries do not match".into()),
                    );
                    self.on_repeat = false;
                    if let Some(b) = self.secret.as_deref_mut() {
                        b.clear();
                    }
                    if let Some(b) = self.repeat_buf.as_mut() {
                        b.clear();
                    }
                    self.resize_to_content();
                }
            }
        }
    }

    fn draw(&mut self) {
        // Everything that needs to read `self` is read BEFORE the pixel buffer is borrowed:
        // the buffer holds a mutable borrow for as long as it is alive, and reaching back
        // into `self` through it is the one thing this layout cannot do.
        let entered = self.entered();
        let lines = self.lines();
        let (Some(win), Some(surface)) = (self.window.as_ref(), self.surface.as_mut()) else {
            return;
        };
        let size = win.inner_size();
        let (w, h) = (size.width.max(1), size.height.max(1));
        let (Some(nw), Some(nh)) = (NonZeroU32::new(w), NonZeroU32::new(h)) else {
            return;
        };
        if surface.resize(nw, nh).is_err() {
            return;
        }
        let Ok(mut buf) = surface.buffer_mut() else {
            return;
        };

        let t = self.theme;
        buf.fill(t.bg);

        let stride = w as usize;
        let height = h as usize;
        let px = FONT_PX;
        let small = px * 0.85;

        // A one-pixel frame, so the prompt reads as its own thing rather than as a patch of
        // colour floating over whatever is behind it.
        for x in 0..stride {
            buf[x] = t.border;
            buf[(height - 1) * stride + x] = t.border;
        }
        for row in 0..height {
            buf[row * stride] = t.border;
            buf[row * stride + stride - 1] = t.border;
        }

        let mut y = PAD + px as i32;
        for (text, size, role) in lines {
            let colour = match role {
                Role::Title => t.accent,
                Role::Body => t.fg,
                Role::Error => t.error,
            };
            self.text
                .draw(&mut buf, stride, height, PAD, y, &text, size, colour);
            y += (size * if role == Role::Title { 2.0 } else { 1.6 }) as i32;
        }

        if let Ask::Pin = self.ask {
            let label = if self.on_repeat {
                self.st.repeat.as_deref().unwrap_or("Repeat:")
            } else {
                self.st.prompt.as_deref().unwrap_or("Passphrase:")
            };
            let lw = self.text.width(label, small);
            self.text
                .draw(&mut buf, stride, height, PAD, y, label, small, t.dim);

            // The field, drawn as a sunken strip so it is obvious where the typing goes.
            let fx = PAD + lw + 12;
            let fy = y - px as i32;
            let fh = (px * 1.5) as i32;
            let fw = stride as i32 - fx - PAD;
            for row in fy.max(0)..(fy + fh).min(height as i32) {
                for col in fx.max(0)..(fx + fw).min(stride as i32) {
                    buf[row as usize * stride + col as usize] = t.field;
                }
            }

            // One mark per CHARACTER, and the count in words beside it. A mask that counts
            // bytes draws two marks for one Cyrillic keypress, and a passphrase typed in the
            // wrong keyboard layout then looks exactly like a right one. That silence is why
            // this program exists.
            let dots: String = std::iter::repeat_n('•', entered.min(80)).collect();
            self.text
                .draw(&mut buf, stride, height, fx + 8, y, &dots, small, t.fg);

            let count = format!("{entered} characters");
            let cw = self.text.width(&count, small * 0.8);
            self.text.draw(
                &mut buf,
                stride,
                height,
                stride as i32 - PAD - cw,
                y + (small * 1.5) as i32,
                &count,
                small * 0.8,
                t.dim,
            );
        }

        let hint = match self.ask {
            Ask::Confirm { one_button: true } => "enter  dismiss",
            Ask::Confirm { one_button: false } => {
                "enter  accept        n  decline        esc  cancel"
            }
            Ask::Pin => "enter  accept        esc  cancel        ctrl-u  clear",
        };
        self.text.draw(
            &mut buf,
            stride,
            height,
            PAD,
            height as i32 - PAD / 2 - 2,
            hint,
            small * 0.8,
            t.dim,
        );

        let _ = buf.present();
    }
}

impl App<'_> {
    /// Puts the window up if it is not up already.
    ///
    /// Called from `new_events`, which fires on every pump, and not only from `resumed`.
    /// winit emits `Resumed` exactly once per EVENT LOOP, on `StartCause::Init`, and the
    /// loop now outlives the prompt — it has to, because winit permits only one per process.
    /// Creating the window from `resumed` alone therefore left the second `GETPIN` of a
    /// connection — the retry after a wrong passphrase — spinning forever on a window
    /// nobody was ever going to be asked to create.
    fn ensure_window(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() || self.outcome.is_some() {
            return;
        }
        let (w, h) = self.size();
        let size = PhysicalSize::new(w, h);
        let attrs = Window::default_attributes()
            .with_title("ward")
            .with_inner_size(size)
            .with_resizable(false)
            // Asking to be on top and focused. X11 obeys; a Wayland compositor decides for
            // itself, and there is no protocol by which an ordinary client can insist.
            .with_window_level(WindowLevel::AlwaysOnTop)
            .with_active(true);

        // No placement request. A Wayland client is not permitted to position its own
        // surface — `xdg_toplevel` has no such request, so the compositor stays in charge of
        // layout — and asking on X11 alone would mean the same setting behaved differently
        // depending on which session you happened to be in. Better that the compositor
        // decides everywhere than that it decides half the time.

        // Failing here is not a refusal. The probe already found a display, so this is the
        // compositor going away between the probe and the window, or a surface that cannot
        // be drawn on — nobody was asked. Reporting it as `Cancelled` told the agent the
        // user had declined a prompt they never saw.
        let Ok(win) = event_loop.create_window(attrs) else {
            self.outcome = Some(Outcome::Unavailable);
            return;
        };
        let win = Rc::new(win);
        match softbuffer::Context::new(win.clone())
            .and_then(|ctx| softbuffer::Surface::new(&ctx, win.clone()))
        {
            Ok(surface) => {
                self.surface = Some(surface);
                self.window = Some(win);
                self.draw();
            }
            Err(e) => {
                eprintln!("ward: no drawable surface: {e}");
                self.outcome = Some(Outcome::Unavailable);
            }
        }
    }
}

impl ApplicationHandler for App<'_> {
    fn new_events(&mut self, event_loop: &ActiveEventLoop, _cause: StartCause) {
        self.ensure_window(event_loop);
    }

    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        self.ensure_window(event_loop);
    }

    fn window_event(
        &mut self,
        _el: &ActiveEventLoop,
        _id: winit::window::WindowId,
        ev: WindowEvent,
    ) {
        match ev {
            WindowEvent::CloseRequested => {
                // Closing the window is a refusal, not a mistake to be ignored — and it is
                // reported as cancellation rather than as an empty passphrase.
                self.outcome = Some(Outcome::Cancelled);
            }
            WindowEvent::RedrawRequested => self.draw(),
            WindowEvent::KeyboardInput { event, .. } => {
                if event.state != ElementState::Pressed {
                    return;
                }
                match event.logical_key.as_ref() {
                    Key::Named(NamedKey::Enter) => self.accept(),
                    // Escape is cancellation everywhere, as it already is in the terminal.
                    // It used to mean NotOk here and Cancelled there, so the same gesture
                    // produced ERR NOT_CONFIRMED or ERR CANCELED depending on which
                    // front-end happened to be picked — and gpg acts on the difference.
                    // Declining now has its own key, below.
                    Key::Named(NamedKey::Escape) => self.outcome = Some(Outcome::Cancelled),
                    Key::Named(NamedKey::Backspace) => self.backspace(),
                    _ => {
                        // `text` is what the layout produced, not which key was struck.
                        // Taking it from the keycode instead is how a program ends up
                        // storing Latin letters while the user is typing Cyrillic — the
                        // exact class of failure that created this project.
                        if let Some(s) = event.text.as_ref() {
                            let ctrl = s.chars().all(|c| (c as u32) < 0x20);
                            if ctrl {
                                // Ctrl-U, the usual "clear the field".
                                if s.chars().any(|c| c as u32 == 0x15) {
                                    self.clear_entry();
                                }
                            } else if matches!(self.ask, Ask::Pin) {
                                // Straight from winit's inline string into locked memory.
                                // The `to_string()` that used to stand here made a heap copy
                                // of every keystroke that nothing ever wiped, and it was not
                                // even working around a borrow: `s` borrows the event.
                                self.push(s);
                            } else if matches!(self.ask, Ask::Confirm { one_button: false }) {
                                // The same letters the terminal takes, so a CONFIRM answers
                                // identically whichever front-end the user got.
                                match s.chars().next() {
                                    Some('y' | 'Y') => self.outcome = Some(Outcome::Ok),
                                    Some('n' | 'N') => self.outcome = Some(Outcome::NotOk),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                if let Some(w) = self.window.as_ref() {
                    w.request_redraw();
                }
            }
            _ => {}
        }
    }
}

impl Frontend for GuiFrontend {
    fn getpin(&mut self, st: &State, into: &mut Secret) -> std::io::Result<Outcome> {
        let repeat_buf = if st.repeat.is_some() {
            Some(Secret::with_capacity(into.capacity())?)
        } else {
            None
        };
        let deadline = st
            .timeout_secs
            .filter(|s| *s > 0)
            .map(|s| Instant::now() + Duration::from_secs(s));

        // Named separately so the borrow checker can see that the event loop and the glyph
        // cache are different fields; through `self` it would treat them as one borrow.
        let GuiFrontend {
            events,
            theme,
            text,
        } = self;
        let app = App {
            theme,
            st,
            text,
            ask: Ask::Pin,
            secret: Some(into),
            repeat_buf,
            on_repeat: false,
            note: None,
            window: None,
            surface: None,
            outcome: None,
            deadline,
        };
        Ok(Self::run(events, app))
    }

    fn confirm(&mut self, st: &State, one_button: bool) -> std::io::Result<Outcome> {
        let deadline = st
            .timeout_secs
            .filter(|s| *s > 0)
            .map(|s| Instant::now() + Duration::from_secs(s));
        let GuiFrontend {
            events,
            theme,
            text,
        } = self;
        let app = App {
            theme,
            st,
            text,
            ask: Ask::Confirm { one_button },
            secret: None,
            repeat_buf: None,
            on_repeat: false,
            note: None,
            window: None,
            surface: None,
            outcome: None,
            deadline,
        };
        Ok(Self::run(events, app))
    }

    fn message(&mut self, st: &State) -> std::io::Result<()> {
        self.confirm(st, true).map(|_| ())
    }
}
