//! The prompt: what a person sees when an application asks for
//! administrator access.
//!
//! A card in the suite's look, centred on the monitor the pointer is on,
//! holding the keyboard for as long as it is up — a password typed while
//! it is open must never land in the window behind it. Its parts, top to
//! bottom: what is being asked for (polkit's own `message`, which the
//! action's author wrote for people), who is answering (the person at
//! the session first; arrows when polkit allows others), the field, a
//! line for what PAM last said, and Cancel / Authenticate.
//!
//! Three rules from the suite's CLAUDE.md shape the input handling:
//!
//! - **What was typed is `text`, never `key`.** The keysym is only read
//!   to recognise Enter, Escape, Backspace and the arrows; a character
//!   comes from the text the press produced, so Shift and AltGr give the
//!   character the person meant and PAM sees the password they typed.
//! - **Nothing derived from a keystroke is logged.** The field is a
//!   `Secret`; its Debug is a length.
//! - **The thing drawn and the thing hit-tested are one layout.**
//!   [`Layout`] is read by both [`view`] and [`PromptApp::pointer_click`].

use crate::conversation::{Did, Shown};
use hyprforge_look::Theme;
use hyprforge_popup::kit::{self, Look};
use hyprforge_popup::{Dismissal, Keysym, Modifiers, PopupApp, Receives};
use hyprforge_secret::Secret;
use iced_runtime::core::alignment::{Horizontal, Vertical};
use iced_runtime::core::text::Wrapping;
use iced_runtime::core::{Border, Element, Length, Padding};
use iced_widget::{column, container, row, text, Space};
use std::convert::Infallible;
use tokio::sync::mpsc::UnboundedSender;

/// What the request is, as polkit described it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// polkit's sentence for people: "Authentication is required to …".
    pub message: String,
    /// `org.freedesktop.udisks2.filesystem-mount`, for whoever wants to
    /// know exactly what they are allowing.
    pub action_id: String,
    /// The identities that may answer, in the order to offer them.
    pub users: Vec<String>,
}

/// Everything the prompt shows, and nothing it does not.
#[derive(Debug)]
pub struct Model {
    pub request: Request,
    /// Which of `request.users` is answering.
    pub user: usize,
    field: Secret<String>,
    /// PAM's current question, if it has asked one — `None` while
    /// pam_fprintd is waiting for a finger, which is exactly when the
    /// field must say so rather than look broken.
    asking: Option<(String, bool)>,
    /// What PAM last said: an error, or something to know.
    said: Option<Said>,
    checking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Said {
    Info(String),
    Error(String),
}

/// What a key press or a click asks the conversation to do.
#[derive(Debug)]
pub enum Action {
    Answer(Secret<String>),
    SwitchTo(String),
    Cancel,
}

impl Model {
    pub fn new(request: Request) -> Model {
        Model {
            request,
            user: 0,
            field: Secret::new(String::new()),
            asking: None,
            said: None,
            checking: false,
        }
    }

    pub fn user(&self) -> &str {
        self.request.users.get(self.user).map(String::as_str).unwrap_or("")
    }

    /// How many characters are in the field — all that is ever exposed
    /// about it outside [`Self::submit`].
    pub fn typed(&self) -> usize {
        self.field.expose().chars().count()
    }

    /// The conversation moved on.
    pub fn shown(&mut self, shown: Shown) {
        match shown {
            Shown::Ask { text, echo } => {
                self.asking = Some((text, echo));
                self.checking = false;
            }
            Shown::Info(text) => self.said = Some(Said::Info(text)),
            Shown::Error(text) => self.said = Some(Said::Error(text)),
            Shown::Checking => self.checking = true,
            // The helper's own error line ("Authentication failure")
            // already said why; a try that failed with nothing said
            // still needs a sentence.
            Shown::TryAgain => {
                self.checking = false;
                self.asking = None;
                self.field = Secret::new(String::new());
                if !matches!(self.said, Some(Said::Error(_))) {
                    self.said = Some(Said::Error("That didn't work. Try again.".into()));
                }
            }
        }
    }

    /// Whether Authenticate would do anything now.
    pub fn can_submit(&self) -> bool {
        self.asking.is_some() && !self.checking
    }

    fn submit(&mut self) -> Option<Action> {
        if !self.can_submit() {
            return None;
        }
        // Moved out, not copied: the field starts empty again and the
        // only copy of the answer goes to the helper.
        let answer = std::mem::replace(&mut self.field, Secret::new(String::new()));
        self.said = None;
        Some(Action::Answer(answer))
    }

    fn switch(&mut self, by: isize) -> Option<Action> {
        let count = self.request.users.len();
        if count < 2 || self.checking {
            return None;
        }
        self.user = (self.user as isize + by).rem_euclid(count as isize) as usize;
        self.asking = None;
        self.said = None;
        self.field = Secret::new(String::new());
        Some(Action::SwitchTo(self.user().to_owned()))
    }

    /// One key press: `keysym` for the keys that are not text, `utf8`
    /// for what it typed.
    pub fn key(&mut self, keysym: Keysym, utf8: Option<&str>) -> Option<Action> {
        match keysym {
            Keysym::Return | Keysym::KP_Enter => return self.submit(),
            Keysym::Escape => return Some(Action::Cancel),
            Keysym::BackSpace => {
                if !self.checking {
                    let mut kept = self.field.expose().clone();
                    kept.pop();
                    self.field = Secret::new(kept);
                }
                return None;
            }
            Keysym::Up | Keysym::Left if self.typed() == 0 => return self.switch(-1),
            Keysym::Down | Keysym::Right if self.typed() == 0 => return self.switch(1),
            _ => {}
        }
        // Enter, Escape and Backspace produce text of their own
        // ("\r", "\u{1b}", "\u{8}") and must never reach a password; a
        // control character of any kind is not something typed.
        let typed: String = utf8.unwrap_or("").chars().filter(|c| !c.is_control()).collect();
        if !typed.is_empty() && !self.checking {
            let mut longer = self.field.expose().clone();
            longer.push_str(&typed);
            self.field = Secret::new(longer);
        }
        None
    }
}

/// Where everything is, in logical pixels — read by the drawing and the
/// hit-testing alike.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Layout {
    pub width: f64,
    pub height: f64,
    pub padding: f64,
    pub title: f64,
    pub message: f64,
    pub user: f64,
    pub field: f64,
    pub said: f64,
    pub buttons: f64,
    pub gap: f64,
}

/// A rectangle, for hit-testing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

impl Rect {
    pub fn contains(&self, (x, y): (f64, f64)) -> bool {
        x >= self.x && x < self.x + self.w && y >= self.y && y < self.y + self.h
    }
}

pub const WIDTH: f64 = 440.0;
const BUTTON_W: f64 = 120.0;
const BUTTON_GAP: f64 = 8.0;
const ARROW_W: f64 = 28.0;

impl Layout {
    /// The layout for a message `message_lines` lines tall at
    /// `font_size`. The line count is measured by the caller (see
    /// `crate::fit`), because only the shaper knows where a sentence wraps.
    pub fn new(font_size: f32, message_lines: usize) -> Layout {
        let f = f64::from(font_size);
        let line = f * 1.35;
        let mut layout = Layout {
            width: WIDTH,
            height: 0.0,
            padding: 20.0,
            title: (f * 1.25 * 1.35).ceil(),
            message: (line * message_lines.clamp(1, 4) as f64).ceil(),
            user: (f * 2.4).ceil(),
            field: (f * 2.5).ceil(),
            said: line.ceil(),
            buttons: (f * 2.4).ceil(),
            gap: 12.0,
        };
        layout.height = layout.padding * 2.0
            + layout.title
            + 6.0
            + layout.message
            + layout.gap
            + layout.user
            + layout.gap
            + layout.field
            + 6.0
            + layout.said
            + layout.gap
            + layout.buttons;
        layout
    }

    fn inner(&self) -> f64 {
        self.width - self.padding * 2.0
    }

    fn user_top(&self) -> f64 {
        self.padding + self.title + 6.0 + self.message + self.gap
    }

    fn buttons_top(&self) -> f64 {
        self.height - self.padding - self.buttons
    }

    /// Authenticate, at the right; Cancel to its left.
    pub fn authenticate(&self) -> Rect {
        Rect { x: self.width - self.padding - BUTTON_W, y: self.buttons_top(), w: BUTTON_W, h: self.buttons }
    }

    pub fn cancel(&self) -> Rect {
        Rect { x: self.width - self.padding - BUTTON_W * 2.0 - BUTTON_GAP, y: self.buttons_top(), w: BUTTON_W, h: self.buttons }
    }

    /// The arrows either side of the name, when there is a choice.
    pub fn previous_user(&self) -> Rect {
        Rect { x: self.padding, y: self.user_top(), w: ARROW_W, h: self.user }
    }

    pub fn next_user(&self) -> Rect {
        Rect { x: self.padding + self.inner() - ARROW_W, y: self.user_top(), w: ARROW_W, h: self.user }
    }
}

/// What a running prompt is told from outside.
#[derive(Debug)]
pub enum Message {
    Shown(Shown),
    /// The authentication ended — by success, by the caller cancelling,
    /// or by the helper breaking. Closes the prompt.
    End,
}

/// The prompt, as a popup: the model, plus the line back to the
/// conversation.
pub struct PromptApp {
    pub model: Model,
    layout: Layout,
    did: UnboundedSender<Did>,
    hovered: Option<Button>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Button {
    Cancel,
    Authenticate,
}

/// How a prompt ended — only ever because it was told to, or because the
/// person cancelled (which the conversation has already been told).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

impl PromptApp {
    pub fn new(model: Model, layout: Layout, did: UnboundedSender<Did>) -> PromptApp {
        PromptApp { model, layout, did, hovered: None }
    }

    /// Carries out an action: tells the conversation, and closes the
    /// prompt on Cancel.
    fn act(&mut self, action: Option<Action>) -> Option<Closed> {
        match action? {
            Action::Answer(answer) => {
                let _ = self.did.send(Did::Answer(answer));
                None
            }
            Action::SwitchTo(user) => {
                let _ = self.did.send(Did::SwitchTo(user));
                None
            }
            Action::Cancel => {
                let _ = self.did.send(Did::Cancel);
                Some(Closed)
            }
        }
    }

    fn button_at(&self, position: (f64, f64)) -> Option<Button> {
        if self.layout.cancel().contains(position) {
            Some(Button::Cancel)
        } else if self.layout.authenticate().contains(position) {
            Some(Button::Authenticate)
        } else {
            None
        }
    }
}

impl PopupApp for PromptApp {
    type Outcome = Closed;

    fn view<'a>(&'a mut self, theme: &'a Theme, _now: u64, _width: f64) -> Element<'a, Infallible, iced_widget::Theme, iced_tiny_skia::Renderer> {
        view(&self.model, &self.layout, &Look::new(theme), self.hovered)
    }

    fn rows_that_fit(&self, _theme: &Theme, _height: f64) -> usize {
        1
    }

    fn pointer_move(&mut self, _theme: &Theme, position: (f64, f64)) -> bool {
        let hovered = self.button_at(position);
        let changed = hovered != self.hovered;
        self.hovered = hovered;
        changed
    }

    fn pointer_click(&mut self, _theme: &Theme, _width: f64, position: (f64, f64)) -> Option<Closed> {
        let action = match self.button_at(position) {
            Some(Button::Cancel) => Some(Action::Cancel),
            Some(Button::Authenticate) => self.model.submit(),
            None if self.layout.previous_user().contains(position) => self.model.switch(-1),
            None if self.layout.next_user().contains(position) => self.model.switch(1),
            None => None,
        };
        self.act(action)
    }

    fn pointer_scroll(&mut self, _rows: i32) {}

    fn key(&mut self, keysym: Keysym, utf8: Option<String>, _modifiers: Modifiers) -> Option<Closed> {
        let action = self.model.key(keysym, utf8.as_deref());
        self.act(action)
    }

    fn dismissal(&self) -> Dismissal {
        Dismissal::HoldKeyboard
    }

    fn needs_finish(_outcome: Closed) -> bool {
        false
    }

    fn finish(&mut self, _outcome: Closed) {}
}

impl Receives<Message> for PromptApp {
    fn receive(&mut self, message: Message) -> Option<Closed> {
        match message {
            Message::Shown(shown) => {
                self.model.shown(shown);
                None
            }
            Message::End => Some(Closed),
        }
    }
}

fn alpha(c: iced_runtime::core::Color, a: f32) -> iced_runtime::core::Color {
    iced_runtime::core::Color { a, ..c }
}

type El<'a> = Element<'a, Infallible, iced_widget::Theme, iced_tiny_skia::Renderer>;

/// The card.
pub(crate) fn view<'a>(model: &'a Model, layout: &Layout, look: &Look, hovered: Option<Button>) -> El<'a> {
    let look = *look;
    let f = look.font_size;

    let title: El = text("Authentication required").size(f * 1.25).font(kit::strong()).color(look.text).into();
    let message: El = container(text(model.request.message.as_str()).size(f).color(look.dim).wrapping(Wrapping::Word))
        .height(Length::Fixed(layout.message as f32))
        .clip(true)
        .into();

    // Who is answering: an initial in the accent, the name, and arrows
    // when polkit allows more than one.
    let several = model.request.users.len() > 1;
    let initial = model.user().chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default();
    let side = (layout.user * 0.8) as f32;
    let avatar = container(text(initial).size(f).font(kit::strong()).color(look.on_accent))
        .width(Length::Fixed(side))
        .height(Length::Fixed(side))
        .align_x(Horizontal::Center)
        .align_y(Vertical::Center)
        .style(move |_: &iced_widget::Theme| container::Style {
            background: Some(look.accent.into()),
            border: Border { radius: (side / 2.0).into(), ..Default::default() },
            ..Default::default()
        });
    let arrow = |glyph: &'static str| -> El {
        let label: El = if several { text(glyph).size(f * 1.2).color(look.dim).into() } else { Space::new().into() };
        container(label)
            .width(Length::Fixed(ARROW_W as f32))
            .height(Length::Fixed(layout.user as f32))
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center)
            .into()
    };
    let who = row![
        arrow("\u{2039}"),
        Space::new().width(Length::Fill),
        avatar,
        text(model.user().to_owned()).size(f).color(look.text),
        Space::new().width(Length::Fill),
        arrow("\u{203a}"),
    ]
    .spacing(10)
    .align_y(Vertical::Center)
    .height(Length::Fixed(layout.user as f32));

    // The field: dots for a password, the text for an echoed answer, and
    // what PAM is doing when it has not asked yet.
    let (shown, colour) = match &model.asking {
        None => ("Waiting\u{2026}".to_string(), look.dim),
        Some(_) if model.checking => ("Checking\u{2026}".to_string(), look.dim),
        Some((prompt, _)) if model.typed() == 0 => (prompt.trim().trim_end_matches(':').to_string(), look.dim),
        Some((_, true)) => (model.field.expose().clone(), look.text),
        Some((_, false)) => ("\u{2022}".repeat(model.typed()), look.text),
    };
    let field_h = layout.field;
    let radius = look.radius_for(field_h, 8.0);
    let field = container(text(shown).size(f).color(colour).wrapping(Wrapping::None))
        .width(Length::Fill)
        .height(Length::Fixed(field_h as f32))
        .padding(Padding { top: 0.0, right: 12.0, bottom: 0.0, left: 12.0 })
        .align_y(Vertical::Center)
        .clip(true)
        .style(move |_: &iced_widget::Theme| container::Style {
            background: Some(alpha(look.inset, 0.6).into()),
            border: Border { radius: radius.into(), width: 1.0, color: look.accent },
            ..Default::default()
        });

    let said: El = match &model.said {
        Some(Said::Error(t)) => text(t.as_str()).size(look.small()).color(look.error).wrapping(Wrapping::None).into(),
        Some(Said::Info(t)) => text(t.as_str()).size(look.small()).color(look.info).wrapping(Wrapping::None).into(),
        None => Space::new().into(),
    };
    let said = container(said).height(Length::Fixed(layout.said as f32)).clip(true);

    let button = |label: &'static str, primary: bool, hot: bool, enabled: bool| -> El {
        let h = layout.buttons;
        let r = look.radius_for(h, 8.0);
        let fill = match (primary, enabled) {
            (true, true) => Some(if hot { alpha(look.accent, 0.85) } else { look.accent }),
            (true, false) => Some(alpha(look.accent, 0.35)),
            (false, _) => hot.then_some(look.selected),
        };
        let fg = if primary { look.on_accent } else { look.text };
        container(text(label).size(f).color(fg))
            .width(Length::Fixed(BUTTON_W as f32))
            .height(Length::Fixed(h as f32))
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center)
            .style(move |_: &iced_widget::Theme| container::Style {
                background: fill.map(Into::into),
                border: Border { radius: r.into(), width: if primary { 0.0 } else { 1.0 }, color: look.inset_border },
                ..Default::default()
            })
            .into()
    };
    let buttons = row![
        Space::new().width(Length::Fill),
        button("Cancel", false, hovered == Some(Button::Cancel), true),
        button("Authenticate", true, hovered == Some(Button::Authenticate), model.can_submit()),
    ]
    .spacing(BUTTON_GAP as f32)
    .height(Length::Fixed(layout.buttons as f32));

    let body = column![
        title,
        Space::new().height(Length::Fixed(6.0)),
        message,
        Space::new().height(Length::Fixed(layout.gap as f32)),
        who,
        Space::new().height(Length::Fixed(layout.gap as f32)),
        field,
        Space::new().height(Length::Fixed(6.0)),
        said,
        Space::new().height(Length::Fixed(layout.gap as f32)),
        buttons,
    ]
    .padding(layout.padding as f32);
    kit::frame(body, &look)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(users: &[&str]) -> Model {
        Model::new(Request {
            message: "Authentication is required to mount the disk".into(),
            action_id: "org.freedesktop.udisks2.filesystem-mount".into(),
            users: users.iter().map(|s| s.to_string()).collect(),
        })
    }

    fn asked(m: &mut Model) {
        m.shown(Shown::Ask { text: "Password: ".into(), echo: false });
    }

    fn typed(m: &mut Model, s: &str) {
        for c in s.chars() {
            m.key(Keysym::NoSymbol, Some(&c.to_string()));
        }
    }

    fn answer_of(action: Option<Action>) -> String {
        match action {
            Some(Action::Answer(secret)) => secret.expose().clone(),
            other => panic!("expected an answer, got {other:?}"),
        }
    }

    /// The character comes from the text the press produced, so Shift
    /// gives the capital the person meant — the bug CLAUDE.md records,
    /// where reading the keysym lost every capital and symbol.
    #[test]
    fn what_is_typed_is_the_text_not_the_key() {
        let mut m = model(&["alex"]);
        asked(&mut m);
        m.key(Keysym::j, Some("J"));
        m.key(Keysym::_1, Some("!"));
        assert_eq!(answer_of(m.key(Keysym::Return, Some("\r"))), "J!");
    }

    /// Enter, Escape and Backspace carry text of their own; none of it
    /// may reach a password.
    #[test]
    fn control_keys_never_type_into_the_password() {
        let mut m = model(&["alex"]);
        asked(&mut m);
        typed(&mut m, "ab");
        m.key(Keysym::BackSpace, Some("\u{8}"));
        m.key(Keysym::Tab, Some("\t"));
        assert_eq!(answer_of(m.key(Keysym::Return, Some("\r"))), "a");
    }

    /// Nothing to answer, nothing sent: Enter before PAM has asked (while
    /// a fingerprint reader waits) or while it is checking does nothing.
    #[test]
    fn enter_answers_only_a_question_that_is_waiting() {
        let mut m = model(&["alex"]);
        typed(&mut m, "early");
        assert!(m.key(Keysym::Return, None).is_none(), "not asked yet");
        asked(&mut m);
        assert!(matches!(m.key(Keysym::Return, None), Some(Action::Answer(_))));
        m.shown(Shown::Checking);
        typed(&mut m, "x");
        assert_eq!(m.typed(), 0, "nothing is typed while checking");
        assert!(m.key(Keysym::Return, None).is_none());
    }

    #[test]
    fn a_failed_try_empties_the_field_and_says_so() {
        let mut m = model(&["alex"]);
        asked(&mut m);
        typed(&mut m, "wrong");
        m.key(Keysym::Return, None);
        m.shown(Shown::Checking);
        m.shown(Shown::TryAgain);
        assert_eq!(m.typed(), 0);
        assert!(matches!(m.said, Some(Said::Error(_))));
        assert!(!m.can_submit(), "until the next question arrives");
    }

    /// The model's Debug is how a panic or a log would show it, and it
    /// must not hold the password.
    #[test]
    fn the_model_never_prints_what_was_typed() {
        let mut m = model(&["alex"]);
        asked(&mut m);
        typed(&mut m, "hunter2");
        assert!(!format!("{m:?}").contains("hunter2"));
    }

    #[test]
    fn the_arrows_switch_identity_only_when_there_is_a_choice() {
        let mut one = model(&["alex"]);
        assert!(one.key(Keysym::Right, None).is_none());
        let mut two = model(&["alex", "root"]);
        assert!(matches!(two.key(Keysym::Right, None), Some(Action::SwitchTo(u)) if u == "root"));
        assert!(matches!(two.key(Keysym::Right, None), Some(Action::SwitchTo(u)) if u == "alex"), "wraps");
    }

    /// The buttons a click finds are where the card draws them: inside
    /// the card, side by side, Authenticate on the right.
    #[test]
    fn the_buttons_are_inside_the_card_and_do_not_overlap() {
        let l = Layout::new(14.0, 2);
        let (c, a) = (l.cancel(), l.authenticate());
        assert!(c.x + c.w <= a.x);
        assert!(a.x + a.w <= l.width - l.padding + 0.01);
        assert!(a.y + a.h <= l.height - l.padding + 0.01);
        assert!(a.y > l.user_top());
    }

    /// Draws the card to `$SHOTS/<name>.png` in a few states, to look at.
    /// Ignored: it renders, it asserts nothing.
    #[test]
    #[ignore]
    fn render_the_card() {
        use iced_runtime::core::{renderer::Style, Color, Rectangle, Size};
        use iced_runtime::user_interface::{Cache, UserInterface};
        let dir = std::path::PathBuf::from(std::env::var("SHOTS").expect("SHOTS"));
        let mut theme = hyprforge_look::Theme::load(std::path::Path::new(&std::env::var("SHOTS_THEME").expect("SHOTS_THEME"))).unwrap();
        theme.font_size = theme.drawable_font_size();
        let look = Look::new(&theme);
        let scale = 1.6f32;
        let states: Vec<(&str, Box<dyn Fn(&mut Model)>)> = vec![
            ("asking", Box::new(|m: &mut Model| { asked(m); typed(m, "hunter2"); })),
            ("fingerprint", Box::new(|m: &mut Model| m.shown(Shown::Info("Place your finger on the fingerprint reader".into())))),
            ("failed", Box::new(|m: &mut Model| { asked(m); m.shown(Shown::Error("Authentication failure".into())); m.shown(Shown::TryAgain); asked(m); })),
        ];
        for (name, set) in states {
            let mut m = model(&["alex", "root"]);
            m.request.message = "Authentication is required to mount SanDisk Ultra (/dev/sda1)".into();
            set(&mut m);
            let layout = Layout::new(theme.font_size, 2);
            let (w, h) = (layout.width as f32, layout.height as f32);
            let (pw, ph) = ((w * scale).round() as u32, (h * scale).round() as u32);
            let mut renderer = iced_tiny_skia::Renderer::new(iced_runtime::core::Font::DEFAULT, iced_runtime::core::Pixels(theme.font_size));
            let size = Size::new(w, h);
            let mut ui = UserInterface::<Infallible, iced_widget::Theme, iced_tiny_skia::Renderer>::build(view(&m, &layout, &look, None), size, Cache::default(), &mut renderer);
            ui.draw(&mut renderer, &iced_widget::Theme::Dark, &Style { text_color: Color::WHITE }, iced_runtime::core::mouse::Cursor::Unavailable);
            let mut pixmap = tiny_skia::Pixmap::new(pw, ph).unwrap();
            let mut mask = tiny_skia::Mask::new(pw, ph).unwrap();
            renderer.draw(&mut pixmap.as_mut(), &mut mask, &iced_tiny_skia::graphics::Viewport::with_physical_size(Size::new(pw, ph), scale), &[Rectangle::with_size(size)], Color::TRANSPARENT);
            // Only now: the drawn text holds weak references to paragraphs
            // the UI tree owns, so dropping it first draws no text at all.
            drop(ui);
            // iced_tiny_skia writes BGRA, for Wayland; a PNG wants RGBA.
            for px in pixmap.data_mut().chunks_exact_mut(4) {
                px.swap(0, 2);
            }
            pixmap.save_png(dir.join(format!("{name}.png"))).unwrap();
        }
    }
}
