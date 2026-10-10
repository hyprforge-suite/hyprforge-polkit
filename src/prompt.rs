//! The prompt: what a person sees when an application asks for
//! administrator access.
//!
//! It is the lock screen's card. The panel, the avatar, the name, the
//! field of dots and the line under it — layout and Caps Lock, or what
//! went wrong — are drawn by `hyprforge-authui`'s own `card_body` and
//! `glass_panel`, not a copy of them, so the two prompts for a password
//! on this desktop cannot drift apart. What a polkit prompt needs beyond
//! the lock's is above and below the card's body: what is being asked
//! for, in polkit's own words (the action's author wrote them for
//! people), and Cancel / Authenticate.
//!
//! The state the card is drawn from is authui's own conversation state,
//! so it behaves as the lock does too: a failure stays on screen until
//! the person starts typing again, and checking keeps the dots that were
//! sent.
//!
//! Three rules from the suite's CLAUDE.md shape the input handling:
//!
//! - **What was typed is `text`, never `key`.** The keysym is only read
//!   to recognise Enter, Escape, Backspace and the arrows; a character
//!   comes from the text the press produced, so Shift and AltGr give the
//!   character the person meant and PAM sees the password they typed.
//! - **Nothing derived from a keystroke is logged.** What was typed is a
//!   `Secret`, inside authui's `State`; its Debug is a length.
//! - **The thing drawn and the thing hit-tested are one layout.**
//!   [`Layout`] is read by both [`view`] and [`PromptApp::pointer_click`].

use crate::conversation::{Did, Shown};
use hyprforge_authui::conversation::{Prompt, State};
use hyprforge_authui::scene::{self, Scene};
use hyprforge_authui::screen;
use hyprforge_look::Theme;
use hyprforge_popup::kit::to_iced;
use hyprforge_popup::{Dismissal, Keysym, Modifiers, PopupApp, Receives};
use hyprforge_secret::Secret;
use iced_runtime::core::alignment::{Horizontal, Vertical};
use iced_runtime::core::font::Weight;
use iced_runtime::core::text::Wrapping;
use iced_runtime::core::{Border, Color, Element, Font, Length, Padding};
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

/// Everything the prompt shows.
#[derive(Debug)]
pub struct Model {
    pub request: Request,
    /// Which of `request.users` is answering.
    pub user: usize,
    /// What the card draws: authui's conversation state.
    state: State,
    /// PAM's open question, kept while a failure is still on screen so
    /// the first character typed can reopen it.
    prompt: Option<Prompt>,
    /// How many dots to keep showing while an answer is checked.
    submitted: usize,
    pub caps_lock: bool,
}

/// What a key press or a click asks the conversation to do.
#[derive(Debug)]
pub enum Action {
    Answer(Secret<String>),
    SwitchTo(String),
    Cancel,
}

const TRY_AGAIN: &str = "That didn't work. Try again.";

impl Model {
    pub fn new(request: Request) -> Model {
        Model { request, user: 0, state: State::Working, prompt: None, submitted: 0, caps_lock: false }
    }

    pub fn user(&self) -> &str {
        self.request.users.get(self.user).map(String::as_str).unwrap_or("")
    }

    #[cfg(test)]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// How many characters have been typed — all that is ever exposed
    /// about the answer outside [`Self::submit`].
    pub fn typed(&self) -> usize {
        match &self.state {
            State::Asking { entered, .. } => entered.expose().chars().count(),
            _ => 0,
        }
    }

    /// The conversation moved on.
    pub fn shown(&mut self, shown: Shown) {
        match shown {
            Shown::Ask { text, echo } => {
                let prompt = Prompt { text, secret: !echo };
                self.prompt = Some(prompt.clone());
                // A failure stays until the person types, as on the lock.
                if !matches!(self.state, State::Failed { .. }) {
                    self.state = State::Asking { prompt, entered: Secret::new(String::new()) };
                }
            }
            // Said while nothing is being asked — pam_fprintd's "Place
            // your finger…". While a question is open the field is the
            // thing to look at, and the line under it shows Caps Lock.
            Shown::Info(text) => {
                if !matches!(self.state, State::Asking { .. }) {
                    self.state = State::Telling { text, error: false };
                }
            }
            Shown::Error(reason) => self.state = State::Failed { reason },
            Shown::Checking => self.state = State::Working,
            Shown::TryAgain => {
                self.prompt = None;
                if !matches!(self.state, State::Failed { .. }) {
                    self.state = State::Failed { reason: TRY_AGAIN.into() };
                }
            }
        }
    }

    /// Whether Authenticate would do anything now.
    pub fn can_submit(&self) -> bool {
        matches!(self.state, State::Asking { .. })
    }

    fn submit(&mut self) -> Option<Action> {
        if !self.can_submit() {
            return None;
        }
        // Moved out, not copied: the only copy of the answer goes to the
        // helper, and the card shows dots for it while it is checked.
        let State::Asking { entered, .. } = std::mem::replace(&mut self.state, State::Working) else {
            return None;
        };
        self.submitted = entered.expose().chars().count();
        Some(Action::Answer(entered))
    }

    fn switch(&mut self, by: isize) -> Option<Action> {
        let count = self.request.users.len();
        if count < 2 || matches!(self.state, State::Working) && self.prompt.is_some() {
            return None;
        }
        self.user = (self.user as isize + by).rem_euclid(count as isize) as usize;
        self.prompt = None;
        self.state = State::Working;
        Some(Action::SwitchTo(self.user().to_owned()))
    }

    fn type_text(&mut self, typed: &str) {
        match &mut self.state {
            State::Asking { entered, .. } => {
                let mut longer = entered.expose().clone();
                longer.push_str(typed);
                *entered = Secret::new(longer);
            }
            // Typing again is what takes a failure off the screen.
            State::Failed { .. } => {
                if let Some(prompt) = self.prompt.clone() {
                    self.state = State::Asking { prompt, entered: Secret::new(typed.to_owned()) };
                }
            }
            _ => {}
        }
    }

    /// One key press: `keysym` for the keys that are not text, `utf8`
    /// for what it typed.
    pub fn key(&mut self, keysym: Keysym, utf8: Option<&str>) -> Option<Action> {
        match keysym {
            Keysym::Return | Keysym::KP_Enter => return self.submit(),
            Keysym::Escape => return Some(Action::Cancel),
            Keysym::BackSpace => {
                if let State::Asking { entered, .. } = &mut self.state {
                    let mut kept = entered.expose().clone();
                    kept.pop();
                    *entered = Secret::new(kept);
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
        if !typed.is_empty() {
            self.type_text(&typed);
        }
        None
    }
}

/// Where everything is, in logical pixels on the popup's surface — read
/// by the drawing and the hit-testing alike.
///
/// The card is the lock's, 380 units wide; around it, transparent room
/// for its shadow, which is drawn outside the panel (20 down, a 50 blur).
/// The card's height is fixed and its body given a fixed box sized from
/// authui's own measures — avatar 72, name, field 46, the line under it,
/// and the spacing between — so Authenticate is exactly where the
/// hit-test looks for it whatever the body draws.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Layout {
    /// authui's unit: the theme's font size over ten, bounded.
    pub u: f64,
    pub width: f64,
    pub height: f64,
    pub card_x: f64,
    pub card_y: f64,
    pub card_w: f64,
    pub card_h: f64,
    pub header: f64,
    pub body: f64,
    pub several: bool,
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

// In authui's units.
const CARD_W: f64 = 380.0;
const PAD_TOP: f64 = 26.0;
const PAD_SIDE: f64 = 28.0;
const PAD_BOTTOM: f64 = 22.0;
const TITLE: f64 = 15.0;
const MESSAGE: f64 = 13.0;
const LINE: f64 = 1.3;
/// authui's `card_body`: avatar 72, gap 10, the name (17 with its lift),
/// gap 18, field 46, gap 18, the line under it (11) — and a little over.
const BODY: f64 = 72.0 + 10.0 + 24.0 + 18.0 + 46.0 + 18.0 + 15.0 + 4.0;
const HEADER_GAP: f64 = 20.0;
const SWITCH: f64 = 22.0;
const SWITCH_GAP: f64 = 6.0;
const BUTTONS_GAP: f64 = 22.0;
const BUTTONS: f64 = 38.0;
const BUTTON_GAP: f64 = 10.0;
const SHADOW_SIDE: f64 = 40.0;
const SHADOW_TOP: f64 = 24.0;
const SHADOW_BOTTOM: f64 = 64.0;

impl Layout {
    /// The layout at authui's unit `u`, for a message `message_lines`
    /// long (measured by the caller, because only the shaper knows where
    /// a sentence wraps), with the identity switch when `several` may
    /// answer.
    pub fn new(u: f32, message_lines: usize, several: bool) -> Layout {
        let u = f64::from(u);
        let header = (TITLE * LINE + 6.0 + MESSAGE * LINE * message_lines.clamp(1, 4) as f64) * u;
        let body = BODY * u;
        let switch = if several { (SWITCH_GAP + SWITCH) * u } else { 0.0 };
        let card_h = (PAD_TOP + HEADER_GAP + BUTTONS_GAP + BUTTONS + PAD_BOTTOM) * u + header + body + switch;
        let card_w = CARD_W * u;
        Layout {
            u,
            width: card_w + 2.0 * SHADOW_SIDE * u,
            height: card_h + (SHADOW_TOP + SHADOW_BOTTOM) * u,
            card_x: SHADOW_SIDE * u,
            card_y: SHADOW_TOP * u,
            card_w,
            card_h,
            header,
            body,
            several,
        }
    }

    /// The width a line of the message has, for measuring it.
    pub fn message_width(u: f32) -> f32 {
        ((CARD_W - 2.0 * PAD_SIDE) as f32) * u
    }

    fn inner_w(&self) -> f64 {
        self.card_w - 2.0 * PAD_SIDE * self.u
    }

    fn button_w(&self) -> f64 {
        (self.inner_w() - BUTTON_GAP * self.u) / 2.0
    }

    fn buttons_y(&self) -> f64 {
        self.card_y + self.card_h - (PAD_BOTTOM + BUTTONS) * self.u
    }

    pub fn cancel(&self) -> Rect {
        Rect { x: self.card_x + PAD_SIDE * self.u, y: self.buttons_y(), w: self.button_w(), h: BUTTONS * self.u }
    }

    pub fn authenticate(&self) -> Rect {
        let cancel = self.cancel();
        Rect { x: cancel.x + cancel.w + BUTTON_GAP * self.u, ..cancel }
    }

    /// "Use another account", under the card's body, when there is one.
    pub fn switch(&self) -> Option<Rect> {
        self.several.then(|| Rect {
            x: self.card_x + PAD_SIDE * self.u,
            y: self.card_y + (PAD_TOP + HEADER_GAP + SWITCH_GAP) * self.u + self.header + self.body,
            w: self.inner_w(),
            h: SWITCH * self.u,
        })
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
    hovered: Option<Hot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hot {
    Cancel,
    Authenticate,
    Switch,
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

    fn hot_at(&self, position: (f64, f64)) -> Option<Hot> {
        if self.layout.cancel().contains(position) {
            Some(Hot::Cancel)
        } else if self.layout.authenticate().contains(position) {
            Some(Hot::Authenticate)
        } else if self.layout.switch().is_some_and(|r| r.contains(position)) {
            Some(Hot::Switch)
        } else {
            None
        }
    }
}

impl PopupApp for PromptApp {
    type Outcome = Closed;

    fn view<'a>(&'a mut self, theme: &'a Theme, _now: u64, _width: f64) -> Element<'a, Infallible, iced_widget::Theme, iced_tiny_skia::Renderer> {
        view(&self.model, &self.layout, theme, self.hovered)
    }

    fn rows_that_fit(&self, _theme: &Theme, _height: f64) -> usize {
        1
    }

    fn pointer_move(&mut self, _theme: &Theme, position: (f64, f64)) -> bool {
        let hovered = self.hot_at(position);
        let changed = hovered != self.hovered;
        self.hovered = hovered;
        changed
    }

    fn pointer_click(&mut self, _theme: &Theme, _width: f64, position: (f64, f64)) -> Option<Closed> {
        let action = match self.hot_at(position) {
            Some(Hot::Cancel) => Some(Action::Cancel),
            Some(Hot::Authenticate) => self.model.submit(),
            Some(Hot::Switch) => self.model.switch(1),
            None => None,
        };
        self.act(action)
    }

    fn pointer_scroll(&mut self, _rows: i32) {}

    fn key(&mut self, keysym: Keysym, utf8: Option<String>, modifiers: Modifiers) -> Option<Closed> {
        // Not a nicety: where pam_faillock counts, a stuck Caps Lock
        // spends a try. Learned from the press, as the lock does.
        self.model.caps_lock = modifiers.caps_lock;
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

type El<'a> = Element<'a, Infallible, iced_widget::Theme, iced_tiny_skia::Renderer>;

fn fade(c: hyprforge_look::Color, alpha: f32) -> Color {
    let c = to_iced(c);
    Color { a: c.a * alpha, ..c }
}

/// The prompt: the lock's card, with the request above its body and the
/// buttons below.
pub(crate) fn view<'a>(model: &'a Model, layout: &Layout, theme: &'a Theme, hovered: Option<Hot>) -> El<'a> {
    let u = layout.u as f32;
    let fg = to_iced(theme.foreground);
    let font = screen::font(theme);
    let medium = Font { weight: Weight::Medium, ..font };
    let strong = Font { weight: Weight::Semibold, ..font };

    let header = column![
        text("Authentication required").size(TITLE as f32 * u).font(strong).color(fg),
        text(model.request.message.as_str())
            .size(MESSAGE as f32 * u)
            .font(font)
            .color(fade(theme.foreground, 0.7))
            .wrapping(Wrapping::Word)
            .align_x(Horizontal::Center),
    ]
    .spacing(6.0 * u)
    .align_x(iced_runtime::core::Alignment::Center)
    .width(Length::Fill);
    let header = container(header).width(Length::Fill).height(Length::Fixed(layout.header as f32)).clip(true);

    // The lock's own card body, from a scene of this conversation.
    let mut scene = Scene::new(&model.state, model.user(), theme, chrono::Local::now());
    scene.caps_lock = model.caps_lock;
    scene.submitted = model.submitted;
    let body: El = screen::card_body::<iced_tiny_skia::Renderer>(&scene)
        // The card body sends no Action — authui says so where it makes
        // it public: the controls that do are not part of it.
        .map(|_: scene::Action| -> Infallible { unreachable!("authui's card body has no controls") });
    let body = container(body).width(Length::Fill).height(Length::Fixed(layout.body as f32)).align_x(Horizontal::Center);

    let mut card = column![header, Space::new().height(Length::Fixed(HEADER_GAP as f32 * u)), body].width(Length::Fill);
    if layout.several {
        let hot = hovered == Some(Hot::Switch);
        card = card.push(Space::new().height(Length::Fixed(SWITCH_GAP as f32 * u)));
        card = card.push(
            container(
                text(format!("Not {}? Use another account", scene::display_name(model.user())))
                    .size(12.0 * u)
                    .font(font)
                    .color(fade(theme.foreground, if hot { 0.95 } else { 0.6 })),
            )
            .width(Length::Fill)
            .height(Length::Fixed(SWITCH as f32 * u))
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center),
        );
    }
    card = card.push(Space::new().height(Length::Fill));

    let button = |label: &'static str, primary: bool, hot: bool, enabled: bool| -> El {
        let radius = 12.0 * u;
        let (fill, edge, ink) = match (primary, enabled) {
            (true, true) => (fade(theme.accent, if hot { 0.85 } else { 1.0 }), Color::TRANSPARENT, to_iced(theme.background)),
            (true, false) => (fade(theme.accent, 0.35), Color::TRANSPARENT, fade(theme.background, 0.8)),
            (false, _) => (fade(theme.background, if hot { 0.75 } else { 0.5 }), fade(theme.foreground, 0.14), fg),
        };
        container(text(label).size(13.0 * u).font(medium).color(ink))
            .width(Length::Fixed(layout.button_w() as f32))
            .height(Length::Fixed(BUTTONS as f32 * u))
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center)
            .style(move |_: &iced_widget::Theme| container::Style {
                background: Some(fill.into()),
                border: Border { radius: radius.into(), width: 1.0, color: edge },
                ..Default::default()
            })
            .into()
    };
    card = card.push(
        row![
            button("Cancel", false, hovered == Some(Hot::Cancel), true),
            button("Authenticate", true, hovered == Some(Hot::Authenticate), model.can_submit()),
        ]
        .spacing(BUTTON_GAP as f32 * u),
    );
    let inner_h = layout.card_h as f32 - (PAD_TOP + PAD_BOTTOM) as f32 * u;
    let card = container(card).height(Length::Fixed(inner_h));
    let panel = screen::glass_panel(
        card,
        theme,
        layout.card_w as f32,
        Padding { top: PAD_TOP as f32 * u, right: PAD_SIDE as f32 * u, bottom: PAD_BOTTOM as f32 * u, left: PAD_SIDE as f32 * u },
    );
    container(panel)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(Padding { top: layout.card_y as f32, left: layout.card_x as f32, right: 0.0, bottom: 0.0 })
        .into()
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
        typed(&mut m, "x");
        assert_eq!(m.typed(), 0, "nothing is typed while checking");
        assert!(m.key(Keysym::Return, None).is_none());
    }

    /// As on the lock: a failure stays on the card until the person
    /// types, and the first character reopens the question.
    #[test]
    fn a_failure_stays_until_typing_starts_again() {
        let mut m = model(&["alex"]);
        asked(&mut m);
        typed(&mut m, "wrong");
        m.key(Keysym::Return, None);
        m.shown(Shown::Error("Authentication failure".into()));
        m.shown(Shown::TryAgain);
        asked(&mut m);
        assert!(matches!(m.state(), State::Failed { reason } if reason == "Authentication failure"));
        assert!(!m.can_submit());
        typed(&mut m, "r");
        assert!(matches!(m.state(), State::Asking { .. }));
        assert_eq!(m.typed(), 1);
    }

    #[test]
    fn a_failure_with_nothing_said_still_says_something() {
        let mut m = model(&["alex"]);
        asked(&mut m);
        m.key(Keysym::Return, None);
        m.shown(Shown::TryAgain);
        assert!(matches!(m.state(), State::Failed { reason } if reason == TRY_AGAIN));
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

    /// What a click finds is where the card draws it: the buttons side
    /// by side at the card's foot, inside it; the switch line between
    /// the body and the buttons.
    #[test]
    fn the_hit_areas_sit_inside_the_card_and_apart() {
        for u in [0.8f32, 1.0, 1.6] {
            let l = Layout::new(u, 2, true);
            let (c, a, s) = (l.cancel(), l.authenticate(), l.switch().unwrap());
            assert!(c.x + c.w <= a.x);
            assert!(a.x + a.w <= l.card_x + l.card_w + 0.01);
            assert!(a.y + a.h <= l.card_y + l.card_h + 0.01);
            assert!(s.y + s.h <= c.y, "switch above the buttons");
            assert!(s.y >= l.card_y + l.header + l.body, "and below the body");
            assert!(l.card_y + l.card_h <= l.height && l.card_x + l.card_w <= l.width, "room for the shadow");
        }
        assert!(Layout::new(1.0, 2, false).switch().is_none());
    }

    /// Draws the prompt to `$SHOTS/<name>.png` in a few states, to look
    /// at. Ignored: it renders, it asserts nothing.
    #[test]
    #[ignore]
    fn render_the_card() {
        use iced_runtime::core::{renderer::Style, Rectangle, Size};
        use iced_runtime::user_interface::{Cache, UserInterface};
        let dir = std::path::PathBuf::from(std::env::var("SHOTS").expect("SHOTS"));
        let theme = hyprforge_look::Theme::load(std::path::Path::new(&std::env::var("SHOTS_THEME").expect("SHOTS_THEME"))).unwrap();
        let theme = screen::renderable(theme);
        let scale = 1.6f32;
        type Set = Box<dyn Fn(&mut Model)>;
        let states: Vec<(&str, &[&str], Set)> = vec![
            // The suite's screenshot user, as in the README's lock and
            // greeter shots — never a real account name.
            ("asking", &["voldemort"], Box::new(|m: &mut Model| { asked(m); typed(m, "hunter2"); })),
            ("fingerprint", &["voldemort"], Box::new(|m: &mut Model| m.shown(Shown::Info("Place your finger on the fingerprint reader".into())))),
            ("failed", &["voldemort", "bellatrix"], Box::new(|m: &mut Model| { asked(m); m.key(Keysym::Return, None); m.shown(Shown::Error("Authentication failure".into())); m.shown(Shown::TryAgain); asked(m); })),
        ];
        for (name, users, set) in states {
            let mut m = model(users);
            m.request.message = "Authentication is required to mount SanDisk Ultra (/dev/sda1)".into();
            set(&mut m);
            let layout = Layout::new(screen::unit(&theme), 2, users.len() > 1);
            let (w, h) = (layout.width as f32, layout.height as f32);
            let (pw, ph) = ((w * scale).round() as u32, (h * scale).round() as u32);
            let mut renderer = iced_tiny_skia::Renderer::new(screen::font(&theme), iced_runtime::core::Pixels(theme.font_size));
            let size = Size::new(w, h);
            let mut ui = UserInterface::<Infallible, iced_widget::Theme, iced_tiny_skia::Renderer>::build(view(&m, &layout, &theme, None), size, Cache::default(), &mut renderer);
            ui.draw(&mut renderer, &iced_widget::Theme::Dark, &Style { text_color: Color::WHITE }, iced_runtime::core::mouse::Cursor::Unavailable);
            let mut card = tiny_skia::Pixmap::new(pw, ph).unwrap();
            let mut mask = tiny_skia::Mask::new(pw, ph).unwrap();
            renderer.draw(&mut card.as_mut(), &mut mask, &iced_tiny_skia::graphics::Viewport::with_physical_size(Size::new(pw, ph), scale), &[Rectangle::with_size(size)], Color::TRANSPARENT);
            // Only now: drawn text holds weak references to paragraphs
            // the UI tree owns, so dropping it first draws no text at all.
            drop(ui);
            // iced_tiny_skia writes BGRA, for Wayland; a PNG wants RGBA.
            for px in card.data_mut().chunks_exact_mut(4) {
                px.swap(0, 2);
            }
            // Something to see the glass against — the lock's own
            // generated wallpaper, when it is there — with the card over it.
            let mut out = tiny_skia::Pixmap::new(pw, ph).unwrap();
            if let Ok(wall) = tiny_skia::Pixmap::load_png(dir.join("wallpaper.png")) {
                out.draw_pixmap(0, 0, wall.as_ref(), &tiny_skia::PixmapPaint::default(), tiny_skia::Transform::identity(), None);
            }
            out.draw_pixmap(0, 0, card.as_ref(), &tiny_skia::PixmapPaint::default(), tiny_skia::Transform::identity(), None);
            out.save_png(dir.join(format!("{name}.png"))).unwrap();
        }
    }
}
