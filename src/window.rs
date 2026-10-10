//! Opening the real prompt: a popup on its own thread, covering the
//! monitor the pointer is on, with the card in the middle of it.
//!
//! Each prompt is its own Wayland connection, opened when it is needed
//! and closed with it, so an agent that sits idle all day holds nothing
//! open on the compositor. A prompt that disappears without the person
//! cancelling — the compositor closed it, the output went away — tells
//! the conversation it was cancelled, so polkit's caller is answered
//! rather than left waiting.

use crate::agent::{PromptHandle, Prompts};
use crate::conversation::Did;
use crate::prompt::{Layout, Model, PromptApp, Request};
use hyprforge_popup::geometry::Point;
use hyprforge_popup::{Connection, Outcome, Placement, Popup};
use iced_runtime::core::text::{self, LineHeight, Paragraph as _, Shaping, Text, Wrapping};
use iced_runtime::core::{alignment, Font, Pixels, Size};
use tokio::sync::mpsc::UnboundedSender;

pub struct Wayland;

impl Prompts for Wayland {
    fn open(&self, request: Request, did: UnboundedSender<Did>) -> std::io::Result<Box<dyn PromptHandle>> {
        // The lock's own guard on a theme it is about to draw — every
        // value brought into a range the renderer accepts.
        let theme = hyprforge_authui::screen::renderable(hyprforge_appearance::look::resolve());
        let u = hyprforge_authui::screen::unit(&theme);
        let lines = message_lines(&crate::prompt::shown_message(&request.message), 13.0 * u, Layout::message_width(u), hyprforge_authui::screen::font(&theme));
        let layout = Layout::new(u, lines, request.users.len() > 1);
        let (placement, layout) = covering(layout).ok_or_else(|| std::io::Error::other("no monitor to show the prompt on"))?;
        let connection = Connection::connect_to_env().map_err(std::io::Error::other)?;
        let (tell, inbox) = hyprforge_popup::inbox();
        let app = PromptApp::new(Model::new(request), layout, did.clone());
        std::thread::Builder::new().name("polkit-prompt".into()).spawn(move || {
            match Popup::run_receiving(connection, placement, app, theme, inbox) {
                Ok(Outcome::App(_)) => {}
                Ok(Outcome::Closed | Outcome::Disconnected) => {
                    let _ = did.send(Did::Cancel);
                }
                Err(e) => {
                    tracing::warn!("the prompt failed: {e}");
                    let _ = did.send(Did::Cancel);
                }
            }
        })?;
        Ok(Box::new(tell))
    }
}

/// How many lines polkit's message takes at the card's width — measured
/// by the shaper that draws it, because only it knows where the
/// sentence wraps.
pub(crate) fn message_lines(message: &str, font_size: f32, width: f32, font: Font) -> usize {
    let paragraph = iced_tiny_skia::graphics::text::Paragraph::with_text(Text {
        content: message,
        bounds: Size::new(width, f32::INFINITY),
        size: Pixels(font_size),
        line_height: LineHeight::default(),
        font,
        align_x: text::Alignment::Left,
        align_y: alignment::Vertical::Top,
        shaping: Shaping::default(),
        wrapping: Wrapping::Word,
    });
    let line = LineHeight::default().to_absolute(Pixels(font_size)).0;
    (paragraph.min_bounds().height / line).round().max(1.0) as usize
}

/// All of the monitor the pointer is on — where the person is looking —
/// or the first monitor when the pointer cannot be found; and the card's
/// layout centred on it.
fn covering(layout: Layout) -> Option<(Placement, Layout)> {
    let monitors = hyprforge_popup::monitors();
    let pointer: Option<Point> = hyprforge_popup::cursor_position();
    let monitor = pointer
        .and_then(|p| hyprforge_popup::geometry::monitor_at(&monitors, p))
        .or_else(|| monitors.first())?;
    let layout = layout.on(monitor.size.width.floor(), monitor.size.height.floor());
    let placement = Placement {
        output_name: monitor.name.clone(),
        margin_left: 0,
        margin_top: 0,
        width: layout.width as u32,
        height: layout.height as u32,
    };
    Some((placement, layout))
}
