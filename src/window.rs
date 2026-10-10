//! Opening the real prompt: a popup on its own thread, centred on the
//! monitor the pointer is on.
//!
//! Each prompt is its own Wayland connection, opened when it is needed
//! and closed with it, so an agent that sits idle all day holds nothing
//! open on the compositor. A prompt that disappears without the person
//! cancelling — the compositor closed it, the output went away — tells
//! the conversation it was cancelled, so polkit's caller is answered
//! rather than left waiting.

use crate::agent::{PromptHandle, Prompts};
use crate::conversation::Did;
use crate::prompt::{Layout, Model, PromptApp, Request, WIDTH};
use hyprforge_popup::geometry::Point;
use hyprforge_popup::{Connection, Outcome, Placement, Popup};
use iced_runtime::core::text::{self, LineHeight, Paragraph as _, Shaping, Text, Wrapping};
use iced_runtime::core::{alignment, Font, Pixels, Size};
use tokio::sync::mpsc::UnboundedSender;

pub struct Wayland;

impl Prompts for Wayland {
    fn open(&self, request: Request, did: UnboundedSender<Did>) -> std::io::Result<Box<dyn PromptHandle>> {
        let mut theme = hyprforge_appearance::look::resolve();
        theme.font_size = theme.drawable_font_size();
        let layout = Layout::new(theme.font_size, message_lines(&request.message, theme.font_size));
        let placement = centred(layout).ok_or_else(|| std::io::Error::other("no monitor to show the prompt on"))?;
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
fn message_lines(message: &str, font_size: f32) -> usize {
    let width = (WIDTH - 40.0) as f32;
    let paragraph = iced_tiny_skia::graphics::text::Paragraph::with_text(Text {
        content: message,
        bounds: Size::new(width, f32::INFINITY),
        size: Pixels(font_size),
        line_height: LineHeight::default(),
        font: Font::DEFAULT,
        align_x: text::Alignment::Left,
        align_y: alignment::Vertical::Top,
        shaping: Shaping::default(),
        wrapping: Wrapping::Word,
    });
    let line = LineHeight::default().to_absolute(Pixels(font_size)).0;
    (paragraph.min_bounds().height / line).round().max(1.0) as usize
}

/// The middle of the monitor the pointer is on — where the person is
/// looking — or the first monitor when the pointer cannot be found.
fn centred(layout: Layout) -> Option<Placement> {
    let monitors = hyprforge_popup::monitors();
    let pointer: Option<Point> = hyprforge_popup::cursor_position();
    let monitor = pointer
        .and_then(|p| hyprforge_popup::geometry::monitor_at(&monitors, p))
        .or_else(|| monitors.first())?;
    Some(Placement {
        output_name: monitor.name.clone(),
        margin_left: ((monitor.size.width - layout.width) / 2.0).max(0.0).round() as i32,
        margin_top: ((monitor.size.height - layout.height) / 2.0).max(0.0).round() as i32,
        width: layout.width.round() as u32,
        height: layout.height.round() as u32,
    })
}
