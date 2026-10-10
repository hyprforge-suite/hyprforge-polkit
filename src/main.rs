//! hyprforge-polkit — a polkit authentication agent for Hyprland.
//!
//! Registers on the system bus as this session's agent and answers
//! polkitd's requests with a prompt in the suite's look. See README.md
//! for what it does and does not do, and `agent.rs` for the protocol.

mod agent;
mod conversation;
mod helper;
mod identity;
mod line;
mod prompt;
mod window;

use std::sync::Arc;

/// The exit status when polkit refuses to register this agent because
/// another one answers for the session. The unit does not restart on it
/// (`RestartPreventExitStatus=3`): retrying cannot change the answer.
const ANOTHER_AGENT: u8 = 3;

/// Registration was refused — the one failure that has its own exit
/// status.
#[derive(Debug)]
struct Refused(anyhow::Error);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl std::error::Error for Refused {}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            if e.is::<Refused>() {
                std::process::ExitCode::from(ANOTHER_AGENT)
            } else {
                std::process::ExitCode::FAILURE
            }
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let me = std::env::var("USER").map_err(|_| anyhow::anyhow!("$USER is not set, so there is no one to authenticate as"))?;
    let agent = Arc::new(agent::Agent::new(Arc::new(helper::Polkit::default()), Arc::new(window::Wayland), me));
    let system = zbus::connection::Builder::system()?.serve_at(agent::OBJECT_PATH, agent::Service(agent))?.build().await?;
    let session = agent::session_id(&system).await.map_err(|e| anyhow::anyhow!("couldn't tell which login session this is: {e}"))?;
    // Refused when another agent already answers for this session —
    // hyprpolkitagent, say. Said plainly, because it is the one failure a
    // person can fix by themselves.
    agent::register(&system, &session).await.map_err(|e| {
        anyhow::Error::new(Refused(anyhow::anyhow!(
            "polkit refused to register this agent for session {session}: {e} — is another agent (hyprpolkitagent?) already running? \
             Settings -> Set up -> \"Administrator prompts\" replaces it"
        )))
    })?;
    tracing::info!("answering polkit for session {session}");
    std::future::pending::<()>().await;
    Ok(())
}
