# hyprforge-polkit

A polkit authentication agent for Hyprland: the prompt that comes up when
an application asks for administrator access — mounting a disk,
installing a package, changing a system setting — drawn as the lock
screen's own card.

Part of [Hyprforge](https://github.com/hyprforge-suite/hyprforge), a suite of
native Hyprland desktop apps — but it runs alone. Installing this gets
you an agent and nothing else; it needs no other Hyprforge component to
start.

## What it does

polkitd decides *whether* a program may do something; when the answer
is "if the person proves who they are", it asks the session's
authentication agent to find out. This is that agent. It registers on
the system bus for the login session it runs in, and for each request
opens a prompt on the monitor the pointer is on: polkit's own sentence
for what is being asked, the account that can answer it (and "Use
another account" when several can), and the lock screen's card — the
same avatar, field and line under it, drawn by `hyprforge-authui`, so
the two prompts for a password on this desktop cannot drift apart.

The prompt dims the desktop behind it. With Hyprforge's Set up item
"Blur behind administrator prompts" (a layer rule on the namespace
`hyprforge-polkit`) Hyprland blurs it too, the way the lock screen's
card sits over a blurred wallpaper.

## How it authenticates — and what it never does

An agent does not check passwords. polkitd hands it a one-time cookie;
the agent hands the cookie and a username to polkit's own helper
(`/run/polkit/agent-helper.socket`, or the setuid
`polkit-agent-helper-1` where the socket does not exist), which runs the
`polkit-1` PAM stack as root and tells polkitd the result itself. The
agent relays what PAM asks and what the person types, and nothing else
— so whatever PAM is configured to accept is what this accepts.

What was typed lives in a `Secret`, whose `Debug` is a length; it is
written to the helper and nowhere else, and never logged. Characters
come from the text a key press produced, never the keysym, so Shift and
AltGr give PAM the password that was typed.

## Fingerprints

When the `polkit-1` stack has `pam_fprintd` ahead of the password, the
prompt says "Place your finger…" and a touch answers it. Hyprforge's
Set up item "Fingerprint for administrator prompts" adds that line. If
nothing touches the reader, `pam_fprintd` gives up after its timeout
(ten seconds, its minimum) and the card asks for the password.

The two cannot be offered at once: PAM asks one question at a time, and
while `pam_fprintd` waits nothing else can be asked. Abandoning the wait
looks costly too, as polkit 127's helper is written: closing the
connection does not stop a helper that is waiting on the reader, so it
goes on to the password module, reads end-of-file, and `pam_faillock`'s
`authfail` would count that as a failed attempt. polkit's own agent
library cancels the same way, so this is a property of the helper, not
of any one agent. It is read from the source, not yet measured.

## Replacing another agent

polkit accepts one agent per session. Set up's "Administrator prompts"
item masks hyprpolkitagent for your user — the switch that holds even
when your Hyprland config starts it with `systemctl --user start
hyprpolkitagent`, without editing that config — and enables this
agent's unit. Undoing the item unmasks it and starts it again. An agent
started some other way (a bare `exec` of polkit-gnome, say) is named
rather than touched.

Started while another agent holds the session, `hyprforge-polkit` says
so and exits with status 3, which its unit does not restart on.

## Building

```
cargo build --release
```

Runs as your user, in your graphical session: `packaging/hyprforge-polkit.service`
is the user unit.

## Licence

MIT — see `LICENSE`.
