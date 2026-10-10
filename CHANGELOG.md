# Changelog

This component is released with the Hyprforge suite and shares its version: see the suite's `CHANGELOG.md`.

## [Unreleased]

### Added

- The agent: registers for the login session, relays polkit's PAM conversation through its helper (socket first, setuid helper second), and draws the prompt as the lock screen's card on a dimmed, blur-ready layer of its own.
- Fingerprints where the `polkit-1` PAM stack offers them.
- "Use another account" when polkit names several identities.
- A user unit, which does not restart when another agent holds the session.
