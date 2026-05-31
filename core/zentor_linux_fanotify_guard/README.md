# Avorax Linux fanotify Guard

Avorax Linux on-access blocking depends on fanotify permission events and kernel support.

Current state:

- Architecture validation state only; no fanotify permission-event service is installed by this repository yet.
- UI modes must be honest:
  - `fanotify blocking active`
  - `monitor-only fallback`
  - `unavailable`

Avorax must not claim blocking when only inotify/user-mode monitoring is available.
