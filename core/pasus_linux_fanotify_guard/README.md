# Pasus Linux fanotify Guard

Pasus Linux on-access blocking depends on fanotify permission events and kernel support.

Current state:

- Architecture placeholder only.
- UI modes must be honest:
  - `fanotify blocking active`
  - `monitor-only fallback`
  - `unavailable`

Pasus must not claim blocking when only inotify/user-mode monitoring is available.
