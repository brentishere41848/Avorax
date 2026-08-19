#!/usr/bin/env bash
set -euo pipefail

readonly apt_timeout_seconds="${AVORAX_APT_TIMEOUT_SECONDS:-300}"
readonly apt_attempts="${AVORAX_APT_ATTEMPTS:-3}"
readonly apt_retry_delay_seconds="${AVORAX_APT_RETRY_DELAY_SECONDS:-5}"
readonly apt_kill_grace_seconds=15
readonly max_apt_operation_budget_seconds=1200

validate_bounded_integer() {
  local name="$1"
  local value="$2"
  local minimum="$3"
  local maximum="$4"

  if [[ ! "$value" =~ ^(0|[1-9][0-9]*)$ ]] || \
    ((value < minimum || value > maximum)); then
    printf '%s must be an integer from %s through %s; got %s.\n' \
      "$name" "$minimum" "$maximum" "$value" >&2
    return 2
  fi
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Required Linux package prerequisite command is unavailable: %s\n' \
      "$command_name" >&2
    return 2
  fi
}

validate_operation_budget() {
  local operation_budget_seconds=$((
    (apt_timeout_seconds + apt_kill_grace_seconds) * apt_attempts +
      apt_retry_delay_seconds * (apt_attempts - 1)
  ))
  if ((operation_budget_seconds > max_apt_operation_budget_seconds)); then
    printf 'Combined apt retry budget is %s seconds; maximum is %s seconds.\n' \
      "$operation_budget_seconds" "$max_apt_operation_budget_seconds" >&2
    return 2
  fi
}

run_bounded_apt() {
  local operation="$1"
  shift

  local attempt
  local status=1
  for ((attempt = 1; attempt <= apt_attempts; attempt++)); do
    printf 'Avorax prerequisite %s attempt %s/%s.\n' \
      "$operation" "$attempt" "$apt_attempts"

    if sudo -- env DEBIAN_FRONTEND=noninteractive \
      timeout --signal=TERM --kill-after="${apt_kill_grace_seconds}s" \
        "${apt_timeout_seconds}s" \
      apt-get \
        -o Acquire::Retries=2 \
        -o Acquire::http::Timeout=30 \
        -o Acquire::https::Timeout=30 \
        -o DPkg::Lock::Timeout=30 \
        -o Dpkg::Use-Pty=0 \
        "$@"; then
      return 0
    else
      status=$?
    fi

    if ((status == 124)); then
      printf 'Avorax prerequisite %s timed out after %s seconds.\n' \
        "$operation" "$apt_timeout_seconds" >&2
    else
      printf 'Avorax prerequisite %s failed with exit code %s.\n' \
        "$operation" "$status" >&2
    fi

    if ((attempt < apt_attempts)); then
      sleep "$apt_retry_delay_seconds" || return
    fi
  done

  printf 'Avorax prerequisite %s failed after %s bounded attempts.\n' \
    "$operation" "$apt_attempts" >&2
  return "$status"
}

main() {
  validate_bounded_integer \
    AVORAX_APT_TIMEOUT_SECONDS "$apt_timeout_seconds" 30 900 || return
  validate_bounded_integer AVORAX_APT_ATTEMPTS "$apt_attempts" 1 5 || return
  validate_bounded_integer AVORAX_APT_RETRY_DELAY_SECONDS \
    "$apt_retry_delay_seconds" 0 60 || return
  validate_operation_budget || return

  require_command sudo || return
  require_command timeout || return
  require_command apt-get || return
  require_command sleep || return

  run_bounded_apt "apt-get update" update || return
  run_bounded_apt "apt-get install" install --no-install-recommends -y \
    clang \
    cmake \
    desktop-file-utils \
    libgtk-3-dev \
    liblzma-dev \
    ninja-build \
    pkg-config || return
}

main "$@"
