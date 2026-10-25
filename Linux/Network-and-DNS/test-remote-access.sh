#!/bin/sh
# What it does
# Inspect SSH service configuration and listeners, with an optional TCP reachability test.
# Available flags
# --help; --output-dir DIRECTORY; --target HOST --port NUMBER (default 22); --user USER --client-address IP --local-address IP provide an sshd Match context.
# How it works
# Uses the shared read-only collector, preserving this entrypoint's flags and report scope.

SCRIPT_NAME=test-remote-access
DESCRIPTION='Inspect SSH service configuration and listeners, with an optional TCP reachability test.'
FLAGS='--target HOST --port NUMBER (default 22); --user USER --client-address IP --local-address IP provide an sshd Match context.'
OPTIONS='target port user client-address local-address'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

[ -r "$LIBRARY_ROOT/lib/ssh-audit.inc" ] || die "Missing Linux/lib/ssh-audit.inc; copy the complete Linux folder."
. "$LIBRARY_ROOT/lib/ssh-audit.inc"
collect_ssh_audit remote

finish
