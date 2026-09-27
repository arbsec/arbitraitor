#!/usr/bin/env bash
# Shared helpers for the github-project-workflow and github-pr-lifecycle skill scripts.
# Sourced, not executed. Provides: arg parsing for --help/--json/--dry-run/--repo,
# config loading, gh invocation, jq parsing, and stable exit codes.
#
# Conventions enforced (see SKILL.md "Safety conditions"):
#   - set -euo pipefail; no eval; no embedding credentials.
#   - never guess identity: repo/org/project come from config or --repo flag, never defaults.
#   - validate-before-mutate; --dry-run for remote-changing ops; idempotent where practical.
#   - stable exit codes: 0 ok | 1 unrecoverable | 2 config/state | 3 policy | 4 concurrent | 5 blocked.

set -euo pipefail

# --- Exit codes (mirrored from both SKILL.md files) ----------------------------
ARB_OK=0
ARB_ERR_UNRECOVERABLE=1
ARB_ERR_CONFIG=2
ARB_ERR_POLICY=3
ARB_ERR_CONCURRENT=4
ARB_ERR_BLOCKED=5

# --- Common flag parsing -------------------------------------------------------
# Usage: arb_lib_parse_common "$@" then read OPT_HELP OPT_JSON OPT_DRY_RUN OPT_REPO
arb_lib_parse_common() {
  OPT_HELP=false; OPT_JSON=false; OPT_DRY_RUN=false; OPT_REPO=""
  ARB_LIB_EXTRA_ARGS=()
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)       OPT_HELP=true; shift ;;
      --json)          OPT_JSON=true; shift ;;
      --dry-run)       OPT_DRY_RUN=true; shift ;;
      -R|--repo)
        if [ -z "${2:-}" ]; then
          echo "error: --repo requires a value (OWNER/REPO)" >&2
          exit "$ARB_ERR_CONFIG"
        fi
        OPT_REPO="$2"; shift 2 ;;
      -R=*|--repo=*)   OPT_REPO="${1#*=}"; shift ;;
      --)              shift; ARB_LIB_EXTRA_ARGS+=("$@"); break ;;
      *)               ARB_LIB_EXTRA_ARGS+=("$1"); shift ;;
    esac
  done
}

# --- Help renderer -------------------------------------------------------------
# Usage: arb_lib_print_help <script-name> <synopsis>
arb_lib_print_help() {
  local name="$1" synopsis="$2"
  cat <<EOF
Usage: $name [options] [args]

$synopsis

Options:
  -h, --help        Show this help and exit 0
  --json            Emit machine-readable JSON on stdout (human form on stderr)
  --dry-run         Print the exact gh/GraphQL that would run; write nothing; exit 0
  -R, --repo OWNER/REPO   Target repository (required; never inferred from cwd)

Exit codes:
  0  success (or dry-run preview)
  1  unrecoverable error (network, auth, unexpected gh output)
  2  config/state error (missing config, unknown field, not found)
  3  policy violation (would violate the scheduling policy, would merge on red, etc.)
  4  concurrent edit detected (resource updatedAt changed since read — retry)
  5  blocked (review loop limit hit — produces blocked/needs-human, never silent approval)
EOF
}

# --- Config loader -------------------------------------------------------------
# Loads .agents/project/github-project.local.toml (preferred) or falls back to the
# committed example ONLY for field/option NAME discovery (node IDs are never taken
# from config — they are resolved at runtime via GraphQL).
# Exits 2 with an actionable message if neither exists.
arb_lib_load_project_config() {
  local repo_root
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "error: not inside a git repository; cannot locate .agents/project/" >&2
    exit "$ARB_ERR_CONFIG"
  }
  local cfg_local="$repo_root/.agents/project/github-project.local.toml"
  local cfg_example="$repo_root/.agents/project/github-project.example.toml"
  # Mutating scripts require the local config (never fall back to the example).
  if [ "$OPT_DRY_RUN" = false ]; then
    if [ ! -f "$cfg_local" ]; then
      echo "error: local project config not found at .agents/project/github-project.local.toml" >&2
      echo "       copy github-project.example.toml -> github-project.local.toml and fill in real values." >&2
      echo "       (the example is for documentation only; mutating scripts require the local copy)" >&2
      exit "$ARB_ERR_CONFIG"
    fi
    ARB_PROJECT_CONFIG="$cfg_local"
  elif [ -f "$cfg_local" ]; then
    ARB_PROJECT_CONFIG="$cfg_local"
  elif [ -f "$cfg_example" ]; then
    ARB_PROJECT_CONFIG="$cfg_example"
  else
    echo "error: no project config found at .agents/project/github-project.local.toml" >&2
    exit "$ARB_ERR_CONFIG"
  fi
  export ARB_PROJECT_CONFIG
}

# --- gh wrapper: fail fast with context ----------------------------------------
# Usage: arb_lib_gh <args...>
arb_lib_gh() {
  command "${GH_BIN:-gh}" "$@"
}

# --- jq wrapper: parse gh --json safely ----------------------------------------
# Usage: arb_lib_jq_filter <gh-json-stdin> <jq-filter>  -> prints filtered result
arb_lib_jq_filter() {
  jq -r "$2" < "$1" 2>/dev/null || {
    echo "error: failed to parse gh JSON output with filter: $2" >&2
    exit "$ARB_ERR_UNRECOVERABLE"
  }
}

# --- Repo resolution (never guess) ---------------------------------------------
# Exits 2 if --repo was not provided AND no unambiguous default exists.
arb_lib_resolve_repo() {
  if [ -n "$OPT_REPO" ]; then echo "$OPT_REPO"; return; fi
  # Try the gh default host/repo detection (requires being inside a repo w/ gh origin).
  local detected
  detected="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null)" || true
  if [ -n "$detected" ]; then echo "$detected"; return; fi
  echo "error: could not resolve repository. Pass --repo OWNER/REPO explicitly." >&2
  exit "$ARB_ERR_CONFIG"
}

# --- Pre-flight check ----------------------------------------------------------
# Verifies gh is installed + authenticated for the required scope.
arb_lib_require_gh_scope() {
  local required_scope="${1:-}"
  if ! command -v gh >/dev/null 2>&1; then
    echo "error: gh CLI not found. Install from https://cli.github.com/" >&2
    exit "$ARB_ERR_CONFIG"
  fi
  if ! gh auth status >/dev/null 2>&1; then
    echo "error: not authenticated to gh. Run 'gh auth login'." >&2
    exit "$ARB_ERR_CONFIG"
  fi
  if [ -n "$required_scope" ]; then
    # Check scopes from the OAuth token header (gh sets X-Oauth-Scopes).
    local scopes
    scopes="$(gh auth status 2>&1 | grep -i 'Token scopes' || true)"
    if ! echo "$scopes" | grep -q "$required_scope"; then
      echo "error: missing gh OAuth scope '$required_scope'. Run: gh auth refresh -s $required_scope" >&2
      exit "$ARB_ERR_CONFIG"
    fi
  fi
}

# --- Dry-run-aware execution (no eval) -----------------------------------------
# Scripts build their gh/GraphQL command as a bash ARRAY (named array), then call:
#   arb_lib_run_or_dry_run <array-name> [gh|graphql]
# The array is expanded with `"${array[@]}"` — never eval. In dry-run mode the
# array is printed (one shell-quoted word per element) and written nothing otherwise.
arb_lib_run_or_dry_run() {
  local -n _arr="$1"
  local kind="${2:-gh}"
  if [ "$OPT_DRY_RUN" = true ]; then
    printf '[dry-run] %s ' "$kind" >&2
    printf '%q ' "${_arr[@]}" >&2
    printf '\n' >&2
    return 0
  fi
  case "$kind" in
    gh)        command "${GH_BIN:-gh}" "${_arr[@]}" ;;
    graphql)   command "${GH_BIN:-gh}" api graphql "${_arr[@]}" ;;
    *)         printf 'error: unknown run kind %q\n' "$kind" >&2; return "$ARB_ERR_CONFIG" ;;
  esac
}
