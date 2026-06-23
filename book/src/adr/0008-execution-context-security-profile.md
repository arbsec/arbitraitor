# ADR 0008: Execution context security profile

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #3

## Context

The adversarial review (C-01) documented concrete attack vectors that exploit the gap between artifact integrity and execution-context integrity:

- `BASH_ENV` points to an attacker-controlled file that Bash reads before the approved script.
- `LD_PRELOAD` or `DYLD_*` injects code into the interpreter.
- A poisoned `PATH` causes `curl`, `tar`, `git`, or `sudo` inside the script to resolve to a malicious binary.
- `SSH_AUTH_SOCK`, cloud credentials, browser sockets, or inherited descriptors remain accessible.
- The interpreter path is replaced after it is checked (TOCTOU).
- The working directory contains attacker-controlled configuration loaded by Git, Python, Node, Ruby, or another tool.

## Decision

A clean, allowlisted execution profile is **mandatory** for all `run` operations at the **mediated** assurance level.

### 1. Environment: allowlist, not denylist

The execution environment is constructed from scratch. Only explicitly allowed variables are present.

**Default allowed:** `LANG`, `LC_ALL`, `TERM`, `PATH` (controlled).

**Explicitly removed or controlled (non-exhaustive):**

```
BASH_ENV, ENV, ZDOTDIR, SHELLOPTS, CDPATH, GLOBIGNORE
LD_PRELOAD, LD_LIBRARY_PATH
DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH, DYLD_FRAMEWORK_PATH
PYTHONPATH, PYTHONSTARTUP, PYTHONINSPECT, PYTHONHOME
NODE_OPTIONS, NODE_PATH
RUBYOPT, RUBYLIB
PERL5OPT, PERL5LIB
GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, GIT_CONFIG_NOSYSTEM
SSH_AUTH_SOCK, SSH_AUTHORIZATION
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_*
AZURE_*, GOOGLE_*, GITHUB_*, NPM_CONFIG_*, PIP_CONFIG_FILE
CARGO_HOME, RUSTC_WRAPPER, RUSTFLAGS
```

Policy may extend the allowlist but may not remove mandatory deny entries.

### 2. Interpreter non-profile mode

| Interpreter | Flags |
|-------------|-------|
| Bash | `--noprofile --norc` |
| Zsh | `-f` (no rc files), unset `ZDOTDIR` |
| PowerShell | `-NoProfile` |
| Python | `-E` (ignore PYTHON* env), `-s` (no user site) |
| Node.js | (no `--require` from env; `NODE_OPTIONS` stripped) |

Behavior that requires user profiles is an explicit **lower-assurance exception** requiring policy approval.

### 3. Descriptor-pinned execution

**Linux:** prefer `fexecve`/`execveat` using an immutable file descriptor. Open the interpreter, verify its identity, then exec from the descriptor. This eliminates the TOCTOU window between path check and exec.

**Other platforms:** open and revalidate the executable immediately before process creation. Record the remaining race limitation in the receipt.

### 4. Temporary home and working directory

By default:

- `HOME` → temporary directory created with `0700` permissions.
- Working directory → separate temporary directory.
- Policy may specify known-safe paths or grant access to specific directories.

### 5. Controlled PATH

The execution `PATH` contains only:

- The system's trusted binary directories (`/usr/bin`, `/usr/local/bin` — policy-defined).
- Explicitly granted directories.

No user `bin`, no `node_modules/.bin`, no current directory.

### 6. Closed inherited file descriptors

All non-essential file descriptors are set to `O_CLOEXEC` before process creation. Only stdin, stdout, and stderr are inherited (and stdin may be replaced with `/dev/null` for non-interactive runs).

### 7. No privilege elevation

- `sudo`, `su`, `doas`, `pkexec`, UAC elevation are **blocked by default** in mediated execution.
- The main Arbitraitor process never runs as root/administrator.
- See ADR 0009.

### 8. Network denied by default

Network access during execution is **denied by default**. Enabling network is an explicit policy decision that **lowers the assurance label**:

```
PASS (mediated, network=denied)     ← default
PASS (mediated, network=enabled)    ← policy exception, lower trust
```

Unrestricted runtime network defeats transitive scanning: static second-stage discovery cannot prove that all runtime downloads were found. If the executed script has unrestricted network access, it can retrieve content from generated URLs, DNS-based endpoints, or benign-looking helper tools after approval.

## Consequences

- A scanned-and-approved script cannot be weaponized by manipulating the execution environment.
- Static analysis findings remain meaningful because the executed code runs in the context that was analyzed (no hidden profile files, no injected env vars).
- Network-denied default means transitive payload coverage claims are honest.
- Some legitimate scripts that require network or specific env vars will require explicit policy exceptions — this is intentional.

## Alternatives considered

- **Denylist instead of allowlist:** Rejected. New dangerous variables are discovered regularly; an allowlist is safer.
- **Inherit environment with sanitization:** Rejected. Too easy to miss a variable class.
- **Full containerization for all execution:** Deferred to contained mode. Mediated mode provides strong guarantees without requiring platform isolation support.

## References

- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §26 (Release and execution), §26.5 (Environment controls)
- `.spec/arbitraitor-adversarial-review-and-gap-analysis.md` C-01, C-02
- [ADR 0007](./0007-assurance-levels-model.md) — Assurance levels
- [ADR 0009](./0009-privilege-separation-no-root-invariant.md) — Privilege separation
