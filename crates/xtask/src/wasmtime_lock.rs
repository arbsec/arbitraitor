//! Lockfile guard for the RUSTSEC-2026-0327 wasmtime waiver.
//!
//! The `deny.toml` and `cargo audit` ignore lists match only the advisory
//! ID, so any *future* affected `wasmtime` copy would also be silently
//! ignored. This check pins what the waiver actually covers: `wasmtime
//! 45.0.3` reached only through `yara-x`. It rejects any other affected
//! version (`[39.0.0, 48.0.4)` or `[49.0.0, 49.0.2)`) unless the advisory
//! ignore entries in `deny.toml` and the security workflow have first been
//! dropped.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Advisory ID the waiver covers.
const ADVISORY: &str = "RUSTSEC-2026-0327";
/// The only wasmtime version the waiver is scoped to.
const WAIVED_VERSION: &str = "45.0.3";

/// A semver triple `(major, minor, patch)` from a version string.
///
/// Pre-release and build suffixes are stripped (`45.0.3-rc.1` -> `(45, 0,
/// 3)`); wasmtime does not ship pre-releases on crates.io, so this is
/// belt-and-braces.
fn parse_triple(version: &str) -> Option<(u64, u64, u64)> {
    let core = version.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// `true` when `version` falls inside one of RUSTSEC-2026-0327's affected
/// ranges: `[39.0.0, 48.0.4)` or `[49.0.0, 49.0.2)`.
fn affected(version: &str) -> bool {
    let Some(v) = parse_triple(version) else {
        return false;
    };
    let below = |b: (u64, u64, u64)| v < b;
    let at_least = |a: (u64, u64, u64)| v >= a;
    (at_least((39, 0, 0)) && below((48, 0, 4))) || (at_least((49, 0, 0)) && below((49, 0, 2)))
}

/// Returns `true` when `deny.toml` no longer carries an ignore entry for the
/// advisory, meaning the waiver was dropped and any wasmtime copy is fair
/// game for `cargo deny`/`cargo audit` to police on their own.
fn waiver_dropped(root: &Path) -> bool {
    let Ok(deny) = fs::read_to_string(root.join("deny.toml")) else {
        return false;
    };
    !deny.contains(ADVISORY)
}

/// One `[[package]]` block: crate name, version, and its direct
/// dependencies as (name, version) pairs (empty version when the edge
/// carries no disambiguator).
type PackageEdges = Vec<(String, String, BTreeSet<(String, String)>)>;

/// Extracts every package block in `Cargo.lock`.
///
/// Returns `(name, version, direct dependencies as (name, version)` pairs)
/// per `[[package]]` block, in file order. The version is the empty string
/// when the edge carries no disambiguator.
fn dependency_edges(lock: &str) -> PackageEdges {
    let mut edges = Vec::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut deps = BTreeSet::new();
    let mut in_deps = false;
    let mut flush =
        |name: &mut String, version: &mut String, deps: &mut BTreeSet<(String, String)>| {
            if !name.is_empty() {
                edges.push((
                    std::mem::take(name),
                    std::mem::take(version),
                    std::mem::take(deps),
                ));
            }
        };
    for line in lock.lines() {
        if line == "[[package]]" {
            flush(&mut name, &mut version, &mut deps);
            in_deps = false;
            continue;
        }
        if in_deps {
            // Dependency lines are quoted entries without a key
            // (`"wasmtime 45.0.3",`); the block ends at the `]` line. They
            // carry the crate name plus an optional version disambiguator
            // and an optional registry URL; the crate name and
            // disambiguator are the first two whitespace-separated fields.
            let trimmed = line.trim().trim_end_matches(',');
            if trimmed == "]" {
                in_deps = false;
                continue;
            }
            let unquoted = trimmed.trim_matches('"');
            let mut fields = unquoted.split_whitespace();
            let dep_name = fields.next().unwrap_or(unquoted).to_owned();
            let dep_version = fields.next().unwrap_or("").to_owned();
            deps.insert((dep_name, dep_version));
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key {
            "name" => {
                name = value.to_owned();
                in_deps = false;
            }
            "version" => {
                version = value.to_owned();
                in_deps = false;
            }
            "dependencies" => in_deps = true,
            _ => {}
        }
    }
    flush(&mut name, &mut version, &mut deps);
    edges
}

/// Runs the guard; returns `Err(reason)` on violation.
///
/// Walks `Cargo.lock` once, pairing every `[[package]]` block with its
/// `name`/`version` and dependency list. For each `wasmtime` package whose
/// version falls inside RUSTSEC-2026-0327's affected ranges, the only
/// accepted shape is the waived `45.0.3` copy reached exclusively through
/// `yara-x` (directly or via `yara-x-*` macros/parser crates). Anything
/// else fails the check with the offending edge named.
pub fn run(root: &Path) -> Result<(), String> {
    if waiver_dropped(root) {
        return Ok(());
    }
    let lock = fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|e| format!("cannot read Cargo.lock: {e}"))?;
    let edges = dependency_edges(&lock);

    // Reverse edges: (dependent name, dependent version) -> wasmtime copy
    // version. Keys of the map are the wasmtime versions in the lockfile.
    let mut parents_of: Vec<(String, Vec<String>)> = Vec::new();
    for (name, version, deps) in &edges {
        for (dep_name, dep_version) in deps {
            if dep_name != "wasmtime" {
                continue;
            }
            let entry = parents_of
                .iter_mut()
                .find(|(v, _)| v == dep_version || dep_version.is_empty());
            match entry {
                Some((_, parents)) => parents.push(format!("{name} {version}")),
                None => parents_of.push((dep_version.clone(), vec![format!("{name} {version}")])),
            }
        }
    }

    let mut violations: Vec<String> = Vec::new();
    for (version, parents) in &parents_of {
        if !affected(version) {
            continue;
        }
        if version == WAIVED_VERSION && parents.iter().all(|p| p.starts_with("yara-x")) {
            continue;
        }
        violations.push(format!(
            "wasmtime {version} is affected by {ADVISORY} but is not covered by \
             the lockfile waiver (only wasmtime {WAIVED_VERSION} via yara-x is waived); \
             reached via {}",
            if parents.is_empty() {
                "<no recorded parents>".to_owned()
            } else {
                parents.join(", ")
            }
        ));
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_suffixed_versions() {
        assert_eq!(parse_triple("45.0.3"), Some((45, 0, 3)));
        assert_eq!(parse_triple("49.0.2"), Some((49, 0, 2)));
        assert_eq!(parse_triple("45.0.3-rc.1"), Some((45, 0, 3)));
        assert_eq!(parse_triple("45.0.3+foo"), Some((45, 0, 3)));
        assert_eq!(parse_triple("junk"), None);
    }

    #[test]
    fn affected_ranges_match_advisory() {
        assert!(!affected("38.9.9"));
        assert!(affected("39.0.0"));
        assert!(affected("45.0.3"));
        assert!(affected("48.0.3"));
        assert!(!affected("48.0.4"));
        assert!(affected("49.0.0"));
        assert!(affected("49.0.1"));
        assert!(!affected("49.0.2"));
        assert!(!affected("50.0.0"));
    }

    fn write_guard_dir(dir: &Path, deny_contains_advisory: bool, lock: &str) {
        fs::create_dir_all(dir).expect("create guard dir");
        let deny = if deny_contains_advisory {
            format!("ignore = [\n    {{ id = \"{ADVISORY}\", reason = \"test\" }},\n]\n")
        } else {
            String::from("ignore = []\n")
        };
        fs::write(dir.join("deny.toml"), deny).expect("write deny.toml");
        fs::write(dir.join("Cargo.lock"), lock).expect("write Cargo.lock");
    }

    #[test]
    fn run_flags_direct_affected_wasmtime_outside_waiver() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-direct");
        let lock = r#"
[[package]]
name = "wasmtime"
version = "44.0.0"

[[package]]
name = "arbitraitor-plugin-host"
version = "0.1.0"
dependencies = [
 "wasmtime 44.0.0",
]

[[package]]
name = "yara-x"
version = "1.20.0"
dependencies = [
 "wasmtime 45.0.3",
]

[[package]]
name = "wasmtime"
version = "45.0.3"
"#;
        write_guard_dir(&dir, true, lock);
        let error = run(&dir).expect_err("direct affected copy must be rejected");
        assert!(error.contains("wasmtime 44.0.0"), "{error}");
        assert!(error.contains("arbitraitor-plugin-host"), "{error}");
    }

    #[test]
    fn run_accepts_waiver_only_yara_x_copy() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-waived");
        let lock = r#"
[[package]]
name = "yara-x"
version = "1.20.0"
dependencies = [
 "wasmtime 45.0.3",
]

[[package]]
name = "wasmtime"
version = "45.0.3"

[[package]]
name = "wasmtime"
version = "49.0.2"
dependencies = []
"#;
        write_guard_dir(&dir, true, lock);
        run(&dir).expect("waived yara-x copy plus patched direct copy must pass");
    }

    #[test]
    fn run_passes_when_waiver_dropped_from_deny_toml() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-dropped");
        let lock = r#"
[[package]]
name = "wasmtime"
version = "44.0.0"
"#;
        write_guard_dir(&dir, false, lock);
        run(&dir).expect("dropped waiver means no local pinning to enforce");
    }
}
