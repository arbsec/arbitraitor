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
/// The `cargo audit` suppression flag the security workflow must pass while
/// the waiver is active. Matching the full flag (not the bare advisory ID)
/// keeps comments, step names, or unrelated mentions of the ID from being
/// mistaken for an active suppression.
const IGNORE_FLAG: &str = "--ignore RUSTSEC-2026-0327";
/// The only wasmtime version the waiver is scoped to.
const WAIVED_VERSION: &str = "45.0.3";
/// Exact set of parent crates through which the waived copy is reached,
/// per the actual Cargo.lock (`yara-x` depends on wasmtime directly; its
/// `yara-x-parser`/`yara-x-macros` siblings do not). Matching the closed
/// set — not a `yara-x*` prefix — keeps a ghost crate named
/// `yara-x-evil` from laundering an affected copy through the waiver.
const WAIVED_PARENTS: [&str; 1] = ["yara-x"];

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

/// Outcome of checking where the RUSTSEC-2026-0327 waiver lives.
enum WaiverState {
    /// `deny.toml` carries the advisory waiver: enforce the lockfile pin.
    Active,
    /// The waiver was dropped from `deny.toml` and no stale reference
    /// remains anywhere: any wasmtime copy is fair game for `cargo deny`/
    /// `cargo audit` to police on their own; the guard is inert.
    Dropped,
    /// The waiver was dropped from `deny.toml` but `security.yml` still
    /// passes `--ignore` for the advisory to `cargo audit`: the suppression
    /// lives on with no lockfile pin — fail loudly.
    Asymmetric,
}

/// Classifies the waiver state from `deny.toml` and the security workflow.
fn waiver_state(root: &Path) -> WaiverState {
    let deny_has_waiver = fs::read_to_string(root.join("deny.toml"))
        .map(|deny| deny.contains(ADVISORY))
        .unwrap_or(false);
    let workflow_ignores = fs::read_to_string(root.join(".github/workflows/security.yml"))
        .map(|workflow| workflow.contains(IGNORE_FLAG))
        .unwrap_or(false);
    match (deny_has_waiver, workflow_ignores) {
        (true, _) => WaiverState::Active,
        (false, true) => WaiverState::Asymmetric,
        (false, false) => WaiverState::Dropped,
    }
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
    // Whether the current section is a `[[package]]` block. Field
    // collection (name/version/dependencies) and the flush paths are
    // gated on this so keys inside `[[patch.unused]]`, `[patch.*]`,
    // `[metadata]`, ... sections can never be mistaken for package
    // fields.
    let mut in_package = false;
    for line in lock.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.starts_with('[') {
            // Section header. Because field collection below is gated on
            // `in_package`, any pending name/version/deps here can only
            // have come from a `[[package]]` block, so flush it on every
            // header — a non-package header (`[[patch.unused]]`,
            // `[patch.*]`, `[metadata]`, ...) must not discard the real
            // package block that just ended, but neither can it launder
            // its own keys into package fields and masquerade as a
            // package.
            if in_package && !name.is_empty() {
                edges.push((
                    std::mem::take(&mut name),
                    std::mem::take(&mut version),
                    std::mem::take(&mut deps),
                ));
            } else {
                name.clear();
                version.clear();
                deps.clear();
            }
            in_package = trimmed_line == "[[package]]";
            in_deps = false;
            continue;
        }
        if !in_package {
            continue;
        }
        if in_deps {
            // Dependency lines are quoted entries without a key
            // (`"wasmtime 45.0.3",`); the block ends at the `]` line. They
            // carry the crate name plus an optional version disambiguator
            // and an optional registry URL; the crate name and
            // disambiguator are the first two whitespace-separated fields.
            if trimmed_line == "]" {
                in_deps = false;
                continue;
            }
            insert_dep_entry(trimmed_line, &mut deps);
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        let value = value.trim();
        match key {
            "name" => {
                name = value.trim_matches('"').to_owned();
                in_deps = false;
            }
            "version" => {
                version = value.trim_matches('"').to_owned();
                in_deps = false;
            }
            "dependencies" => {
                in_deps = false;
                let Some(rest) = value.strip_prefix('[') else {
                    continue;
                };
                if let Some(inline) = rest.strip_suffix(']') {
                    // Inline form: `dependencies = ["wasmtime 45.0.3"]`.
                    for entry in inline.split(',') {
                        if entry.trim().is_empty() {
                            continue;
                        }
                        insert_dep_entry(entry, &mut deps);
                    }
                } else {
                    in_deps = true;
                }
            }
            _ => {}
        }
    }
    // A file ending inside a package section flushes normally; a trailing
    // non-package section leaves `in_package` false so nothing is emitted.
    if in_package && !name.is_empty() {
        edges.push((name, version, deps));
    }
    edges
}

/// Inserts one quoted dependency entry (`"wasmtime 45.0.3"` or
/// `"wasmtime"`) into `deps`.
fn insert_dep_entry(entry: &str, deps: &mut BTreeSet<(String, String)>) {
    let unquoted = entry.trim().trim_end_matches(',').trim_matches('"');
    let mut fields = unquoted.split_whitespace();
    let dep_name = fields.next().unwrap_or(unquoted).to_owned();
    let dep_version = fields.next().unwrap_or("").to_owned();
    deps.insert((dep_name, dep_version));
}

/// Runs the guard; returns `Err(reason)` on violation.
///
/// Walks `Cargo.lock` once, pairing every `[[package]]` block with its
/// `name`/`version` and dependency list. For each `wasmtime` package whose
/// version falls inside RUSTSEC-2026-0327's affected ranges, the only
/// accepted shape is the waived `45.0.3` copy reached exclusively through
/// the exact parent set in [`WAIVED_PARENTS`]. Anything
/// else fails the check with the offending edge named.
pub fn run(root: &Path) -> Result<(), String> {
    match waiver_state(root) {
        WaiverState::Active => {}
        WaiverState::Dropped => return Ok(()),
        WaiverState::Asymmetric => {
            return Err(format!(
                "{ADVISORY} waiver was dropped from deny.toml but \
                 .github/workflows/security.yml still passes --ignore {ADVISORY} to \
                 cargo audit: the suppression lives on with no lockfile pin. Remove the \
                 stale --ignore from the workflow, or restore the deny.toml waiver."
            ));
        }
    }
    let lock = fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|e| format!("cannot read Cargo.lock: {e}"))?;
    let edges = dependency_edges(&lock);

    // Cargo writes a versionless edge (`"wasmtime"`) when the lockfile has
    // exactly one wasmtime copy. Collect the wasmtime versions FIRST and
    // resolve every versionless edge against that set; an ambiguous or
    // unknown target fails closed instead of silently matching the wrong
    // (or no) copy.
    let wasmtime_versions: Vec<String> = edges
        .iter()
        .filter(|(name, _, _)| name == "wasmtime")
        .map(|(_, version, _)| version.clone())
        .collect();
    let resolve_edge_version = |dep_version: &str| -> Result<String, String> {
        if !dep_version.is_empty() {
            return Ok(dep_version.to_owned());
        }
        match wasmtime_versions.as_slice() {
            [] => Err(format!(
                "{ADVISORY}: Cargo.lock contains a versionless wasmtime \
                 dependency edge but no wasmtime [[package]] block; cannot \
                 determine which copy the edge targets"
            )),
            [only] => Ok(only.clone()),
            many => Err(format!(
                "{ADVISORY}: Cargo.lock contains a versionless wasmtime \
                 dependency edge but multiple wasmtime copies ({}); cannot \
                 determine which copy the edge targets",
                many.join(", ")
            )),
        }
    };

    // Reverse edges: (dependent name, dependent version) -> wasmtime copy
    // version. Keys of the map are the resolved wasmtime versions.
    let mut parents_of: Vec<(String, Vec<String>)> = Vec::new();
    for (name, version, deps) in &edges {
        for (dep_name, dep_version) in deps {
            if dep_name != "wasmtime" {
                continue;
            }
            let resolved = resolve_edge_version(dep_version)?;
            let entry = parents_of.iter_mut().find(|(v, _)| v == &resolved);
            match entry {
                Some((_, parents)) => parents.push(format!("{name} {version}")),
                None => parents_of.push((resolved, vec![format!("{name} {version}")])),
            }
        }
    }

    let mut violations: Vec<String> = Vec::new();
    for (version, parents) in &parents_of {
        if !affected(version) {
            continue;
        }
        if version == WAIVED_VERSION
            && parents.iter().all(|p| {
                p.split_once(' ')
                    .is_some_and(|(name, _)| WAIVED_PARENTS.contains(&name))
            })
        {
            continue;
        }
        violations.push(format!(
            "wasmtime {version} is affected by {ADVISORY} but is not covered by \
             the lockfile waiver (only wasmtime {WAIVED_VERSION} via {} is waived); \
             reached via {}",
            WAIVED_PARENTS.join(", "),
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
        write_guard_dir_with_workflow(dir, deny_contains_advisory, deny_contains_advisory, lock);
    }

    fn write_guard_dir_with_workflow(
        dir: &Path,
        deny_contains_advisory: bool,
        workflow_contains_advisory: bool,
        lock: &str,
    ) {
        fs::create_dir_all(dir.join(".github/workflows")).expect("create guard dir");
        let deny = if deny_contains_advisory {
            format!("ignore = [\n    {{ id = \"{ADVISORY}\", reason = \"test\" }},\n]\n")
        } else {
            String::from("ignore = []\n")
        };
        fs::write(dir.join("deny.toml"), deny).expect("write deny.toml");
        let workflow = if workflow_contains_advisory {
            format!("run: cargo audit --ignore {ADVISORY}\n")
        } else {
            String::from("run: cargo audit\n")
        };
        fs::write(dir.join(".github/workflows/security.yml"), workflow)
            .expect("write security.yml");
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
        write_guard_dir_with_workflow(&dir, false, false, lock);
        run(&dir).expect("dropped waiver means no local pinning to enforce");
    }

    #[test]
    fn run_fails_when_waiver_dropped_but_workflow_still_ignores() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-asymmetric");
        let lock = r#"
[[package]]
name = "wasmtime"
version = "44.0.0"
"#;
        write_guard_dir_with_workflow(&dir, false, true, lock);
        let error = run(&dir).expect_err("stale workflow ignore with dropped waiver must fail");
        assert!(error.contains("deny.toml"), "{error}");
        assert!(error.contains("security.yml"), "{error}");
    }

    #[test]
    fn workflow_comment_mentioning_advisory_is_not_an_ignore() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-comment-only");
        let lock = r#"
[[package]]
name = "wasmtime"
version = "44.0.0"
"#;
        write_guard_dir(&dir, false, lock);
        // The workflow mentions the advisory ID only in a comment and a step
        // name; without the actual --ignore flag this must classify as
        // Dropped, not Asymmetric.
        fs::write(
            dir.join(".github/workflows/security.yml"),
            r#"# RUSTSEC-2026-0327 waiver removed; do not re-add --ignore
- name: audit (RUSTSEC-2026-0327 unwaived)
  run: cargo audit
"#,
        )
        .expect("write security.yml");
        run(&dir).expect("comment-only advisory mention must not count as an ignore");
    }

    #[test]
    fn versionless_edge_resolves_single_wasmtime_copy_and_flags_affected() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-versionless-single");
        // Cargo writes the edge without a version disambiguator when the
        // lockfile holds exactly one wasmtime copy.
        let lock = r#"
[[package]]
name = "arbitraitor-plugin-host"
version = "0.1.0"
dependencies = [
 "wasmtime",
]

[[package]]
name = "wasmtime"
version = "44.0.0"
"#;
        write_guard_dir(&dir, true, lock);
        let error = run(&dir).expect_err("versionless edge to an affected copy must be flagged");
        assert!(error.contains("wasmtime 44.0.0"), "{error}");
        assert!(error.contains("arbitraitor-plugin-host"), "{error}");
    }

    #[test]
    fn versionless_edge_with_multiple_wasmtime_copies_fails_closed() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-versionless-ambiguous");
        let lock = r#"
[[package]]
name = "arbitraitor-plugin-host"
version = "0.1.0"
dependencies = [
 "wasmtime",
]

[[package]]
name = "wasmtime"
version = "45.0.3"

[[package]]
name = "wasmtime"
version = "44.0.0"
"#;
        write_guard_dir(&dir, true, lock);
        let error =
            run(&dir).expect_err("versionless edge with two wasmtime copies must fail closed");
        assert!(error.contains("versionless wasmtime"), "{error}");
        assert!(error.contains("45.0.3"), "{error}");
        assert!(error.contains("44.0.0"), "{error}");
    }

    #[test]
    fn versionless_edge_with_no_wasmtime_package_fails_closed() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-versionless-orphan");
        let lock = r#"
[[package]]
name = "arbitraitor-plugin-host"
version = "0.1.0"
dependencies = [
 "wasmtime",
]
"#;
        write_guard_dir(&dir, true, lock);
        let error =
            run(&dir).expect_err("versionless edge with zero wasmtime packages must fail closed");
        assert!(error.contains("versionless wasmtime"), "{error}");
        assert!(error.contains("no wasmtime [[package]] block"), "{error}");
    }

    #[test]
    fn trailing_patch_unused_after_affected_dependent_still_flags() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-patch-trailing");
        let lock = r#"
[[package]]
name = "zzz-evil-relay"
version = "0.1.0"
dependencies = [
 "wasmtime 45.0.3",
]

[[package]]
name = "wasmtime"
version = "45.0.3"

[[patch.unused]]
name = "yara-x"
version = "1.20.0"
"#;
        write_guard_dir(&dir, true, lock);
        let error = run(&dir).expect_err("trailing [[patch.unused]] must not launder the edge");
        assert!(error.contains("wasmtime 45.0.3"), "{error}");
        assert!(error.contains("zzz-evil-relay"), "{error}");
    }

    #[test]
    fn patch_unused_named_yara_x_does_not_waive_precedent_dependent() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-patch-yara-ghost");
        let lock = r#"
[[package]]
name = "zzz-evil-relay"
version = "0.1.0"
dependencies = [
 "wasmtime 45.0.3",
]

[[package]]
name = "wasmtime"
version = "45.0.3"

[[patch.unused]]
name = "yara-x"
version = "1.20.0"
dependencies = [
 "wasmtime 45.0.3",
]
"#;
        write_guard_dir(&dir, true, lock);
        let error = run(&dir).expect_err("a [[patch.unused]] yara-x entry must not waive the edge");
        assert!(error.contains("zzz-evil-relay"), "{error}");
    }

    #[test]
    fn patch_and_metadata_section_headers_are_not_packages() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-section-headers");
        let lock = r#"
[[package]]
name = "zzz-evil-relay"
version = "0.1.0"
dependencies = [
 "wasmtime 45.0.3",
]

[[package]]
name = "wasmtime"
version = "45.0.3"

[patch.crates-io]
name = "yara-x"
version = "1.20.0"

[metadata]
name = "yara-x"
version = "1.20.0"
dependencies = [
 "wasmtime 45.0.3",
]
"#;
        write_guard_dir(&dir, true, lock);
        let error =
            run(&dir).expect_err("[patch.*]/[metadata] headers must not become package blocks");
        assert!(error.contains("zzz-evil-relay"), "{error}");
    }

    #[test]
    fn metadata_multiline_content_after_packages_is_ignored() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-metadata-multiline");
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

[metadata]
wasmtime-45.0.3-checksum = "abcd"
notes = """
wasmtime 45.0.3 vendored via yara-x
"""
"#;
        write_guard_dir(&dir, true, lock);
        run(&dir).expect("trailing [metadata] content must not corrupt parsed edges");
    }

    #[test]
    fn inline_dependency_array_is_parsed() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-inline-deps");
        let lock = r#"
[[package]]
name = "zzz-evil-relay"
version = "0.1.0"
dependencies = ["wasmtime 45.0.3"]

[[package]]
name = "wasmtime"
version = "45.0.3"
"#;
        write_guard_dir(&dir, true, lock);
        let error = run(&dir).expect_err("inline dependency array must not lose the edge");
        assert!(error.contains("wasmtime 45.0.3"), "{error}");
        assert!(error.contains("zzz-evil-relay"), "{error}");
    }

    #[test]
    fn ghost_yara_x_prefix_parent_does_not_waive() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-ghost-prefix");
        let lock = r#"
[[package]]
name = "yara-x-evil"
version = "0.1.0"
dependencies = [
 "wasmtime 45.0.3",
]

[[package]]
name = "wasmtime"
version = "45.0.3"
"#;
        write_guard_dir(&dir, true, lock);
        let error = run(&dir).expect_err("prefix-matched ghost parent must not waive the edge");
        assert!(error.contains("yara-x-evil"), "{error}");
    }

    #[test]
    fn valid_lockfile_with_trailing_unused_wasmtime_patch_passes() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-trailing-patch-valid");
        // A valid lockfile: exactly one resolved wasmtime copy (45.0.3, via
        // yara-x with a versionless edge) plus a trailing [[patch.unused]]
        // entry naming wasmtime 44.0.0. The patch entry must NOT be counted
        // as a second wasmtime copy, or the versionless edge would fail
        // closed with "multiple wasmtime copies" and reject a valid
        // lockfile.
        let lock = r#"
[[package]]
name = "yara-x"
version = "1.20.0"
dependencies = [
 "wasmtime",
]

[[package]]
name = "wasmtime"
version = "45.0.3"

[[patch.unused]]
name = "wasmtime"
version = "44.0.0"
"#;
        write_guard_dir(&dir, true, lock);
        run(&dir).expect("trailing [[patch.unused]] wasmtime entry must not look like a copy");
    }

    #[test]
    fn unused_patch_between_packages_does_not_create_phantom_edge() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-patch-between-packages");
        // A [[patch.unused]] block between two [[package]] blocks: its
        // collected name/version/dependencies must be discarded at the
        // next [[package]] header, not flushed as a phantom wasmtime copy.
        // With the fix there is exactly one wasmtime copy (44.0.0), so the
        // dependent's versionless edge resolves to it and the affected
        // copy is flagged — never a "multiple wasmtime copies" error.
        let lock = r#"
[[package]]
name = "zzz-evil-relay"
version = "0.1.0"
dependencies = [
 "wasmtime",
]

[[patch.unused]]
name = "wasmtime"
version = "44.0.0"
dependencies = [
 "something-else 1.0.0",
]

[[package]]
name = "wasmtime"
version = "44.0.0"
"#;
        write_guard_dir(&dir, true, lock);
        let error = run(&dir).expect_err("inter-block patch must not suppress the real flagging");
        assert!(error.contains("wasmtime 44.0.0"), "{error}");
        assert!(error.contains("zzz-evil-relay"), "{error}");
        assert!(!error.contains("multiple wasmtime copies"), "{error}");
    }

    #[test]
    fn fields_outside_package_sections_are_ignored() {
        let dir = std::env::temp_dir().join("xtask-wasmtime-guard-fields-outside-packages");
        // A trailing [metadata] section carrying name/version/dependencies
        // keys that reference wasmtime: those fields must contribute no
        // edges, so the guard sees only the single waived 45.0.3 copy and
        // passes.
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

[metadata]
name = "wasmtime"
version = "44.0.0"
dependencies = [
 "wasmtime 45.0.3",
]
"#;
        write_guard_dir(&dir, true, lock);
        run(&dir).expect("[metadata] fields must not create edges or copies");
    }
}
