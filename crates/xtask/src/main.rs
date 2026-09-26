use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime};

const REPO_ROOT: &str = env!("CARGO_MANIFEST_DIR");

const USAGE: &str = "usage: xtask docs-check | cleanup [worktrees|artifacts] [--yes] [--days <n>]";

fn repo_root() -> PathBuf {
    Path::new(REPO_ROOT)
        .ancestors()
        .nth(2)
        .expect("could not determine repo root from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

struct Adr {
    number: String,
    title: String,
}

fn collect_adr_files(dir: &Path) -> Vec<Adr> {
    let mut adrs = Vec::new();
    let entries = fs::read_dir(dir).unwrap_or_else(|e| {
        eprintln!("error: cannot read {}: {e}", dir.display());
        std::process::exit(1);
    });
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".md") || name == "README.md" {
            continue;
        }
        let path = entry.path();
        let content = fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error: cannot read {}: {e}", path.display());
            std::process::exit(1);
        });
        let h1 = content
            .lines()
            .find(|l| l.starts_with("# "))
            .unwrap_or_else(|| {
                eprintln!("error: no H1 heading in {}", path.display());
                std::process::exit(1);
            });
        let rest = h1.trim_start_matches("# ADR ");
        let (number, title) = rest.split_once(": ").unwrap_or((rest, ""));
        adrs.push(Adr {
            number: number.to_string(),
            title: title.to_string(),
        });
    }
    adrs.sort_by(|a, b| a.number.cmp(&b.number));
    adrs
}

fn collect_summary_adrs(summary: &str) -> Vec<Adr> {
    let mut adrs = Vec::new();
    for line in summary.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("- [ADR ") {
            continue;
        }
        let start = trimmed.find("[ADR ").map(|i| i + 5);
        let colon = trimmed.find(": ");
        let close = trimmed.find("](");
        if let (Some(s), Some(c), Some(cl)) = (start, colon, close)
            && s < c
            && c < cl
        {
            let number = trimmed[s..c].to_string();
            let title = trimmed[c + 2..cl].to_string();
            adrs.push(Adr { number, title });
        }
    }
    adrs.sort_by(|a, b| a.number.cmp(&b.number));
    adrs
}

fn normalize_title(s: &str) -> String {
    strip_spec_citation(s)
        .replace(['`', '"'], "")
        .replace(" = ", "=")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Remove parenthetical spec-paragraph citations that name an internal
/// section, so titles in `docs/adr/` and the book SUMMARY compare equal
/// regardless of whether the internal document section is named.
/// Citations are stripped from user-facing surfaces; this keeps the mirror
/// check focused on the title itself.
fn strip_spec_citation(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s.as_bytes()[i] == b'('
            && s[i..].starts_with("(spec §")
            && let Some(close) = s[i..].find(')')
        {
            i += close + 1;
            continue;
        }
        let ch = s[i..].chars().next().expect("valid UTF-8");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn check_adrs(root: &Path) -> bool {
    let adr_dir = root.join("docs/adr");
    let summary_path = root.join("book/src/SUMMARY.md");
    let summary = fs::read_to_string(&summary_path).unwrap_or_else(|e| {
        eprintln!("error: cannot read {}: {e}", summary_path.display());
        std::process::exit(1);
    });
    let files = collect_adr_files(&adr_dir);
    let summary_adrs = collect_summary_adrs(&summary);
    let file_map: BTreeMap<&str, &str> = files
        .iter()
        .map(|a| (a.number.as_str(), a.title.as_str()))
        .collect();
    let summary_map: BTreeMap<&str, &str> = summary_adrs
        .iter()
        .map(|a| (a.number.as_str(), a.title.as_str()))
        .collect();
    let mut ok = true;
    for (num, title) in &file_map {
        match summary_map.get(*num) {
            Some(t) if normalize_title(t) != normalize_title(title) => {
                eprintln!(
                    "ADR {num}: title mismatch — file says \"{title}\", SUMMARY says \"{t}\""
                );
                ok = false;
            }
            None => {
                eprintln!("ADR {num}: in docs/adr/ but missing from SUMMARY.md");
                ok = false;
            }
            _ => {}
        }
    }
    for num in summary_map.keys() {
        if !file_map.contains_key(*num) {
            eprintln!("ADR {num}: in SUMMARY.md but no file in docs/adr/");
            ok = false;
        }
    }
    if ok {
        println!("ok: {} ADRs in docs/adr/ match SUMMARY.md", files.len());
    }
    ok
}

// ---------------------------------------------------------------------------
// cleanup: worktree + build-artifact maintenance
// ---------------------------------------------------------------------------

/// A single record of `git worktree list --porcelain`.
#[derive(Debug, PartialEq, Eq)]
struct WorktreeEntry {
    /// Worktree checkout directory.
    path: PathBuf,
    /// Short branch name (e.g. `fix/foo`) when the worktree is on a branch;
    /// `None` when detached.
    branch: Option<String>,
    /// `locked` in porcelain output (protected against removal by git).
    locked: bool,
    /// `bare` record (the main repository checkout of a bare clone).
    bare: bool,
}

fn parse_worktree_porcelain(out: &str) -> Vec<WorktreeEntry> {
    let mut entries = Vec::new();
    let mut current_path: Option<PathBuf> = None;
    let mut current_branch: Option<String> = None;
    let mut current_locked = false;
    let mut current_bare = false;
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("worktree ") {
            if let Some(path) = current_path.take() {
                entries.push(WorktreeEntry {
                    path,
                    branch: current_branch.take(),
                    locked: current_locked,
                    bare: current_bare,
                });
            }
            current_path = Some(PathBuf::from(rest.trim_end()));
            current_branch = None;
            current_locked = false;
            current_bare = false;
            continue;
        }
        if current_path.is_none() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("branch ") {
            current_branch = Some(
                rest.trim_end()
                    .strip_prefix("refs/heads/")
                    .unwrap_or(rest.trim_end())
                    .to_string(),
            );
        } else if line.starts_with("locked") {
            current_locked = true;
        } else if line.starts_with("bare") {
            current_bare = true;
        }
    }
    if let Some(path) = current_path {
        entries.push(WorktreeEntry {
            path,
            branch: current_branch.take(),
            locked: current_locked,
            bare: current_bare,
        });
    }
    entries
}

/// Extract the value of a JSON string field from a flat JSON payload such as
/// `{"state":"MERGED"}`. Values are expected to be simple unescaped strings
/// (enum names, identifiers); anything else fails to extract rather than
/// guessing.
fn extract_json_string_field(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let mut i = 0;
    while let Some(pos) = json[i..].find(&needle) {
        let start = i + pos + needle.len();
        let rest = json[start..].trim_start();
        if let Some(value) = rest.strip_prefix(':') {
            let value = value.trim_start();
            let value = value.strip_prefix('"')?;
            if let Some(end) = value.find('"') {
                if value[..end].contains('\\') {
                    return None; // escaped content: out of scope for this tool
                }
                return Some(value[..end].to_string());
            }
            return None;
        }
        // nested occurrence; keep scanning after this needle
        i = start;
    }
    None
}

/// A summary of `gh pr list --json headRefOid,state` output.
#[derive(Debug, PartialEq, Eq)]
struct PrRecord {
    state: String,
    head_oid: String,
}

/// Parse the flat JSON array gh prints for `--json headRefOid,state`.
/// gh emits keys in sorted order, so each record's `headRefOid` precedes its
/// `state`; records are isolated by slicing between consecutive `headRefOid`
/// keys. Values are simple unescaped strings (enum names, hex SHAs); anything
/// else fails to extract rather than guessing.
fn parse_pr_records(json: &str) -> Vec<PrRecord> {
    let hay = json.trim();
    if !hay.starts_with('[') {
        return Vec::new();
    }
    const KEY: &str = "\"headRefOid\"";
    let mut key_starts: Vec<usize> = hay.match_indices(KEY).map(|(i, _)| i).collect();
    key_starts.push(hay.len());
    let mut records = Vec::new();
    for (n, &start) in key_starts.iter().take(key_starts.len() - 1).enumerate() {
        let stop = key_starts[n + 1];
        // Rebuild a minimal object so extract_json_string_field can read the
        // fields: {"headRefOid":"<oid>","state":"<state>"}
        let slice = &hay[start..stop];
        let object = format!("{{{slice}");
        let Some(head_oid) = extract_json_string_field(&object, "headRefOid") else {
            return Vec::new();
        };
        let Some(state) = extract_json_string_field(&object, "state") else {
            return Vec::new();
        };
        records.push(PrRecord { state, head_oid });
    }
    records
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrState {
    Open,
    Merged,
    Closed,
    /// PRs exist for the branch name but none of them matches this branch's
    /// HEAD SHA (recycled branch name); treat as unsubmitted work.
    HeadMismatch,
    None,
}

/// Decide the cleanup action from PR records versus the local branch HEAD.
/// A PR only counts when its `headRefOid` equals the worktree's HEAD, so a
/// branch name recycled from a previously merged PR cannot cause deletion of
/// unrelated work. Open takes precedence over Merged, which takes precedence
/// over Closed (most-conservative state wins).
fn decide_pr_state(records: &[PrRecord], local_head: &str) -> PrState {
    let mut saw_open = false;
    let mut saw_merged = false;
    let mut saw_closed = false;
    for record in records {
        if record.head_oid.eq_ignore_ascii_case(local_head)
            && match record.state.to_ascii_uppercase().as_str() {
                "OPEN" => {
                    saw_open = true;
                    true
                }
                "MERGED" => {
                    saw_merged = true;
                    true
                }
                "CLOSED" => {
                    saw_closed = true;
                    true
                }
                _ => false,
            }
        {
            continue;
        }
    }
    if saw_open {
        PrState::Open
    } else if saw_merged {
        PrState::Merged
    } else if saw_closed {
        PrState::Closed
    } else if records.is_empty() {
        PrState::None
    } else {
        PrState::HeadMismatch
    }
}

/// Parse `owner/repo` from a git remote URL (https or ssh form).
fn parse_repo_slug(url: &str) -> Option<String> {
    let url = url.trim();
    let tail = if let Some(rest) = url.strip_prefix("https://") {
        rest.split_once('/').map(|(_, tail)| tail).unwrap_or(rest)
    } else if let Some(rest) = url.strip_prefix("git@") {
        rest.split_once(':').map(|(_, tail)| tail).unwrap_or(rest)
    } else {
        let after_scheme = url.split("://").nth(1);
        match after_scheme.and_then(|rest| rest.split_once('/')) {
            Some((_, tail)) => tail,
            None => return None,
        }
    };
    let tail = tail.trim_end_matches('/');
    let tail = tail.strip_suffix(".git").unwrap_or(tail);
    let (owner, name) = tail.rsplit_once('/')?;
    if owner.is_empty() || name.is_empty() {
        return None;
    }
    Some(format!("{owner}/{name}"))
}

fn fmt_bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    let n = n as f64;
    if n < KIB {
        format!("{n:.0} B")
    } else if n < KIB * KIB {
        format!("{:.1} KB", n / KIB)
    } else if n < KIB * KIB * KIB {
        format!("{:.1} MB", n / (KIB * KIB))
    } else {
        format!("{:.1} GB", n / (KIB * KIB * KIB))
    }
}

fn fmt_days_ago(age: Duration) -> String {
    let days = age.as_secs() / 86_400;
    let hours = (age.as_secs() % 86_400) / 3_600;
    if days > 0 {
        format!("{days}d{hours}h")
    } else {
        let minutes = (age.as_secs() % 3_600) / 60;
        format!("{hours}h{minutes}m")
    }
}

/// Run a subprocess and fail the whole cleanup run on a non-zero exit.
/// Arguments are passed as OS strings (never through a shell), so hostile
/// branch names cannot become commands.
fn run_capture(cwd: &Path, program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .current_dir(cwd)
        .args(args)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!("{program}: command not found (install {program} first)")
            } else {
                format!("{program}: {e}")
            }
        })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let mut shown = format!("{program} {args:?} failed");
        if !stderr.is_empty() {
            shown.push_str(": ");
            shown.push_str(&stderr);
        }
        return Err(shown);
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Resolve what to do with `branch` in `worktree`: fetch that branch's HEAD
/// SHA, list every PR whose head branch matches by name, and let
/// `decide_pr_state` pick the safe action (SHA match required).
fn query_pr_state(
    root: &Path,
    worktree: &Path,
    repo: &str,
    branch: &str,
) -> Result<PrState, String> {
    let head = run_capture(worktree, "git", &["rev-parse", "HEAD"])?
        .trim()
        .to_string();
    if head.is_empty() {
        return Err(format!("no HEAD SHA resolved in {}", worktree.display()));
    }
    let out = run_capture(
        root,
        "gh",
        &[
            "pr",
            "list",
            "--repo",
            repo,
            "--head",
            branch,
            "--state",
            "all",
            "--json",
            "headRefOid,state",
        ],
    )?;
    Ok(decide_pr_state(&parse_pr_records(&out), &head))
}

/// Max mtime and total byte size of everything under `dir` (dirs included in
/// the mtime scan; symlinks are counted but never followed).
fn dir_age_and_size(dir: &Path, now: SystemTime) -> Result<(Duration, u64), String> {
    if fs::symlink_metadata(dir)
        .map_err(|e| format!("cannot stat {}: {e}", dir.display()))?
        .file_type()
        .is_symlink()
    {
        return Err(format!("{} is a symlink; refusing to scan", dir.display()));
    }
    let mut stack = vec![dir.to_path_buf()];
    let mut max_mtime: Option<SystemTime> = None;
    let mut total: u64 = 0;
    while let Some(p) = stack.pop() {
        let meta =
            fs::symlink_metadata(&p).map_err(|e| format!("cannot stat {}: {e}", p.display()))?;
        if meta.is_symlink() {
            total += meta.len();
            if let Ok(mt) = meta.modified() {
                max_mtime = max_mtime.map_or(Some(mt), |m| Some(m.max(mt)));
            }
            continue; // never follow links
        }
        if meta.is_dir() {
            if let Ok(mt) = meta.modified() {
                max_mtime = max_mtime.map_or(Some(mt), |m| Some(m.max(mt)));
            }
            let rd = fs::read_dir(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
            for entry in rd {
                stack.push(entry.map_err(|e| format!("{e}"))?.path());
            }
            continue;
        }
        total += meta.len();
        if let Ok(mt) = meta.modified() {
            max_mtime = max_mtime.map_or(Some(mt), |m| Some(m.max(mt)));
        }
    }
    let mtime = max_mtime.ok_or_else(|| format!("{} is empty", dir.display()))?;
    Ok((now.duration_since(mtime).unwrap_or(Duration::ZERO), total))
}

struct CleanOptions {
    /// Apply deletions; otherwise only report (`--yes`).
    apply: bool,
    /// Artifacts older than this are removed (`--days`, default 7).
    artifact_max_age: Duration,
}

fn clean_worktrees(root: &Path, opts: &CleanOptions) -> Result<usize, String> {
    let out = run_capture(root, "git", &["worktree", "list", "--porcelain"])?;
    let entries = parse_worktree_porcelain(&out);
    let mut errors = 0usize;
    let mut removed = 0usize;
    if entries.len() <= 1 {
        println!("cleanup worktrees: no secondary worktrees found");
        return Ok(removed);
    }
    let main = fs::canonicalize(&entries[0].path)
        .map_err(|e| format!("cannot canonicalize main worktree: {e}"))?;
    let remote = run_capture(root, "git", &["remote", "get-url", "origin"])?;
    let repo = parse_repo_slug(&remote).ok_or_else(|| {
        format!(
            "cleanup worktrees: cannot determine owner/repo from origin remote {:?}",
            remote.trim()
        )
    })?;

    for entry in &entries[1..] {
        let display_path = entry.path.display().to_string();
        if !entry.path.is_dir() {
            println!(
                "cleanup worktrees: stale entry {display_path} (missing on disk; git worktree prune handles it)"
            );
            continue;
        }
        let canonical = match fs::canonicalize(&entry.path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("cleanup worktrees: skip {display_path}: cannot canonicalize: {e}");
                errors += 1;
                continue;
            }
        };
        if canonical == main {
            continue;
        }
        if entry.bare || entry.branch.is_none() {
            println!("cleanup worktrees: skip {display_path} (bare or detached; manual review)");
            errors += 1;
            continue;
        }
        if entry.locked {
            println!("cleanup worktrees: skip {display_path} (locked by git)");
            continue;
        }
        let status = run_capture(&entry.path, "git", &["status", "--porcelain"])?;
        if !status.trim().is_empty() {
            println!(
                "cleanup worktrees: skip {display_path} (working tree not clean; inspect manually)"
            );
            continue;
        }
        let branch = entry.branch.as_deref().unwrap_or_default();
        let state = query_pr_state(root, &entry.path, &repo, branch)?;
        match state {
            PrState::Open => {
                println!("cleanup worktrees: keep {display_path} (branch {branch}: open PR)");
            }
            PrState::None => {
                println!(
                    "cleanup worktrees: keep {display_path} (branch {branch}: no PR found; unsubmitted work is not removed)"
                );
            }
            PrState::HeadMismatch => {
                println!(
                    "cleanup worktrees: keep {display_path} (branch {branch}: PRs exist for this branch name but none matches its HEAD; unsubmitted work is not removed)"
                );
            }
            PrState::Merged | PrState::Closed => {
                let label = if state == PrState::Merged {
                    "merged"
                } else {
                    "closed"
                };
                if opts.apply {
                    if let Err(e) = run_capture(root, "git", &["worktree", "remove", &display_path])
                    {
                        eprintln!("cleanup worktrees: error removing {display_path}: {e}");
                        errors += 1;
                        continue;
                    }
                    if let Err(e) = run_capture(root, "git", &["branch", "-D", branch]) {
                        eprintln!("cleanup worktrees: error deleting branch {branch}: {e}");
                        errors += 1;
                        continue;
                    }
                    removed += 1;
                    println!(
                        "cleanup worktrees: removed {display_path} (branch {branch}: {label} PR; branch deleted)"
                    );
                } else {
                    println!(
                        "cleanup worktrees: [dry-run] would remove {display_path} (branch {branch}: {label} PR)"
                    );
                }
            }
        }
    }
    if opts.apply
        && let Err(e) = run_capture(root, "git", &["worktree", "prune"])
    {
        eprintln!("cleanup worktrees: prune failed: {e}");
        errors += 1;
    }
    if errors > 0 {
        return Err(format!("{errors} worktree(s) need manual attention"));
    }
    Ok(removed)
}

fn clean_artifacts(root: &Path, opts: &CleanOptions) -> Result<u64, String> {
    let out = run_capture(root, "git", &["worktree", "list", "--porcelain"])?;
    let entries = parse_worktree_porcelain(&out);
    let now = SystemTime::now();
    let mut freed = 0u64;
    let mut errors = 0usize;
    for entry in &entries {
        if entry.bare {
            continue;
        }
        let target = entry.path.join("target");
        if !target.is_dir() {
            continue;
        }
        if entry.locked {
            println!(
                "cleanup artifacts: skip {} (worktree locked by git)",
                target.display()
            );
            continue;
        }
        let (age, size) = match dir_age_and_size(&target, now) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("cleanup artifacts: skip {}: {e}", target.display());
                errors += 1;
                continue;
            }
        };
        let label = entry.branch.as_deref().unwrap_or("(main)");
        if age >= opts.artifact_max_age {
            if opts.apply {
                if let Err(e) = fs::remove_dir_all(&target) {
                    eprintln!(
                        "cleanup artifacts: error removing {}: {e}",
                        target.display()
                    );
                    errors += 1;
                    continue;
                }
                freed += size;
                println!(
                    "cleanup artifacts: removed {} ({}, {} old; worktree {})",
                    target.display(),
                    fmt_bytes(size),
                    fmt_days_ago(age),
                    label
                );
            } else {
                freed += size;
                println!(
                    "cleanup artifacts: [dry-run] would remove {} ({}, {} old; worktree {})",
                    target.display(),
                    fmt_bytes(size),
                    fmt_days_ago(age),
                    label
                );
            }
        } else {
            println!(
                "cleanup artifacts: keep {} ({}, {} old; worktree {}; threshold {}d)",
                target.display(),
                fmt_bytes(size),
                fmt_days_ago(age),
                label,
                opts.artifact_max_age.as_secs() / 86_400
            );
        }
    }
    if errors > 0 {
        return Err(format!("{errors} artifact dir(s) need manual attention"));
    }
    Ok(freed)
}

fn run_cleanup(
    root: &Path,
    opts: &CleanOptions,
    run_worktrees: bool,
    run_artifacts: bool,
) -> ExitCode {
    println!(
        "cleanup: mode={} (use --yes to apply deletions)",
        if opts.apply { "apply" } else { "dry-run" }
    );
    let mut ok = true;
    if run_worktrees {
        match clean_worktrees(root, opts) {
            Ok(n) => println!("cleanup worktrees: {n} worktree(s) removed"),
            Err(e) => {
                eprintln!("cleanup worktrees: {e}");
                ok = false;
            }
        }
    }
    if run_artifacts {
        match clean_artifacts(root, opts) {
            Ok(bytes) => println!("cleanup artifacts: {} freed", fmt_bytes(bytes)),
            Err(e) => {
                eprintln!("cleanup artifacts: {e}");
                ok = false;
            }
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn parse_cleanup_args(args: &[String]) -> Result<(CleanOptions, bool, bool), String> {
    let mut opts = CleanOptions {
        apply: false,
        artifact_max_age: Duration::from_secs(7 * 86_400),
    };
    let mut run_worktrees = true;
    let mut run_artifacts = true;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--yes" => opts.apply = true,
            "--days" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| "--days requires a number".to_string())?;
                let days: u64 = v
                    .parse()
                    .map_err(|_| format!("--days: invalid number {v:?}"))?;
                if days == 0 {
                    return Err(
                        "--days must be at least 1 (a fresh build-dir should never be removed)"
                            .to_string(),
                    );
                }
                opts.artifact_max_age = Duration::from_secs(days.saturating_mul(86_400));
            }
            "worktrees" | "artifacts" => {
                let is_worktrees = args[i].as_str() == "worktrees";
                if is_worktrees {
                    run_artifacts = false;
                } else {
                    run_worktrees = false;
                }
                if !run_worktrees && !run_artifacts {
                    return Err(format!(
                        "select at most one phase (worktrees|artifacts); {USAGE}"
                    ));
                }
            }
            other => return Err(format!("unknown cleanup option {other:?}; {USAGE}")),
        }
        i += 1;
    }
    Ok((opts, run_worktrees, run_artifacts))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let root = repo_root();
    match args.get(1).map(|s| s.as_str()) {
        Some("docs-check") | None => {
            let adr_ok = check_adrs(&root);
            if adr_ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some("cleanup") => match parse_cleanup_args(&args[2..]) {
            Ok((opts, run_worktrees, run_artifacts)) => {
                run_cleanup(&root, &opts, run_worktrees, run_artifacts)
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Some(cmd) => {
            eprintln!("unknown command: {cmd}");
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn porcelain_parses_branch_records() {
        let input = "worktree /home/dev/arb\nclean\nHEAD abc123\nbranch refs/heads/main\n\nworktree /home/dev/arb-fix\nHEAD def456\nbranch refs/heads/fix/foo\n\n";
        let parsed = parse_worktree_porcelain(input);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, PathBuf::from("/home/dev/arb"));
        assert_eq!(parsed[0].branch.as_deref(), Some("main"));
        assert!(!parsed[0].locked);
        assert_eq!(parsed[1].branch.as_deref(), Some("fix/foo"));
    }

    #[test]
    fn porcelain_flags_locked_bare_detached() {
        let input = "worktree /bare-main\nbare\n\nworktree /locked-wt\nbranch refs/heads/x\nlocked locked by mekwall\n\nworktree /detached-wt\ndetached\n\n";
        let parsed = parse_worktree_porcelain(input);
        assert_eq!(parsed.len(), 3);
        assert!(parsed[0].bare);
        assert!(parsed[1].locked);
        assert!(parsed[2].branch.is_none());
        assert!(!parsed[2].locked);
    }

    #[test]
    fn empty_porcelain_yields_no_entries() {
        assert!(parse_worktree_porcelain("").is_empty());
    }

    #[test]
    fn extracts_state_field() {
        assert_eq!(
            extract_json_string_field("{\"state\":\"MERGED\"}", "state").as_deref(),
            Some("MERGED")
        );
        assert_eq!(
            extract_json_string_field("  {\"state\" : \"OPEN\"}  ", "state").as_deref(),
            Some("OPEN")
        );
        assert_eq!(
            extract_json_string_field("{\"head\":\"abc\"}", "state"),
            None
        );
    }

    #[test]
    fn parses_pr_records() {
        let single = r#"[{"headRefOid":"abc123","state":"MERGED"}]"#;
        assert_eq!(
            parse_pr_records(single),
            vec![PrRecord {
                state: "MERGED".to_string(),
                head_oid: "abc123".to_string()
            }]
        );
        let many =
            r#"[{"headRefOid":"0000","state":"OPEN"},{"headRefOid":"1111","state":"CLOSED"}]"#;
        assert_eq!(parse_pr_records(many).len(), 2);
        assert_eq!(parse_pr_records(many)[1].state, "CLOSED");
        assert!(parse_pr_records("[]").is_empty());
        assert!(parse_pr_records("gh: error text").is_empty());
    }

    #[test]
    fn pr_head_mismatch_never_deletes_unsubmitted_work() {
        // Branch name recycled from a previously merged PR whose head SHA no
        // longer matches: the local branch tip is "newlocal".
        let records = [PrRecord {
            state: "MERGED".to_string(),
            head_oid: "oldhq".to_string(),
        }];
        assert_eq!(decide_pr_state(&records, "newlocal"), PrState::HeadMismatch);
        // Same HEAD SHA: the PR really is this branch's PR.
        assert_eq!(decide_pr_state(&records, "oldhq"), PrState::Merged);
        // No PRs at all.
        assert_eq!(decide_pr_state(&[], "newlocal"), PrState::None);
    }

    #[test]
    fn pr_state_precedence_is_conservative() {
        // Same SHA matching multiple PRs: open wins over merged/closed.
        let records = [
            PrRecord {
                state: "MERGED".to_string(),
                head_oid: "sha".to_string(),
            },
            PrRecord {
                state: "OPEN".to_string(),
                head_oid: "sha".to_string(),
            },
            PrRecord {
                state: "CLOSED".to_string(),
                head_oid: "sha".to_string(),
            },
        ];
        assert_eq!(decide_pr_state(&records, "sha"), PrState::Open);
        let merged_closed = &records[0..1];
        assert_eq!(decide_pr_state(merged_closed, "sha"), PrState::Merged);
    }

    #[test]
    fn cleanup_args_accept_positional_phases() {
        let (opts, wt, art) = parse_cleanup_args(&["worktrees".to_string(), "--yes".to_string()])
            .expect("valid args");
        assert!(opts.apply && wt && !art);
        let (_, wt, art) = parse_cleanup_args(&["artifacts".to_string()]).expect("valid args");
        assert!(!wt && art);
        let (_, wt, art) = parse_cleanup_args(&[]).expect("valid args");
        assert!(wt && art);
        assert!(parse_cleanup_args(&["worktrees".to_string(), "artifacts".to_string()]).is_err());
        assert!(parse_cleanup_args(&["--bogus".to_string()]).is_err());
        let (opts, _, _) =
            parse_cleanup_args(&["--days".to_string(), "3".to_string()]).expect("valid days");
        assert_eq!(opts.artifact_max_age, Duration::from_secs(3 * 86_400));
        assert!(parse_cleanup_args(&["--days".to_string(), "0".to_string()]).is_err());
    }

    #[test]
    fn parses_repo_slugs() {
        assert_eq!(
            parse_repo_slug("https://github.com/arbsec/arbitraitor.git"),
            Some("arbsec/arbitraitor".to_string())
        );
        assert_eq!(
            parse_repo_slug("git@github.com:arbsec/arbitraitor.git"),
            Some("arbsec/arbitraitor".to_string())
        );
        assert_eq!(parse_repo_slug("not-a-remote"), None);
    }

    #[test]
    fn humanizes_bytes() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536), "1.5 KB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn humanizes_ages() {
        assert_eq!(
            fmt_days_ago(Duration::from_secs(5 * 86_400 + 3_600)),
            "5d1h"
        );
        assert_eq!(fmt_days_ago(Duration::from_secs(2 * 3_600)), "2h0m");
    }
}
