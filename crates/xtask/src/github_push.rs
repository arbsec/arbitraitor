//! `xtask push-branch`: land a local branch's tree as ONE GitHub-App-signed
//! commit on the remote branch via GraphQL `createCommitOnBranch`.
//!
//! Aligns arbitraitor with the arbsec verified-commit path (orchestraitor
//! precedent, `.agents/skills/github-pr-lifecycle/references/verified-commit-path.md`):
//!
//! - The landed commit is created by the App installation, so GitHub itself
//!   signs it (`web-flow` committer, `verification: valid`) — no local
//!   signing key exists for the bot, so plain `git push` of a bot-authored
//!   commit can never verify and the `required_signatures` ruleset rejects
//!   it at merge time.
//! - The push credential is the installation token carried ONLY in the
//!   Authorization header; the ambient `gh` credential helper (which falls
//!   back to the operator's personal keyring account) is never involved, so
//!   ref updates can no longer be misattributed to the human owner
//!   (incident 2026-10-13: PR #801 showed "mekwall force-pushed" because a
//!   `git push` ran without `GH_TOKEN` and the helper authenticated as the
//!   keyring identity).
//!
//! Mechanics (mirroring `orc github push-branch`):
//! 1. Resolve `(owner, repo)` from the `origin` remote; local branch from
//!    HEAD (or flags).
//! 2. Read the remote branch head (absent for a new branch).
//! 3. Compute the change set between the remote-head tree (existing branch)
//!    or the base tree (new branch) and the local branch's committed tree —
//!    never the index or working directory.
//! 4. Land via a UNIQUE temp branch (`push-branch/tmp-<nanos>`) so the
//!    tree-equality and `signature.isValid` gates run BEFORE the real ref
//!    moves; delete the temp ref on every path.
//! 5. Move the real ref with an exact-head CAS precondition
//!    (`updateRefs`/`RefUpdate.beforeOid`), then re-read the ref to confirm
//!    the move outcome (the payload carries only a nullable
//!    `clientMutationId`).
//!
//! The token stays in memory for the session; it is never echoed, logged,
//! persisted, or passed through the arbitraitor curl shim.

use std::process::{Command, ExitCode};

use serde_json::Value;

const GRAPHQL_ENDPOINT: &str = "https://api.github.com/graphql";

const USAGE_PUSH_BRANCH: &str = "usage: xtask push-branch [--owner <o>] [--repo <name|owner/name>] \
     [--branch <local>] [--remote-branch <name>] [--base <ref>] [--message <subject>] \
     [--body-file <path>] [--dry-run]";

pub fn run(args: &[String]) -> ExitCode {
    match run_inner(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Options {
    owner: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
    remote_branch: Option<String>,
    base: Option<String>,
    message: Option<String>,
    body_file: Option<String>,
    dry_run: bool,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        owner: None,
        repo: None,
        branch: None,
        remote_branch: None,
        base: None,
        message: None,
        body_file: None,
        dry_run: false,
    };
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let takes_value = matches!(
            flag,
            "--owner"
                | "--repo"
                | "--branch"
                | "--remote-branch"
                | "--base"
                | "--message"
                | "--body-file"
        );
        if takes_value {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| format!("{flag} requires a value"))?
                .clone();
            let slot = match flag {
                "--owner" => &mut o.owner,
                "--repo" => &mut o.repo,
                "--branch" => &mut o.branch,
                "--remote-branch" => &mut o.remote_branch,
                "--base" => &mut o.base,
                "--message" => &mut o.message,
                _ => &mut o.body_file,
            };
            *slot = Some(v);
        } else if flag == "--dry-run" {
            o.dry_run = true;
        } else {
            return Err(format!("unknown flag `{flag}`; {USAGE_PUSH_BRANCH}"));
        }
        i += 1;
    }
    Ok(o)
}

fn run_inner(args: &[String]) -> Result<(), String> {
    let opts = parse_args(args)?;
    if opts.message.is_none() {
        return Err(format!(
            "--message <subject> is required; {USAGE_PUSH_BRANCH}"
        ));
    }
    let cwd = std::env::current_dir().map_err(|e| format!("cannot read cwd: {e}"))?;
    let origin_owner_repo = origin_owner_repo(&cwd)?;
    let repo_slug = opts
        .repo
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .or(origin_owner_repo.1.as_deref())
        .ok_or_else(|| {
            format!(
                "no --repo given and the origin remote of {} does not name a repository",
                cwd.display()
            )
        })?
        .to_string();
    let (owner, repo) = match repo_slug.split_once('/') {
        Some((o, r)) if !o.is_empty() && !r.is_empty() => (o.to_string(), r.to_string()),
        _ => {
            let o = opts
                .owner
                .as_deref()
                .map(str::trim)
                .filter(|o| !o.is_empty())
                .or(origin_owner_repo.0.as_deref())
                .ok_or_else(|| format!("--repo {repo_slug} needs --owner"))?;
            (o.to_string(), repo_slug.clone())
        }
    };
    let local_branch = match &opts.branch {
        Some(b) => b.clone(),
        None => git(&cwd, &["rev-parse", "--abbrev-ref", "HEAD"])?,
    };
    if local_branch == "HEAD" {
        return Err(
            "detached HEAD — pass --branch <local> explicitly to name the branch whose tree \
             should be landed"
                .to_string(),
        );
    }
    let remote_branch = opts
        .remote_branch
        .clone()
        .unwrap_or_else(|| local_branch.clone());
    let body = match &opts.body_file {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read --body-file {path}: {e}"))?,
        None => String::new(),
    };

    // 1. The intended tree: the branch's committed tree object.
    let local_tree = git(&cwd, &["rev-parse", &format!("{local_branch}^{{tree}}")])?;

    // 2. Mint the installation token (in-memory only).
    let token = crate::github_mint::mint()?;

    let graphql = GraphqlSession::new(token.clone());

    // 3. Remote branch head + the diff base for the change set.
    let existing = graphql.branch_ref(&owner, &repo, &remote_branch)?;
    let (diff_base_tree, base_commit, observed_head) = if let Some(head_oid) = existing
        .as_ref()
        .and_then(|v| v.pointer("/target/oid"))
        .and_then(Value::as_str)
        .map(str::to_string)
    {
        // Existing remote branch: diff against the REMOTE HEAD tree (never
        // the base — an earlier landing may have moved the remote past it).
        let tree = remote_head_tree(
            &token,
            &cwd,
            &owner,
            &repo,
            head_oid.clone(),
            &remote_branch,
        )?;
        (tree, None, Some(head_oid))
    } else {
        // New remote branch: diff base is --base, else the default branch,
        // resolved through the API (a local ref may be stale).
        let base_ref = match &opts.base {
            Some(b) => b.clone(),
            None => graphql.default_branch(&owner, &repo)?,
        };
        let base_head = graphql
            .branch_head(&owner, &repo, &base_ref)?
            .ok_or_else(|| {
                format!("base ref {base_ref} does not exist on {owner}/{repo} — pass --base <ref>")
            })?;
        let tree = remote_head_tree(&token, &cwd, &owner, &repo, base_head.clone(), &base_ref)?;
        (tree, Some(base_head), None)
    };

    let changes = diff_tree_changes(&cwd, &diff_base_tree, &local_tree)?;
    if changes.is_empty() {
        return Err(format!(
            "branch `{local_branch}` tree {local_tree} is identical to the remote head tree — \
             nothing to land"
        ));
    }
    // Build the payload BEFORE the dry-run report so the fail-closed
    // executable-addition and object-type checks surface in dry-runs too.
    let file_changes = build_file_changes(&cwd, &changes, &diff_base_tree, &local_tree)?;
    if opts.dry_run {
        let (adds, dels) = changes
            .iter()
            .fold((0u32, 0u32), |(a, d), (st, _)| match st.as_str() {
                "D" => (a, d + 1),
                _ => (a + 1, d), // A/M/T all ship as FileAddition
            });
        eprintln!(
            "dry-run: would land {owner}/{repo} {remote_branch} at tree {local_tree}\n\
             change set base: {diff_base_tree}\n\
             message: {}\n\
             fileChanges: {adds} addition(s), {dels} deletion(s)",
            opts.message.as_deref().unwrap_or_default(),
        );
        return Ok(());
    }

    // 4. Land on a unique temp branch; gates run before the real ref moves.
    let repository_id = graphql.repository_id(&owner, &repo)?;
    let temp_branch = format!(
        "push-branch/tmp-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let bootstrap = observed_head
        .clone()
        .or_else(|| base_commit.clone())
        .ok_or("internal: no bootstrap commit resolved")?;
    if graphql.branch_ref(&owner, &repo, &temp_branch)?.is_some() {
        return Err(format!(
            "temporary branch `{temp_branch}` already exists (unexpected collision) — retry"
        ));
    }
    let created = graphql.create_ref(
        &repository_id,
        &format!("refs/heads/{temp_branch}"),
        &bootstrap,
    )?;
    let temp_head = created
        .pointer("/target/oid")
        .and_then(Value::as_str)
        .ok_or("createRef response missing target.oid")?
        .to_string();
    let temp_ref_id = created
        .get("id")
        .and_then(Value::as_str)
        .ok_or("createRef response missing ref.id")?
        .to_string();

    let commit = match graphql.create_commit_on_branch(
        &owner,
        &repo,
        &temp_branch,
        &temp_head,
        opts.message.as_deref().unwrap_or_default(),
        &body,
        &file_changes,
    ) {
        Ok(c) => c,
        Err(e) => {
            cleanup_temp_ref(&graphql, &temp_ref_id, &temp_branch);
            return Err(e);
        }
    };
    if let Err(e) = verify_landed_commit(&commit, &local_tree, &local_branch) {
        cleanup_temp_ref(&graphql, &temp_ref_id, &temp_branch);
        return Err(e);
    }
    let new_head = commit
        .get("oid")
        .and_then(Value::as_str)
        .ok_or("landing commit response missing commit.oid")?
        .to_string();

    // 5. CAS-swing the real ref; then verify the move outcome.
    let swing = match &observed_head {
        Some(before) => graphql.move_ref_with_precondition(
            &owner,
            &repo,
            &repository_id,
            &remote_branch,
            before,
            &new_head,
        ),
        None => graphql
            .create_ref(
                &repository_id,
                &format!("refs/heads/{remote_branch}"),
                &new_head,
            )
            .map(|_| ()),
    };
    cleanup_temp_ref(&graphql, &temp_ref_id, &temp_branch);
    swing?;

    eprintln!("landed {remote_branch} at {new_head} (App-signed, tree {local_tree})");
    Ok(())
}

/// Best-effort temp-ref cleanup; a leaked ref is WARNED about by name (it
/// must be deleted by hand: `gh api -X DELETE repos/<o>/<r>/git/refs/heads/<ref>`)
/// but never masks the primary error path.
fn cleanup_temp_ref(graphql: &GraphqlSession, temp_ref_id: &str, temp_branch: &str) {
    if let Err(e) = graphql.delete_ref(temp_ref_id) {
        eprintln!(
            "WARNING: failed to delete temporary ref `refs/heads/{temp_branch}` (id {temp_ref_id}): \
             {e} — the ref is still visible on the remote and should be deleted manually"
        );
    }
}

// --- GraphQL session ---------------------------------------------------------

struct GraphqlSession {
    bearer: String,
}

impl GraphqlSession {
    fn new(bearer: String) -> Self {
        Self { bearer }
    }

    fn execute(&self, operation: &str, query: &str, variables: &Value) -> Result<Value, String> {
        let payload = serde_json::json!({"query": query, "variables": variables}).to_string();
        let payload_file = SecretFile::temp(payload.as_bytes())?;
        let header_file =
            SecretFile::temp(format!("Authorization: Bearer {}", self.bearer).as_bytes())?;
        // --max-time bounds a hung TLS connection (never hang the agent).
        // /usr/bin/curl is invoked directly to bypass the arbitraitor curl
        // shim (which strips Authorization headers) — the absolute path is
        // the documented mint posture (github_mint.rs).
        let out = Command::new("/usr/bin/curl")
            .args([
                "-sS",
                "--fail-with-body",
                "--max-time",
                "60",
                "-X",
                "POST",
                "-H",
            ])
            .arg(format!("@{}", header_file.path.display()))
            .args(["-H", "Accept: application/vnd.github+json", "-H"])
            .arg("Content-Type: application/json")
            .arg("--data-binary")
            .arg(format!("@{}", payload_file.path.display()))
            .arg(GRAPHQL_ENDPOINT)
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    "curl not found at /usr/bin/curl (required for the GraphQL transport)"
                        .to_string()
                } else {
                    format!("curl: {e}")
                }
            })?;
        let body = String::from_utf8_lossy(&out.stdout).to_string();
        if !out.status.success() {
            let detail = crate::extract_json_string_field(&body, "message")
                .unwrap_or_else(|| "no detail returned".to_string());
            return Err(format!(
                "graphql request failed (curl exit {}): {detail}",
                out.status.code().unwrap_or(-1)
            ));
        }
        let envelope: Value = serde_json::from_str(&body)
            .map_err(|_| format!("{operation}: malformed JSON response"))?;
        if let Some(errors) = envelope.get("errors").and_then(Value::as_array) {
            let messages: Vec<String> = errors
                .iter()
                .filter_map(|e| e.get("message").and_then(Value::as_str))
                .map(str::to_string)
                .collect();
            if !messages.is_empty() {
                return Err(format!("{operation}: {}", messages.join("; ")));
            }
        }
        envelope
            .get("data")
            .cloned()
            .ok_or_else(|| format!("{operation}: response missing data object"))
    }

    fn repository_id(&self, owner: &str, repo: &str) -> Result<String, String> {
        let data = self.execute(
            "repository query",
            "query($owner:String!,$repo:String!){repository(owner:$owner,name:$repo){id}}",
            &serde_json::json!({"owner": owner, "repo": repo}),
        )?;
        data.pointer("/repository/id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "repository query response missing repository.id".to_string())
    }

    fn default_branch(&self, owner: &str, repo: &str) -> Result<String, String> {
        let data = self.execute(
            "default branch query",
            "query($owner:String!,$repo:String!){repository(owner:$owner,name:$repo){defaultBranchRef{name}}}",
            &serde_json::json!({"owner": owner, "repo": repo}),
        )?;
        data.pointer("/repository/defaultBranchRef/name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("cannot resolve the default branch of {owner}/{repo}"))
    }

    /// `Ok(None)` ONLY when the remote ref is absent; transport errors
    /// propagate so an API failure is never mistaken for "no such branch".
    fn branch_ref(&self, owner: &str, repo: &str, branch: &str) -> Result<Option<Value>, String> {
        let data = self.execute(
            "branch ref query",
            "query($owner:String!,$repo:String!,$qualified:String!){repository(owner:$owner,name:$repo){ref(qualifiedName:$qualified){id target{oid}}}}",
            &serde_json::json!({"owner": owner, "repo": repo, "qualified": format!("refs/heads/{branch}")}),
        )?;
        if data.pointer("/repository/ref").is_some_and(Value::is_null) {
            return Ok(None);
        }
        Ok(data.pointer("/repository/ref").cloned())
    }

    fn branch_head(&self, owner: &str, repo: &str, branch: &str) -> Result<Option<String>, String> {
        let rf = self.branch_ref(owner, repo, branch)?;
        Ok(rf.and_then(|v| {
            v.pointer("/target/oid")
                .and_then(Value::as_str)
                .map(str::to_string)
        }))
    }

    fn create_ref(&self, repository_id: &str, name: &str, oid: &str) -> Result<Value, String> {
        let data = self.execute(
            "createRef",
            "mutation($input:CreateRefInput!){createRef(input:$input){ref{id target{... on Commit{oid}}}}}",
            &serde_json::json!({"input": {"repositoryId": repository_id, "name": name, "oid": oid}}),
        )?;
        data.pointer("/createRef/ref")
            .cloned()
            .ok_or_else(|| "createRef response missing createRef.ref".to_string())
    }

    fn delete_ref(&self, ref_id: &str) -> Result<(), String> {
        let _ = self.execute(
            "deleteRef",
            "mutation($input:DeleteRefInput!){deleteRef(input:$input){clientMutationId}}",
            &serde_json::json!({"input": {"refId": ref_id}}),
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn create_commit_on_branch(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        expected_head_oid: &str,
        headline: &str,
        body: &str,
        file_changes: &Value,
    ) -> Result<Value, String> {
        let data = self.execute(
            "createCommitOnBranch",
            "mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid tree{oid} signature{... on GpgSignature{isValid} ... on SmimeSignature{isValid} ... on SshSignature{isValid}}}}}",
            &serde_json::json!({
                "input": {
                    "branch": {
                        "repositoryNameWithOwner": format!("{owner}/{repo}"),
                        "branchName": branch,
                    },
                    "expectedHeadOid": expected_head_oid,
                    "message": {"headline": headline, "body": body},
                    "fileChanges": file_changes,
                }
            }),
        )?;
        data.pointer("/createCommitOnBranch/commit")
            .cloned()
            .ok_or_else(|| "createCommitOnBranch response missing commit".to_string())
    }

    /// Exact-head CAS move (`updateRefs`, `beforeOid` = observed head,
    /// `force=false`). The payload carries only a nullable
    /// `clientMutationId`, so the move OUTCOME is verified by re-reading
    /// the ref; a spurious error envelope after a successful move is
    /// downgraded to a warning (false-negative guard, orchestraitor
    /// precedent).
    fn move_ref_with_precondition(
        &self,
        owner: &str,
        repo: &str,
        repository_id: &str,
        remote_branch: &str,
        before_oid: &str,
        new_oid: &str,
    ) -> Result<(), String> {
        let result = self.execute(
            "updateRefs",
            "mutation($input:UpdateRefsInput!){updateRefs(input:$input){clientMutationId}}",
            &serde_json::json!({
                "input": {
                    "repositoryId": repository_id,
                    "refUpdates": [{
                        "name": format!("refs/heads/{remote_branch}"),
                        "afterOid": new_oid,
                        "beforeOid": before_oid,
                        "force": false,
                    }],
                }
            }),
        );
        if let Err(error) = result {
            // False-negative guard: re-read the ref; a provably-moved ref
            // degrades the error to a warning.
            let moved = self
                .branch_ref(owner, repo, remote_branch)?
                .and_then(|v| {
                    v.pointer("/target/oid")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .is_some_and(|oid| oid.eq_ignore_ascii_case(new_oid));
            if moved {
                eprintln!(
                    "WARNING: updateRefs errored ({error}) but {remote_branch} provably points at {new_oid} — treating the landing as successful"
                );
                return Ok(());
            }
            return Err(error);
        }
        // Verify the move outcome regardless of payload shape.
        let moved = self.branch_ref(owner, repo, remote_branch)?.and_then(|v| {
            v.pointer("/target/oid")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        match moved {
            Some(oid) if oid.eq_ignore_ascii_case(new_oid) => Ok(()),
            Some(oid) => Err(format!(
                "post-move verification failed: {remote_branch} points at {oid}, expected {new_oid}"
            )),
            None => Err(format!(
                "post-move verification failed: {remote_branch} disappeared — treating the landing as failed"
            )),
        }
    }
}

// --- Gates -------------------------------------------------------------------

fn verify_landed_commit(commit: &Value, local_tree: &str, branch: &str) -> Result<(), String> {
    let oid = commit.get("oid").and_then(Value::as_str).unwrap_or("?");
    let landed_tree = commit
        .pointer("/tree/oid")
        .and_then(Value::as_str)
        .ok_or("landing commit response missing tree.oid")?;
    if landed_tree != local_tree {
        return Err(format!(
            "landing commit tree mismatch: remote commit {oid} tree is {landed_tree}, local branch \
             `{branch}` tree is {local_tree} — refusing to move the ref; the remote branch is unchanged"
        ));
    }
    let verified = commit
        .get("signature")
        .and_then(|s| s.get("isValid"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !verified {
        return Err(format!(
            "landing commit {oid} is NOT verified (signature missing or invalid) — refusing to move \
             the ref; the remote branch is unchanged; the required_signatures ruleset would reject it"
        ));
    }
    Ok(())
}

// --- Local git + tree helpers -------------------------------------------------

fn git(cwd: &std::path::Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn origin_owner_repo(cwd: &std::path::Path) -> Result<(Option<String>, Option<String>), String> {
    let url = match git(cwd, &["remote", "get-url", "origin"]) {
        Ok(u) => u,
        Err(_) => return Ok((None, None)),
    };
    Ok(parse_github_slug(&url))
}

fn parse_github_slug(url: &str) -> (Option<String>, Option<String>) {
    parse_github_slug_inner(url).unwrap_or((None, None))
}

// Only github.com remotes (exact host, no port) yield a slug; any other
// host, a `github.com:<port>` URL form, or foreign userinfo returns
// (None, None) so the caller reports a typed error instead of silently
// landing elsewhere — a tampered origin must not redirect the target.
fn parse_github_slug_inner(url: &str) -> Option<(Option<String>, Option<String>)> {
    // scp form first: git@github.com:owner/repo.git (colon separator).
    if let Some(rest) = url.strip_prefix("git@github.com:") {
        let slug = rest.trim_end_matches(".git").trim_end_matches('/');
        return Some(match slug.split_once('/') {
            Some((o, r)) if !o.is_empty() && !r.is_empty() => {
                (Some(o.to_string()), Some(r.to_string()))
            }
            _ => (None, None),
        });
    }
    for scheme in ["https://", "http://", "git@", "ssh://"] {
        if let Some(rest) = url.strip_prefix(scheme) {
            // Strip exact `git@` userinfo; any other userinfo is rejected.
            let host_and_path = match rest.split_once('@') {
                Some(("git", remaining)) => remaining,
                Some(_) => return Some((None, None)),
                None => rest,
            };
            let Some((host, path)) = host_and_path.split_once('/') else {
                return Some((None, None));
            };
            // A ':' in the authority is a port (or malformed scp) — reject.
            if host.contains(':') || host != "github.com" {
                return Some((None, None));
            }
            let slug = path.trim_end_matches(".git").trim_end_matches('/');
            return Some(match slug.split_once('/') {
                Some((o, r)) if !o.is_empty() && !r.is_empty() => {
                    (Some(o.to_string()), Some(r.to_string()))
                }
                _ => (None, None),
            });
        }
    }
    Some((None, None))
}

/// `git diff-tree -r -z --no-renames --no-commit-id --name-status` between
/// two trees; parses `STATUS\0path\0` records (git omits the final NUL).
fn diff_tree_changes(
    cwd: &std::path::Path,
    base_tree: &str,
    tree: &str,
) -> Result<Vec<(String, String)>, String> {
    let raw = Command::new("git")
        .current_dir(cwd)
        .args([
            "diff-tree",
            "-r",
            "-z",
            "--no-renames",
            "--no-commit-id",
            "--name-status",
            base_tree,
            tree,
        ])
        .output()
        .map_err(|e| format!("git diff-tree: {e}"))?;
    if !raw.status.success() {
        return Err(format!(
            "git diff-tree failed: {}",
            String::from_utf8_lossy(&raw.stderr).trim()
        ));
    }
    let mut changes = Vec::new();
    let mut fields = raw.stdout.split(|b| *b == 0).peekable();
    while let Some(status) = fields.next() {
        if status.is_empty() {
            continue;
        }
        let status = String::from_utf8_lossy(status).to_string();
        match fields.next() {
            Some(path) if !path.is_empty() => {
                changes.push((status, String::from_utf8_lossy(path).to_string()));
            }
            _ => break,
        }
    }
    Ok(changes)
}

/// Builds the `fileChanges` payload from the diff records. Blob contents
/// come from the branch's committed objects (`git cat-file blob`), never
/// the working directory. GitHub's `createCommitOnBranch` `FileAddition`
/// has NO mode field — added files always land `100644`, so an executable
/// file being ADDED (not already 100755 in the base tree) cannot survive
/// the landing; that case fails closed with a typed error (the
/// tree-equality gate would refuse it anyway — this surfaces the cause).
fn build_file_changes(
    cwd: &std::path::Path,
    changes: &[(String, String)],
    base_tree: &str,
    local_tree: &str,
) -> Result<Value, String> {
    let base_modes = tree_modes(cwd, base_tree)?;
    let mut additions = Vec::new();
    let mut deletions = Vec::new();
    for (status, path) in changes {
        match status.as_str() {
            "D" => deletions.push(serde_json::json!({ "path": path })),
            "A" | "M" | "T" => {
                // Only blobs can ride FileAddition: symlinks (120000) and
                // gitlinks (160000) would land as regular-file content,
                // silently changing the tree — fail closed instead.
                let obj_type = git(cwd, &["cat-file", "-t", &format!("{local_tree}:{path}")])?;
                if obj_type != "blob" {
                    return Err(format!(
                        "`{path}` is a {obj_type} ({mode_note}) in the local tree — \
                         createCommitOnBranch FileAddition only carries regular-file blobs, so \
                         this change set cannot be landed as-is (tree gate would refuse it)",
                        mode_note = if obj_type == "commit" {
                            "gitlink/submodule 160000"
                        } else {
                            "symlink 120000"
                        }
                    ));
                }
                let contents = Command::new("git")
                    .current_dir(cwd)
                    .args(["cat-file", "blob", &format!("{local_tree}:{path}")])
                    .output()
                    .map_err(|e| format!("git cat-file blob {path}: {e}"))?;
                if !contents.status.success() {
                    return Err(format!(
                        "git cat-file blob {local_tree}:{path} failed: {}",
                        String::from_utf8_lossy(&contents.stderr).trim()
                    ));
                }
                if status == "A" {
                    let local_mode = git(cwd, &["ls-tree", local_tree, "--", path])?
                        .split_whitespace()
                        .next()
                        .unwrap_or("100644")
                        .to_string();
                    if local_mode == "100755"
                        && base_modes.get(path.as_str()) != Some(&"100755".to_string())
                    {
                        return Err(format!(
                            "`{path}` is executable (100755) locally but is being ADDED — GitHub's \
                             createCommitOnBranch FileAddition always lands 100644, so the remote \
                             tree would differ from the local tree (the tree gate refuses the \
                             landing). Commit the file as 100644 locally, or land the file with \
                             mode 100644 and chmod locally afterwards."
                        ));
                    }
                }
                additions.push(serde_json::json!({
                    "path": path,
                    "contents": base64_encode(&contents.stdout),
                }));
            }
            other => return Err(format!("unsupported diff status `{other}` for {path}")),
        }
    }
    let mut payload = serde_json::Map::new();
    if !additions.is_empty() {
        payload.insert("additions".to_string(), Value::Array(additions));
    }
    if !deletions.is_empty() {
        payload.insert("deletions".to_string(), Value::Array(deletions));
    }
    if payload.is_empty() {
        return Err("change set produced no fileChanges".to_string());
    }
    Ok(Value::Object(payload))
}

/// Reads a tree's entry modes (`git ls-tree -r -z <tree>`): path -> mode.
fn tree_modes(
    cwd: &std::path::Path,
    tree: &str,
) -> Result<std::collections::HashMap<String, String>, String> {
    let out = Command::new("git")
        .current_dir(cwd)
        .args(["ls-tree", "-r", "-z", tree])
        .output()
        .map_err(|e| format!("git ls-tree: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git ls-tree failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut modes = std::collections::HashMap::new();
    for record in out.stdout.split(|b| *b == 0) {
        if record.is_empty() {
            continue;
        }
        let Some(tab) = record.iter().position(|b| *b == b'\t') else {
            continue;
        };
        let meta = String::from_utf8_lossy(&record[..tab]).to_string();
        let path = String::from_utf8_lossy(&record[tab + 1..]).to_string();
        let mode = meta
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        modes.insert(path, mode);
    }
    Ok(modes)
}

// --- Secret-file plumbing (mirrors github_mint) -------------------------------

/// A 0600 file inside a 0700 private temp dir; the file itself is removed on
/// drop (the session dir is reused across calls in this process and ages out
/// via OS tmpfiles policy). Secrets (the Authorization header, the GraphQL
/// payload) reach curl via `@file` arguments — never argv, env, or inside
/// the repo.
struct SecretFile {
    path: std::path::PathBuf,
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        // The secret file is per-call; delete it eagerly so residue is
        // bounded to the empty session dir (0700) even on early returns.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Resolves the session temp dir: a PID-unique 0700 dir created once per
/// process. If creation fails, falls back to a fresh per-call dir (same
/// posture, just not shared) — never a panic, never a default-ACL path.
#[cfg(unix)]
fn session_temp_dir() -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    static SESSION_DIR: std::sync::LazyLock<Option<std::path::PathBuf>> =
        std::sync::LazyLock::new(|| {
            let candidate = std::env::temp_dir().join(format!(
                "xtask-push-branch-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&candidate)
                .ok()
                .map(|_| candidate)
        });
    if let Some(p) = SESSION_DIR.as_ref() {
        return Ok(p.clone());
    }
    // Fallback: unique per-call dir with the same 0700 posture (the session
    // dir could not be created — never a panic, never a default-ACL path).
    let fallback = std::env::temp_dir().join(format!(
        "xtask-push-branch-fallback-{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
        std::process::id()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&fallback)
        .map_err(|e| format!("tempdir: {e}"))?;
    Ok(fallback)
}

impl SecretFile {
    /// Writes `contents` to a 0600 file inside a private 0700 session temp
    /// dir (created atomically via `DirBuilder::mode`, mirroring
    /// `github_mint::SecretFile` — no chmod-after-create TOCTOU window).
    /// Non-unix platforms fail closed: they cannot enforce POSIX modes, and
    /// secret material must never land under default ACLs (github_mint
    /// posture). One session dir (created lazily, reused for every call in
    /// this process) limits crash residue to a single directory per run;
    /// each file is removed on drop.
    fn temp(contents: &[u8]) -> Result<Self, String> {
        #[cfg(not(unix))]
        {
            let _ = contents;
            return Err(
                "non-unix platforms are unsupported for push-branch: POSIX file modes cannot \
                 be enforced, and the installation token must never land under default ACLs"
                    .to_string(),
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let base = session_temp_dir()?;
            let file = base.join(format!(
                "secret-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
            ));
            std::fs::write(&file, contents).map_err(|e| format!("tempfile write: {e}"))?;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("tempfile permissions: {e}"))?;
            // Write-then-chmod on a 0700 dir is safe (no TOCTOU exposure:
            // the parent denies traversal to other users).
            Ok(Self { path: file })
        }
    }
}

/// Reads the remote head commit's tree locally: fetch the head OID from
/// github.com with the token in an extraheader (never argv/URL), then
/// rev-parse its tree. Falls back to a branch-name fetch.
fn remote_head_tree(
    token: &str,
    cwd: &std::path::Path,
    owner: &str,
    repo: &str,
    head_oid: String,
    remote_branch: &str,
) -> Result<String, String> {
    if !fetch_authenticated(token, cwd, owner, repo, &head_oid)
        && !fetch_authenticated(token, cwd, owner, repo, remote_branch)
    {
        // fall through to rev-parse; the error below carries the remediation
    }
    if let Ok(tree) = git(cwd, &["rev-parse", &format!("{head_oid}^{{tree}}")]) {
        return Ok(tree);
    }
    Err(format!(
        "cannot read the remote head {head_oid} tree locally — run `git fetch \
         https://github.com/{owner}/{repo}.git` first"
    ))
}

fn fetch_authenticated(
    token: &str,
    cwd: &std::path::Path,
    owner: &str,
    repo: &str,
    what: &str,
) -> bool {
    let authorization = format!(
        "basic {}",
        base64_encode(format!("x-access-token:{token}").as_bytes())
    );
    Command::new("git")
        .current_dir(cwd)
        .args([
            "fetch",
            "--quiet",
            &format!("https://github.com/{owner}/{repo}.git"),
            what,
        ])
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "http.https://github.com/.extraheader")
        .env("GIT_CONFIG_VALUE_0", authorization)
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Standard base64 (RFC 4648, padded) without adding a dependency: 12 lines.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_shape() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn slug_parsing() {
        assert_eq!(
            parse_github_slug("https://github.com/arbsec/arbitraitor.git"),
            (Some("arbsec".to_string()), Some("arbitraitor".to_string()))
        );
        assert_eq!(
            parse_github_slug("git@github.com:arbsec/arbitraitor.git"),
            (Some("arbsec".to_string()), Some("arbitraitor".to_string()))
        );
        assert_eq!(
            parse_github_slug("ssh://git@github.com/arbsec/arbitraitor.git"),
            (Some("arbsec".to_string()), Some("arbitraitor".to_string()))
        );
        // Port forms must be REJECTED, not misparsed (gen-1 M4): the old
        // parser produced owner "22" from ssh://git@github.com:22/owner/repo.
        assert_eq!(
            parse_github_slug("ssh://git@github.com:22/owner/repo.git"),
            (None, None)
        );
        assert_eq!(
            parse_github_slug("https://github.com:443/owner/repo.git"),
            (None, None)
        );
        // Foreign userinfo rejected (not silently stripped).
        assert_eq!(
            parse_github_slug("https://evil@github.com/owner/repo.git"),
            (None, None)
        );
        // Host-lookalike rejections.
        assert_eq!(
            parse_github_slug("https://github.com.evil.com/x/y"),
            (None, None)
        );
        assert_eq!(
            parse_github_slug("https://github.com@evil.com/x"),
            (None, None)
        );
        assert_eq!(parse_github_slug("https://example.com/x/y"), (None, None));
    }
}
