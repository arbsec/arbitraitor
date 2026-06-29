use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const REPO_ROOT: &str = env!("CARGO_MANIFEST_DIR");

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
    s.replace(['`', '"'], "")
        .replace(" = ", "=")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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
        Some(cmd) => {
            eprintln!("unknown command: {cmd}");
            eprintln!("usage: xtask docs-check");
            ExitCode::FAILURE
        }
    }
}
