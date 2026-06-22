//! Explanation templates for each [`FindingCategory`].
//!
//! Pure data: risk descriptions and actionable recommendations keyed by
//! category. Separated from [`crate::explain`] to keep the report-building
//! logic compact.

#![forbid(unsafe_code)]

use arbitraitor_model::finding::FindingCategory;

/// Returns a risk-oriented explanation for a finding category.
#[must_use]
pub fn category_risk(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::Provenance => {
            "The artifact's origin or provenance could not be fully verified. \
             Unverified origin means the content may have been tampered with in transit \
             or may not come from the claimed publisher."
        }
        FindingCategory::Reputation => {
            "The source or artifact has a poor reputation based on threat intelligence. \
             Content from low-reputation sources has a higher probability of being malicious."
        }
        FindingCategory::Transport => {
            "The retrieval used an insecure transport — plaintext HTTP, raw IP addresses, \
             disabled TLS verification, or URL shorteners that obscure the destination. \
             Insecure transport allows interception and tampering."
        }
        FindingCategory::ContentMismatch => {
            "The observed content does not match what was expected. \
             This can indicate tampering, a compromised mirror, or a misconfigured pipeline."
        }
        FindingCategory::MalwareSignature => {
            "The content matched a known malware signature. \
             This is a strong indicator that the artifact contains malicious code \
             that has been previously identified by threat researchers."
        }
        FindingCategory::SuspiciousScriptBehavior => {
            "The script exhibits behavior commonly used to evade detection or audit — \
             disabling security controls, clearing command history, or weakening shell \
             failure handling. These techniques are rarely needed by legitimate scripts."
        }
        FindingCategory::Obfuscation => {
            "The script uses obfuscation — encoded commands (Base64, hex), Unicode \
             homoglyphs, or variable concatenation to conceal what it actually runs. \
             Obfuscation is a strong indicator of malicious intent because it prevents \
             static inspection of the real payload."
        }
        FindingCategory::CredentialAccess => {
            "The script accesses credentials or secret material — SSH keys, cloud \
             metadata endpoints, environment variables, or credential files. \
             Malicious scripts use this to harvest passwords, tokens, and keys \
             for lateral movement or exfiltration."
        }
        FindingCategory::Persistence => {
            "The script establishes persistence by modifying cron jobs, systemd units, \
             shell startup profiles, or package repository configuration. \
             Persistence ensures the attacker's code runs again on reboot or login, \
             surviving cleanup of the original script."
        }
        FindingCategory::PrivilegeEscalation => {
            "The script invokes privilege escalation tools (sudo, su, doas, pkexec). \
             While sometimes legitimate, crossing a privilege boundary is a prerequisite \
             for most system-level attacks and should be scrutinized."
        }
        FindingCategory::DestructiveBehavior => {
            "The script performs destructive actions — recursive deletion (rm -rf /), \
             disk formatting (mkfs), disk wiping (dd), or fork bombs. \
             These can render the system unusable or destroy all data."
        }
        FindingCategory::NetworkBehavior => {
            "The script exhibits suspicious network behavior — reverse shells (netcat, \
             socat), bash /dev/tcp connections, or connections to suspicious ports. \
             Reverse shells give an attacker interactive control of the system."
        }
        FindingCategory::DynamicCodeExecution => {
            "The script dynamically constructs and executes code — eval, piping \
             downloaded content to a shell, decoding Base64/hex then executing, \
             or sourcing from risky paths. This collapses retrieval, inspection, \
             and execution into one opaque step, bypassing static analysis."
        }
        FindingCategory::ArchiveHazard => {
            "The archive contains hazardous entries — path traversal (../../etc/passwd), \
             absolute paths, symlinks pointing outside the archive, or oversized entries. \
             These can overwrite system files or exhaust resources during extraction."
        }
        FindingCategory::PackageRisk => {
            "The content poses a package ecosystem risk — typosquatting, dependency \
             confusion, or malicious install hooks. Package-based attacks exploit \
             trust in public package registries."
        }
        FindingCategory::PolicyViolation => {
            "The artifact violates a configured security policy. \
             Policy violations should be reviewed against the governing policy rules \
             before any release decision."
        }
        FindingCategory::ParserError => {
            "The script could not be fully parsed. Syntax errors or malformed content \
             prevent complete analysis, meaning some threats may be hidden in the \
             unparsed portions."
        }
        FindingCategory::ResourceLimitEvent => {
            "The artifact or script exceeded a resource limit during analysis — \
             maximum size, nesting depth, or node count. Resource limits prevent \
             denial-of-service via pathologically structured input."
        }
    }
}

/// Returns an actionable recommendation for a finding category.
#[must_use]
pub fn recommendation_for(category: FindingCategory) -> String {
    match category {
        FindingCategory::Provenance => {
            "Verify the publisher's signature and fetch from the official source. \
             Do not proceed if provenance cannot be established."
        }
        FindingCategory::Reputation => {
            "Check the source against multiple reputation feeds and reject if confirmed malicious."
        }
        FindingCategory::Transport => {
            "Require HTTPS with valid TLS certificates. Reject raw IP URLs and shortened links."
        }
        FindingCategory::ContentMismatch => {
            "Re-fetch from the canonical source and verify the expected digest."
        }
        FindingCategory::MalwareSignature => {
            "Quarantine the artifact immediately and investigate the retrieval chain."
        }
        FindingCategory::SuspiciousScriptBehavior => {
            "Review the script manually for follow-on malicious actions. \
             Defense evasion is rarely the only technique used."
        }
        FindingCategory::Obfuscation => {
            "Decode the obfuscated payload and inspect the real instructions before executing."
        }
        FindingCategory::CredentialAccess => {
            "Block credential access and rotate any secrets that may have been exposed."
        }
        FindingCategory::Persistence => {
            "Identify and remove all persistence mechanisms. Check for other changes \
             made by the same script."
        }
        FindingCategory::PrivilegeEscalation => {
            "Confirm the privilege escalation is necessary and authorized. \
             Restrict to specific commands if possible."
        }
        FindingCategory::DestructiveBehavior => {
            "Do not execute. Isolate the system if the script has already run."
        }
        FindingCategory::NetworkBehavior => {
            "Block the destination endpoints and investigate for an active reverse shell."
        }
        FindingCategory::DynamicCodeExecution => {
            "Download, inspect, and execute as separate steps. \
             Never pipe remote content directly into a shell."
        }
        FindingCategory::ArchiveHazard => {
            "Extract with path sanitization enabled and reject archives with traversal entries."
        }
        FindingCategory::PackageRisk => {
            "Verify the package name against the official registry and audit dependencies."
        }
        FindingCategory::PolicyViolation => {
            "Review the policy violation against the governing rules and request an exception \
             if justified."
        }
        FindingCategory::ParserError => {
            "Inspect the unparsed portions manually or reject the artifact if incomplete."
        }
        FindingCategory::ResourceLimitEvent => {
            "Increase the limit if the input is expected to be large, or reject if \
             the size is anomalous."
        }
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_category_has_meaningful_risk_explanation() {
        for category in all_categories() {
            let risk = category_risk(category);
            assert!(
                risk.len() > 40,
                "category {category:?} explanation is too short"
            );
        }
    }

    #[test]
    fn every_category_has_actionable_recommendation() {
        for category in all_categories() {
            let rec = recommendation_for(category);
            assert!(
                rec.len() > 20,
                "category {category:?} recommendation is too short"
            );
        }
    }

    fn all_categories() -> Vec<FindingCategory> {
        use FindingCategory::*;
        vec![
            Provenance,
            Reputation,
            Transport,
            ContentMismatch,
            MalwareSignature,
            SuspiciousScriptBehavior,
            Obfuscation,
            CredentialAccess,
            Persistence,
            PrivilegeEscalation,
            DestructiveBehavior,
            NetworkBehavior,
            DynamicCodeExecution,
            ArchiveHazard,
            PackageRisk,
            PolicyViolation,
            ParserError,
            ResourceLimitEvent,
        ]
    }
}
