# Community Submissions

The community intelligence system allows Arbitraitor users to contribute and benefit from shared threat intelligence.

## How it works

```
User discovers indicator
        │
        ▼
┌──────────────────┐
│ Submission API    │
│                    │
│ 1. Validate       │
│    indicator       │
│                    │
│ 2. Check for      │
│    duplicates      │
│                    │
│ 3. Score          │
│    automatically  │
│                    │
│ 4. Queue for      │
│    review          │
└──────────────────┘
        │
        ▼
┌──────────────────┐
│ Security Review   │
│                    │
│ Manual review     │
│ by ArbSec team    │
│                    │
│ Approve / Reject  │
│ with reason       │
└──────────────────┘
        │
        ▼
┌──────────────────┐
│ Transparency Log  │
│                    │
│ Append-only log   │
│ of all decisions  │
│                    │
│ Public audit      │
└──────────────────┘
        │
        ▼
Published to feed
```

## Submission criteria

Valid submissions include:

- **Malware distribution URLs** found in scripts or packages
- **Typosquatting domains** that impersonate legitimate software
- **Compromised package registries** with malicious packages
- **Known malicious hash prefixes** for large malware families
- **Phishing kits** detected in wild

Invalid submissions (rejected):

- Private personal data
- Heuristic-only findings without confirmation
- Indicators from internal Red Team assessments (not shared externally)
- Duplicate submissions

## Trust tiers

Submitters are classified by trust tier:

| Tier | Description | Score modifier |
|------|-------------|----------------|
| **Verified** | Identity-verified submitters | +1 confidence |
| **Trusted** | Long-standing community members | +0 |
| **New** | New accounts | -1 confidence |
| **Anonymous** | No account | Not accepted |

## Review workflow

### Step 1: Automated checks

```rust
// Automated validation
if is_duplicate(indicator) { return Reject("duplicate") }
if !is_valid_format(indicator) { return Reject("invalid_format") }
if contains_pii(indicator) { return Reject("pii_found") }
if !passes_heuristics(indicator) { return Flag("needs_review") }
```

### Step 2: Triage

Indicators are triaged based on:

- Source tier (verified, trusted, new)
- Severity (critical, high, medium)
- Confidence (high, medium, low)
- Tags overlap with existing indicators

High-confidence critical indicators from verified sources can be fast-tracked.

### Step 3: Review

A reviewer examines:

- Source of the indicator (how was it discovered?)
- Supporting evidence (sample, VT report, blog post)
- Context (targeted campaign, opportunistic)

### Step 4: Decision

| Decision | Meaning |
|----------|---------|
| **Approve** | Indicator published to feed |
| **Reject** | Indicator not published, submitter notified |
| **Escalate** | Forward to appropriate party (e.g., CERT) |
| **Needs more info** | Reviewer requests additional context |

## Transparency log

All decisions are recorded in an append-only transparency log:

```json
{
  "log_version": "1.0",
  "entries": [
    {
      "index": 12345,
      "timestamp": "2026-06-23T12:00:00Z",
      "action": "approve",
      "indicator": {
        "type": "url",
        "value": "https://evil.example.com/malware.exe"
      },
      "submitter": "user:abc123",
      "reviewer": "arbsec:reviewer:xyz",
      "reason": "Confirmed malware via sandbox execution",
      "evidence": ["https://example.com/vt-report"]
    },
    {
      "index": 12346,
      "timestamp": "2026-06-23T13:00:00Z",
      "action": "reject",
      "indicator": {
        "type": "domain",
        "value": "legitimate-software.com"
      },
      "submitter": "user:def456",
      "reviewer": "arbsec:reviewer:xyz",
      "reason": "Legitimate software domain, not typosquatting"
    }
  ]
}
```

The log is publicly readable and can be audited to verify the integrity of decisions.

## Dispute resolution

If a submitter believes an indicator was incorrectly rejected:

1. File a dispute through the API with `dispute_reason`
2. Original reviewer re-examines
3. If upheld, escalate to senior reviewer
4. Final decision recorded in transparency log

Disputes cannot overturn approval decisions by reviewers.

## API reference

### Submit indicator

```http
POST /api/v1/indicators
Authorization: Bearer <token>
Content-Type: application/json

{
  "indicator": {
    "type": "url",
    "value": "https://evil.example.com/malware.exe"
  },
  "source": "found-in-shellscript",
  "evidence": [
    {
      "type": "url",
      "value": "https://example.com/vt-report"
    }
  ],
  "tags": ["malware", "payload"]
}
```

### Response

```json
{
  "id": "ind-abc123",
  "status": "pending_review",
  "estimated_review_time": "48h"
}
```
