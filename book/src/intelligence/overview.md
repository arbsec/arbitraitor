# Intelligence Overview

Arbitraitor's intelligence system matches artifacts and indicators against threat intelligence feeds to improve detection accuracy.

## How intelligence works

```
Artifact or indicator
       │
       ▼
┌──────────────────┐
│ Intelligence      │
│ Pipeline          │
│                   │
│ 1. Extract        │
│    indicators     │
│    (URLs, IPs,    │
│    hashes, etc.)  │
│                   │
│ 2. Query feeds    │
│    in parallel    │
│                   │
│ 3. Aggregate      │
│    matches        │
│                   │
│ 4. Apply to       │
│    findings       │
└──────────────────┘
       │
       ▼
   Findings with
   TI enrichment
```

## Supported indicator types

| Type | Description |
|------|-------------|
| URL | Full URL with path |
| Domain | Domain name (exact or substring) |
| IP Address | IPv4 or IPv6 address |
| SHA-256 | File digest |
| Email | Email address |

## Feed types

### Built-in feeds

| Feed | Type | Description |
|------|------|-------------|
| URLhaus | Malware URL | Abuse.ch malware URL database |
| Community | Indicators | ArbSec community submissions |

### Custom feeds

Arbitraitor supports any feed that exposes a JSON or CSV API:

```toml
[intel.feeds.my-feed]
enabled = true
url = "https://feeds.example.com/indicators.json"
type = "json"  # json | csv
api-key = "secret://env/MY_FEED_API_KEY"
refresh-interval = "1h"
cache-ttl = "24h"

[intel.feeds.my-feed.format]
indicator-field = "indicator"
type-field = "type"
tags-field = "tags"
confidence-field = "confidence"
```

## Matching engine

The matching engine processes indicators in stages:

### Stage 1: Extraction

Extracts indicators from the artifact:

- URLs from shell scripts, HTML, JavaScript
- Domain names from URLs
- IP addresses from network-related content
- File hashes from referenced files (if accessible)

### Stage 2: Feed queries

Each extracted indicator is queried against enabled feeds in parallel:

```rust
let results = feed_lookup(indicator).await;
// Returns Vec<IndicatorMatch>
```

### Stage 3: Aggregation

Matches from multiple feeds are aggregated:

- Deduplicated by indicator + source
- Confidence scores normalized
- Tags merged

### Stage 4: Finding enrichment

Enriched indicators are added to findings:

```json
{
  "id": "network:curl",
  "severity": "high",
  "title": "Downloads content via curl",
  "intel": [
    {
      "indicator": "https://evil.example.com/payload.exe",
      "source": "urlhaus",
      "confidence": "high",
      "tags": ["malware", "payload"]
    }
  ]
}
```

## Indicator matching

### URL matching

URLs match if:

- Exact match: `https://evil.example.com/malware.exe`
- Domain match: any path under `evil.example.com`
- Pattern match: configurable wildcard patterns

### Hash matching

SHA-256 hashes match exactly:

- Artifact digest matches a known malware hash
- Referenced file digests match known malware

### Confidence levels

| Level | Meaning |
|-------|---------|
| Low | Single source, unverified |
| Medium | Multiple sources or recent report |
| High | Active campaign, multiple reports |

High-confidence intelligence matches can escalate findings even if the static analysis alone would not.

## Feed freshness

Feeds are refreshed on a configured interval:

```toml
[intel.feeds.urlhaus]
refresh-interval = "1h"  # Check for updates every hour
cache-ttl = "24h"        # Stale after 24 hours
```

If a feed is stale (last refresh > TTL), its matches are downgraded:

```
High confidence -> Medium
Medium confidence -> Low
Low confidence -> Ignored
```

## Configuring intelligence

See [Configuration](../configuration.md) for the full `[intel]` section reference.
