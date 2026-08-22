# Reference corpora

Snapshots of two public reference sources. Both are works of the United States
government and are in the public domain.

| File | Source | Used for |
|---|---|---|
| `kev_catalogue.json` | [CISA Known Exploited Vulnerabilities catalogue](https://github.com/cisagov/kev-data) | Confirming which published CVE identifiers are exploited in the wild and which are associated with ransomware campaigns |
| `nist_sp800_53_controls.json` | [NIST SP 800-53 Rev. 5 control catalogue](https://github.com/usnistgov/oscal-content) | Retrieving remediation guidance, quoted from the control text |
| `manifest.json` | — | Retrieval date, source URLs, content digests and record counts |

## Why these are committed

They are checked in rather than downloaded on demand so that:

- a clone runs with no network access;
- every run is reproducible against a known snapshot, and the report states
  which one it used;
- the deployed application never depends on a third party being reachable
  while somebody is reading a report.

## Refreshing

```bash
python scripts/fetch_reference_data.py            # download and overwrite
python scripts/fetch_reference_data.py --verify   # check what is present
```

The fetch fails rather than writing a partial snapshot if a source is
unreachable, returns nothing usable, or omits any control the scenario depends
on. `manifest.json` records the retrieval date, so a stale snapshot is visible
rather than silent.
