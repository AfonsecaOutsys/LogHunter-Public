# CDN Detection Future Directions

## Goal

Add CDN awareness to LogHunter without baking CDN logic into the current ALB parsers or existing export generation flow.

The work should split into two separate capabilities:

1. Detect whether a public website is fronted by a CDN.
2. Analyze already-generated Excel, CSV, and SQLite outputs on demand and flag likely CDN usage in the results.

## Guiding Constraint

CDN detection should be implemented as a dedicated parser/analyzer that runs explicitly when requested by the operator.

Do not:

- fold this into the existing ALB raw log parsers
- add CDN-specific branching into the current export pipeline
- make every existing export slower or more complex by default

## Capability 1: Website Fronted By CDN

### Purpose

Determine whether a hostname is likely served through a CDN, even before looking at ALB traffic.

### Expected Input

- hostname or URL

### Detection Signals

- DNS resolution
- CNAME chain inspection
- resolved A/AAAA records
- IP-to-provider matching against known CDN CIDR ranges
- HTTP response header fingerprinting
- optional TLS certificate and edge behavior inspection

### Common Signals To Check

- `server`
- `via`
- `x-cache`
- `x-served-by`
- `cf-ray`
- `cf-cache-status`
- `akamai-*`
- CloudFront-style cache headers

### Output Shape

Return a confidence-based result, not a binary truth claim.

Suggested output fields:

- `Hostname`
- `DetectedProvider`
- `Confidence`
- `DetectionReasons`
- `ResolvedIps`
- `MatchedCidrs`
- `ProbeTimestampUtc`

### Confidence Model

- `High`: provider-owned hostname pattern and IP range match, or strong response-header fingerprint
- `Medium`: IP range match only, or multiple weak indicators
- `Low`: heuristic match without provider-owned ranges
- `None`: no CDN indicator found

### Notes

- This is domain-level detection.
- It answers "is this site probably fronted by a CDN?"
- It does not prove that every ALB request passed through that CDN.

## Capability 2: On-Demand CDN Analysis For Existing Outputs

### Purpose

Take artifacts already produced by LogHunter and annotate rows that are likely CDN-originated based on the client IPs present in those exports.

This should work after the fact on:

- Excel exports
- CSV exports
- SQLite outputs

### Core Idea

The analyzer reads the exported dataset, finds the source/client IP column, checks those IPs against a local CDN intelligence dataset, and writes a flagged result.

This should be a separate action the operator runs on demand.

### Important Separation

The current parsers/exporters should remain responsible for:

- parsing ALB logs
- generating normal reports
- exporting current datasets

The CDN analyzer should be responsible for:

- opening an existing artifact
- identifying the relevant IP field
- enriching rows with CDN match information
- applying display cues such as row color changes

## Artifact-Specific Behavior

### Excel

Likely the best first target because it supports operator-friendly highlighting.

Possible behavior:

- add a new worksheet with CDN analysis summary
- add new columns such as `CDN`, `CDN Provider`, `CDN Confidence`, `Matched CIDR`
- apply row fill color when a CDN match is found
- optionally use different colors for `High`, `Medium`, and `Low`

### CSV

CSV cannot store color, so the output should be a derived CSV.

Possible behavior:

- generate a sibling file with appended columns
- preserve original rows
- add fields such as `cd n_detected`, `cdn_provider`, `cdn_confidence`, `matched_cidr`

Rename that field later to `cdn_detected`; the spacing above is only here to avoid accidental copy/paste into code without review.

### SQLite

Treat SQLite as an analyzable store, not something to mutate blindly.

Possible behavior:

- create a companion table for CDN analysis results
- or create a derived database copy with appended columns
- avoid altering the original database by default

Preferred approach:

- keep source tables intact
- write analysis results into a dedicated table keyed by row identifier or source IP

## Detection Basis For Export Analysis

### What We Can Reliably Use

- source/client IP visible in ALB-derived exports
- known CDN IP ranges
- optional ASN ownership data

### What We Cannot Reliably Use From ALB Exports Alone

- original client IP behind the CDN
- request headers not preserved by the export
- proof that a request definitely passed through a CDN when no match is found

### Result Language

Use careful wording:

- `Likely CDN`
- `Likely Cloudflare`
- `Likely CloudFront`
- `Likely Fastly`
- `Unknown`
- `No known CDN match`

Avoid absolute wording like:

- `Confirmed CDN`
- `Definitely direct`

unless future correlation data supports it.

## Shared Intelligence Layer

Both capabilities should use the same local provider intelligence package.

### Data Sources To Support

- AWS `ip-ranges.json` for CloudFront and related AWS ranges
- Cloudflare published IPv4/IPv6 lists
- Fastly published address list
- other providers when reliable published ranges exist
- optional local ASN database for fallback classification

### Local Cache Requirement

Do not make runtime network access a requirement for analysis.

Instead:

- maintain a local cache/snapshot
- allow manual refresh when needed
- stamp datasets with `last updated`

## Proposed Architecture

### 1. CDN Intelligence Module

Responsibilities:

- load provider CIDRs
- normalize IPv4/IPv6 values
- perform fast CIDR lookups
- return provider and matched range

### 2. Website Probe Module

Responsibilities:

- resolve hostnames
- inspect DNS chain
- fetch headers
- classify likely CDN fronting

### 3. Export Analyzer Module

Responsibilities:

- open Excel, CSV, or SQLite
- locate client IP field
- enrich rows from CDN intelligence
- write a derived output or analysis layer

### 4. Presentation Layer

Responsibilities:

- row highlighting for Excel
- summary counts by provider
- direct vs likely-CDN breakdown
- mismatch reporting where hostname probe says CDN but export analysis does not show CDN IPs

## Suggested Operator Workflow

### Website Probe

1. Enter hostname
2. Run CDN fronting probe
3. View likely provider and confidence

### Export Analysis

1. Select existing Excel, CSV, or SQLite artifact
2. Run CDN analysis
3. Produce a derived analyzed artifact
4. Review flagged rows and provider summary

## Initial Scope Recommendation

Build in this order:

1. Shared CDN IP intelligence layer
2. On-demand Excel analyzer with row highlighting
3. CSV analyzer with appended columns
4. SQLite analyzer with companion results table
5. External website probe

Rationale:

- export analysis is closer to immediate operator value
- Excel highlighting matches the intended workflow
- shared intelligence can be reused later by the hostname probe

## Open Questions For Later

- Which existing export types already contain stable client IP columns?
- Do current Excel exports have a consistent header name for source IP?
- Should analyzed artifacts overwrite the original file or always generate siblings?
- What exact color palette should represent provider/confidence states?
- Should the website probe support batch mode for multiple domains?
- Do we want a manual provider override when CIDR evidence is weak?

## Non-Goals For First Pass

- modifying current ALB parser behavior
- changing existing export defaults
- introducing mandatory online lookups during analysis
- making claims about original end-user IPs behind a CDN
- solving every CDN provider from day one

## Summary

This should be treated as a separate on-demand CDN analysis feature set with two modes:

- hostname probing to estimate whether a site is fronted by a CDN
- post-processing of existing LogHunter artifacts to flag likely CDN traffic

The clean design is to centralize provider intelligence once and reuse it in both paths.
