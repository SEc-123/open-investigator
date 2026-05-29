# Open Investigator content distribution assets

Status date: 2026-05-29

This file turns Open Investigator promotion into repeatable content, paid,
directory, and partnership motions. It complements the community drafts in
`community-posts.md`.

## Published Content URLs

Use these public pages when posting outside GitHub:

| Asset type | Public URL | Best audience |
|---|---|---|
| Product overview | https://www.arvantacyber.com/open-investigator/ | General technical readers, CTOs, security leads |
| Problem article | https://www.arvantacyber.com/open-investigator/articles/suspicious-ip-linux-triage/ | Linux admins, blue team, SREs, incident responders |
| Safety/boundary article | https://www.arvantacyber.com/open-investigator/articles/ai-incident-tool-safety-boundary/ | Security engineers, CTOs, AI safety/security discussion |
| Comparison page | https://www.arvantacyber.com/open-investigator/open-investigator-vs-siem-soar/ | Buyers and security leaders comparing scope |
| Report page | https://www.arvantacyber.com/open-investigator/ai-dfir-reporting-tool/ | DFIR teams and teams evaluating report handoff |

## Content Types

| Type | Asset | Status | Next action |
|---|---|---|---|
| Problem content | Suspicious-IP Linux triage article | Published | Share in Linux/SRE/blue-team contexts when relevant. |
| Tutorial content | Long-form usage article and quick-start commands | Drafted in repo | Turn into a 4-6 minute demo video or docs page. |
| Comparison content | SIEM/SOAR/EDR boundary page | Published | Use in LinkedIn, newsletter, and buyer-facing posts. |
| Case content | Suspicious-IP mini case | Ready below | Use as a short post or video narrative. |
| Video content | 90-second demo script | Ready below | Record terminal + report walkthrough before Product Hunt. |

## Mini Case Narrative

Title:

```text
From one suspicious IP to a reviewable host evidence report
```

Story:

```text
An alert starts with a single IP address. The responder does not know whether it
is a scanner, customer, proxy, admin VPN, or attacker.

Open Investigator runs locally and starts with:

oi ip 1.2.3.4 -s 7d

The first pass checks where the IP appears, whether it touched auth or web logs,
whether it is connected now, whether a process or service is related, and
whether recent files or persistence changed near the same time.

The useful result is not "AI says compromised." The useful result is a case
folder with evidence.jsonl, commands.log, report.json, and report.md that a
responder can review, challenge, and extend.
```

CTA:

```text
Try the open-source CLI on a non-production host:
https://github.com/SEc-123/open-investigator
```

## 90-Second Demo Video

Goal: create the Product Hunt/social launch video without overproducing it.

Shot list:

| Time | Screen | Voiceover |
|---|---|---|
| 0-10s | GitHub README and product mark | "Open Investigator is an Apache-2.0 local AI server investigator for incident response." |
| 10-25s | Terminal: clone/build | "It runs locally and gives AI sealed read-only tools instead of raw shell." |
| 25-45s | Terminal: `oi scan -s 7d` and `oi ip 1.2.3.4 -s 7d` | "Start from a vague server anomaly, suspicious IP, account, path, web root, Java service, or process." |
| 45-65s | Case directory listing | "Every run writes case artifacts: evidence.jsonl, commands.log, report.json, and report.md." |
| 65-80s | Report preview | "The output is a reviewable first-pass investigation report with evidence, gaps, confidence, and follow-up points." |
| 80-90s | Website overview and GitHub URL | "It investigates. It does not remediate, isolate hosts, block IPs, or mutate production systems." |

Caption:

```text
Open Investigator: local read-only AI server investigation for Linux and
Windows incident response.
```

## Paid Distribution Drafts

Do not spend money until analytics, conversion tracking, daily caps, and a
landing-page owner are set. Start tiny and stop quickly if traffic is low
quality.

Google Ads search groups:

| Group | Keywords | Landing page | Ad angle |
|---|---|---|---|
| AI incident response | `ai incident response tool`, `ai server investigation`, `ai dfir tool` | https://www.arvantacyber.com/open-investigator/local-ai-incident-response/ | "Investigate suspicious servers locally with read-only AI evidence collection." |
| Linux triage | `linux incident response cli`, `suspicious ip linux logs`, `linux host investigation tool` | https://www.arvantacyber.com/open-investigator/articles/suspicious-ip-linux-triage/ | "Start from a suspicious IP and produce a reviewable host report." |
| WebShell | `webshell investigation tool`, `web server incident response`, `suspicious web root file changes` | https://www.arvantacyber.com/open-investigator/webshell-investigation-tool/ | "Trace web clues into files, processes, network, and evidence reports." |

LinkedIn sponsored post:

```text
For security engineers and SREs: Open Investigator is an open-source local AI
server investigator. It lets AI collect read-only host evidence and produce
report.md/report.json without giving the model remediation authority.

Best for first-pass triage from suspicious IPs, WebShell clues, Java service
anomalies, login changes, process/network clues, and vague server alerts.

https://www.arvantacyber.com/open-investigator/
```

Reddit Ads test:

```text
Open-source local AI server investigation. Read-only evidence collection for
Linux/Windows incident response. No remediation authority, no raw shell in safe
mode.
```

Use only if targeting allows relevant technical communities and the ad links to
the practical article, not the homepage.

## Channel Partnership Outreach

Target groups:

- DFIR and incident-response newsletters
- blue-team newsletters
- Linux admin newsletters
- Java operations/SRE newsletters
- open-source security tool directories
- curated "awesome incident response" and DFIR lists
- practitioner blogs that review security tooling

Short outreach:

```text
Subject: Open-source read-only AI server investigator for DFIR/SRE readers

Hi <name>,

I maintain Open Investigator, an Apache-2.0 local AI server investigation CLI:
https://github.com/SEc-123/open-investigator

It lets AI collect host evidence through sealed read-only tools and produce
evidence.jsonl, commands.log, report.json, and report.md. The boundary is
explicit: it investigates but does not isolate hosts, kill processes, delete
files, disable accounts, restart services, block IPs, or change firewall state.

Two practical pages that may fit your readers:
- Suspicious-IP Linux triage:
  https://www.arvantacyber.com/open-investigator/articles/suspicious-ip-linux-triage/
- AI incident-tool safety boundary:
  https://www.arvantacyber.com/open-investigator/articles/ai-incident-tool-safety-boundary/

If this is useful for your DFIR, SRE, or blue-team audience, I would appreciate
feedback or inclusion in a tools/resources section. No ask for votes.

Thanks,
<name>
```

## Submission Tracker

Copy rows as work proceeds:

| Date | Channel | Contact or URL | Asset | Status | Result | Follow-up |
|---|---|---|---|---|---|---|
| YYYY-MM-DD | Newsletter | | Suspicious-IP article | drafted/sent/accepted/rejected | | |
| YYYY-MM-DD | Directory | | GitHub repo | submitted/live/rejected | | |
| YYYY-MM-DD | Blog/KOL | | Safety-boundary article | drafted/sent/responded | | |
| YYYY-MM-DD | Paid search | | Local AI incident response page | planned/live/paused | | |
