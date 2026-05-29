# Open Investigator community scale plan

This is the operating plan for turning Open Investigator promotion into a
repeatable community motion instead of a one-time launch post.

## Goal

Make Open Investigator discoverable by the people who already search for or
discuss server incident response, DFIR, WebShell triage, Java memory-shell
investigation, Linux/Windows host investigation, and safe AI security tooling.

Primary audiences:

- incident responders and DFIR practitioners
- blue-team and security engineers
- SREs and platform engineers doing first-pass server triage
- Java/Linux/Windows operators who need practical investigation workflows
- CTOs and security leads evaluating AI-assisted response boundaries

## Distribution ladder

1. Search foundation.
   Keep the overview page and eight topic pages healthy, indexed, and linked
   from the sitemap.

2. GitHub discovery.
   Keep repository About, website, topics, releases, README, and issues useful
   for people arriving from GitHub search.

3. Technical content.
   Publish practical articles that answer a real investigation question before
   linking the product.

4. Community discussions.
   Post in communities only when the post stands on its own as useful technical
   material. Disclose affiliation and avoid vote coordination.

5. Directory and newsletter submissions.
   Submit once to relevant lists, newsletters, and tool directories. Track every
   submission and follow-up.

6. Weekly loop.
   Review indexing, repo signals, community feedback, and the next best post.
   Convert useful feedback into docs, issues, or release tasks.

## 30-day content calendar

| Week | Asset | Primary page | Community angle |
|---|---|---|---|
| 1 | How to investigate a suspicious IP on a Linux server with read-only evidence collection | https://www.arvantacyber.com/open-investigator/local-ai-incident-response/ | Practical first-pass triage, not a launch announcement |
| 1 | Show HN post when maintainer can answer comments | https://github.com/SEc-123/open-investigator | Ask for feedback on the sealed-tool safety boundary |
| 2 | WebShell triage walkthrough: web logs, recent files, process context, and outbound connections | https://www.arvantacyber.com/open-investigator/webshell-investigation-tool/ | Useful for blue team, Linux admin, and web ops communities |
| 2 | LinkedIn/X technical takeaway from the WebShell walkthrough | https://www.arvantacyber.com/open-investigator/webshell-investigation-tool/ | Short operator-facing summary with repo link |
| 3 | Java memory-shell investigation without default heap dumps | https://www.arvantacyber.com/open-investigator/java-memory-shell-investigation/ | Java/SRE angle: layered diagnostics and production safety |
| 3 | Reddit discussion where rules allow: what safety boundary should AI incident tools have? | https://www.arvantacyber.com/open-investigator/read-only-ai-server-investigation/ | Ask a real design question; disclose affiliation |
| 4 | Why read-only AI investigation is not EDR, SIEM, or SOAR | https://www.arvantacyber.com/open-investigator/open-investigator-vs-siem-soar/ | Comparison/boundary article for security leaders |
| 4 | Monthly feedback post: what changed after first community feedback | https://github.com/SEc-123/open-investigator | Converts comments into product momentum |

## Article matrix

| Search phrase | Article title | Link target | Proof to include |
|---|---|---|---|
| suspicious IP server logs | How to investigate a suspicious IP on a Linux server | Local AI incident response page | `oi ip`, auth/web/network/process evidence, report artifacts |
| WebShell investigation tool | WebShell triage with web logs, recent files, and process context | WebShell page | `oi web --root`, suspicious requests, file changes, web-user processes |
| Java memory shell investigation | Java memory-shell clues without unsafe default dumps | Java page | `oi java`, `oi mem`, explicit `--java-deep`, heap/JFR gates |
| AI DFIR report | Turning host evidence into an auditable DFIR report | AI DFIR reporting page | `evidence.jsonl`, `commands.log`, `report.json`, `report.md` |
| read-only incident response | Why AI incident tools should start read-only | Read-only AI investigation page | sealed tools, no raw shell in safe mode, audited `oi_ro_run` |
| SIEM SOAR alternative | What Open Investigator is and is not compared with SIEM/SOAR/EDR | SIEM/SOAR boundary page | local host first-pass scope, no remediation, no fleet correlation |

## Community posting queue

| Channel | Status | Next action | Asset |
|---|---|---|---|
| GitHub topics/About | Live | Keep topics aligned with README and release notes | `rust`, `incident-response`, `forensics`, `dfir`, `security-tools`, `blue-team` |
| Hacker News | Ready if maintainer can cover comments | Submit one Show HN only when available for same-day replies | `docs/promotion/community-posts.md` |
| Reddit | Needs subreddit rule check per target | Ask moderators where rules are unclear; prefer educational posts | Reddit technical post draft |
| LinkedIn | Ready | Publish concise founder/operator post with specific use-case links | LinkedIn launch post |
| X | Ready | Publish thread with commands and safety boundary | X thread |
| Product Hunt | Not ready | Prepare screenshots, demo video, and a warmed personal maker account | Product Hunt draft |
| Google Search Console | Needs verified property access | Submit `https://www.arvantacyber.com/sitemap.xml` and inspect topic URLs | Search foundation |
| Bing Webmaster Tools | Needs verified property access | Submit sitemap and verify indexability | Search foundation |
| Directories/newsletters | Needs manual review | Submit to one relevant tool list per week | Directory queue |

Current external-entry progress and browser blockers are tracked in
`docs/promotion/external-entry-status.md`.

## Directory queue

Review and submit manually, one at a time:

- awesome incident response and DFIR lists
- blue-team and security tooling newsletters
- open-source security tool directories
- Java operations or SRE newsletters for the Java memory-shell article
- Linux admin newsletters for suspicious IP and WebShell walkthroughs
- Rust command-line tool showcases after release metadata is polished

Track each submission with date, URL, status, owner, and follow-up in the table
from `reusable-promotion-playbook.md`.

## Search engine handoff

Use the verified company account when available.

Google Search Console:

1. Open the verified `https://www.arvantacyber.com/` property.
2. Submit `https://www.arvantacyber.com/sitemap.xml`.
3. Inspect these URLs and request indexing if Google has not discovered them:
   - `https://www.arvantacyber.com/open-investigator/`
   - `https://www.arvantacyber.com/open-investigator/local-ai-incident-response/`
   - `https://www.arvantacyber.com/open-investigator/read-only-ai-server-investigation/`
   - `https://www.arvantacyber.com/open-investigator/webshell-investigation-tool/`
   - `https://www.arvantacyber.com/open-investigator/java-memory-shell-investigation/`
   - `https://www.arvantacyber.com/open-investigator/linux-host-investigation/`
   - `https://www.arvantacyber.com/open-investigator/windows-host-investigation/`
   - `https://www.arvantacyber.com/open-investigator/open-investigator-vs-siem-soar/`
   - `https://www.arvantacyber.com/open-investigator/ai-dfir-reporting-tool/`

Bing Webmaster Tools:

1. Add or open the verified `https://www.arvantacyber.com/` site.
2. Submit `https://www.arvantacyber.com/sitemap.xml`.
3. Inspect the same Open Investigator URLs.

## Weekly scale loop

Every week, the automation should:

1. Verify overview and topic-page status, title, description, canonical, robots,
   and sitemap coverage.
2. Review GitHub topics, README friction, new issues, stars, forks, releases,
   and CI status.
3. Choose one article from the matrix or community feedback.
4. Recommend one channel action and one link target.
5. Record platform blockers: login, account age, missing demo media, unclear
   community rules, property verification, or search-console processing state.
6. Never ask for votes, mass-post, hide affiliation, or bypass platform gates.
