# Open Investigator promotion kit

This folder is the reusable launch and community kit for Open Investigator.
It is written so the same operating model can be reused for future Arvanta
open-source or developer-tool launches.

## Positioning

Open Investigator is an Apache-2.0, local, read-only AI server investigator for
Linux and Windows hosts.

One-line description:

```text
Open Investigator lets an AI investigator collect local host evidence through
sealed read-only tools and produce an auditable incident report.
```

Short pitch:

```text
Given a suspicious IP, account, path, web root, Java service, process, or vague
server anomaly, Open Investigator lets an AI call bounded read-only tools,
correlate evidence, and generate report.md/report.json without giving the model
raw shell access or remediation authority.
```

Audience:

- incident responders
- security engineers
- DFIR practitioners
- SREs and platform engineers who do first-pass triage
- CTOs and security leads evaluating AI-assisted response workflows
- developers who operate Linux or Windows servers

Not the audience:

- buyers looking for EDR replacement
- teams expecting cross-host SOAR orchestration
- users who want automatic host remediation

## Canonical links

- Website: https://www.arvantacyber.com/open-investigator/
- GitHub: https://github.com/SEc-123/open-investigator
- Feedback: oi@arvantacyber.com
- License: Apache-2.0
- Product mark: `assets/open-investigator-mark.svg`

## Search landing pages

Use the most specific page when posting or answering a question. Use the GitHub
link when the user wants source, install commands, issues, or contribution
details.

| Topic | Public page |
|---|---|
| Local AI incident response | https://www.arvantacyber.com/open-investigator/local-ai-incident-response/ |
| Read-only AI server investigation | https://www.arvantacyber.com/open-investigator/read-only-ai-server-investigation/ |
| WebShell and web server anomalies | https://www.arvantacyber.com/open-investigator/webshell-investigation-tool/ |
| Java service and memory-shell clues | https://www.arvantacyber.com/open-investigator/java-memory-shell-investigation/ |
| Linux host triage | https://www.arvantacyber.com/open-investigator/linux-host-investigation/ |
| Windows host triage | https://www.arvantacyber.com/open-investigator/windows-host-investigation/ |
| SIEM/SOAR/EDR boundary | https://www.arvantacyber.com/open-investigator/open-investigator-vs-siem-soar/ |
| Evidence-backed DFIR reports | https://www.arvantacyber.com/open-investigator/ai-dfir-reporting-tool/ |

## Message pillars

1. Local and read-only by default.
   The runtime writes case artifacts, not target-system changes.

2. AI gets sealed tools, not raw shell.
   Safe mode exposes only `oi_*` investigation tools. Investigator mode adds a
   policy-filtered read-only command fallback.

3. Evidence is preserved.
   Every run creates a case directory with `evidence.jsonl`, `commands.log`,
   `report.json`, and `report.md`.

4. Built for real server questions.
   Start from an IP, account, path, web root, Java service, process, login
   anomaly, WebShell clue, persistence clue, or vague incident report.

5. Explicit safety boundary.
   It is not EDR, SOAR, firewall control, process killing, account disabling, or
   cleanup automation.

## Keyword map

Use these terms in docs, posts, and future SEO pages. Do not stuff keywords;
write useful pages that answer the searcher's real problem.

| Search intent | Page or article angle |
|---|---|
| AI server incident response tool | https://www.arvantacyber.com/open-investigator/local-ai-incident-response/ |
| Linux incident response CLI | https://www.arvantacyber.com/open-investigator/linux-host-investigation/ |
| Windows server incident investigation | https://www.arvantacyber.com/open-investigator/windows-host-investigation/ |
| AI DFIR tool | https://www.arvantacyber.com/open-investigator/ai-dfir-reporting-tool/ |
| WebShell investigation tool | https://www.arvantacyber.com/open-investigator/webshell-investigation-tool/ |
| Java memory shell investigation | https://www.arvantacyber.com/open-investigator/java-memory-shell-investigation/ |
| suspicious IP server logs | https://www.arvantacyber.com/open-investigator/local-ai-incident-response/ |
| read-only incident response | https://www.arvantacyber.com/open-investigator/read-only-ai-server-investigation/ |
| OpenAI function calling security tool | https://www.arvantacyber.com/open-investigator/read-only-ai-server-investigation/ |
| SIEM/SOAR comparison | https://www.arvantacyber.com/open-investigator/open-investigator-vs-siem-soar/ |

## Community rules to respect

The goal is durable community trust, not one-off traffic.

- Hacker News Show HN is for things people can try. Use a working GitHub link,
  real commands, clear limitations, and be present to answer questions.
  Official HN Show HN guidance: https://news.ycombinator.com/showhn.html
- Hacker News asks users not to ask friends to upvote/comment. Do not coordinate
  votes. Official HN guidelines: https://news.ycombinator.com/newsguidelines.html
- Product Hunt requires personal accounts for posting; company or branded
  accounts cannot post, vote, or comment. New personal accounts may need time
  before posting. Product Hunt help:
  https://help.producthunt.com/en/articles/481909-how-can-i-get-access-to-post
- Reddit treats repeated self-benefiting links as spam risk. Post useful
  technical material first, check subreddit rules, and ask moderators when in
  doubt. Reddit spam help:
  https://support.reddithelp.com/hc/articles/360043504051

## Launch assets

Product name:

```text
Open Investigator
```

Tagline:

```text
Local read-only AI server investigation for incident response.
```

Product Hunt title:

```text
Open Investigator - Local AI server investigator for incident response
```

Product Hunt subtitle:

```text
Let AI collect host evidence through sealed read-only tools and generate an
auditable incident report.
```

Hacker News title:

```text
Show HN: Open Investigator - local read-only AI server investigation CLI
```

Primary CTA:

```text
Try it on a non-production test host:
cargo build --release
./target/release/oi scan -s 7d
```

Secondary CTA:

```text
Read the safety model and send feedback or collector ideas.
```

## 14-day launch plan

Day 0:

- Confirm website title, description, canonical, robots, and sitemap.
- Confirm GitHub README has quick use, safety model, and contact.
- Prepare HN, Product Hunt, Reddit, LinkedIn, X, and email copy.
- Prepare one long-form article and one technical walkthrough.

Day 1:

- Publish the long-form technical article.
- Share a concise LinkedIn post from the founder/operator account.
- Share an X thread with commands, safety boundary, and GitHub link.

Day 2:

- Submit Show HN if the GitHub repo and README are ready for users to try.
- Stay online for questions for at least 4 hours after submission.
- Answer technical questions with evidence and limitations.

Day 3:

- Share a technical Reddit post only where rules allow it. Prefer education
  posts such as "How I designed read-only AI incident investigation" over a
  direct ad.

Day 4:

- Open GitHub issues for requested collectors or platform compatibility gaps.
- Convert useful community feedback into docs or roadmap tasks.

Day 5:

- Submit to relevant open-source directories and security tool lists.
- Send a short email to 10-20 trusted practitioners asking for feedback, not
  votes.

Day 7:

- Publish a follow-up post with real lessons: what users asked, what changed,
  which limitations remain.

Day 14:

- Decide whether Product Hunt is ready. If not, keep warming a personal account
  and ship one more demo/walkthrough before launch.

## Metrics

Track these weekly:

- GitHub stars, forks, issues, pull requests
- website visits to `/open-investigator/`
- referral traffic from HN, Reddit, LinkedIn, X, Product Hunt
- README-to-build friction found in issues or comments
- number of meaningful security practitioner conversations
- docs changes generated from community feedback

## Reuse template

For the next product, replace:

- product name
- GitHub URL
- website URL
- one-line pitch
- "what it is not"
- quick-start command
- 3 technical proof points
- 3 limitations
- target communities

Keep:

- no fake votes
- no spam
- no undisclosed affiliation
- real demo before launch
- one canonical page and one canonical repo
- weekly content, feedback, and directory checklist
