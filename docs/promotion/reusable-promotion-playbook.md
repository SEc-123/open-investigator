# Reusable community promotion playbook

This playbook converts a developer/security tool into a repeatable community
launch cycle. Use it for Open Investigator now and for future Arvanta launches.

## Principles

1. Build public assets before posting.
2. Post where the audience already discusses the problem.
3. Lead with technical usefulness, not adjectives.
4. Disclose affiliation.
5. Never coordinate fake votes, fake comments, or engagement pods.
6. Turn feedback into commits, issues, and docs.
7. Keep a weekly cadence after launch.

## Required assets per product

Each product launch needs:

- canonical website URL
- canonical source or download URL
- title, tagline, and one-line pitch
- logo or mark
- quick-start command or demo path
- one long-form technical article
- one Show HN style post
- one Reddit discussion post
- one LinkedIn post
- one X thread
- Product Hunt title, subtitle, maker comment, and media checklist
- email feedback request
- list of communities and moderators/rules status
- 30-day content calendar and article matrix
- directory/newsletter submission queue
- search engine submission handoff for sitemap and URL inspection
- weekly metrics template

## Weekly operating cadence

Monday:

- Check website indexing basics: title, description, canonical, robots,
  sitemap, HTTP status.
- Confirm all topic landing pages are still 200 and listed in sitemap:
  local AI incident response, read-only AI investigation, WebShell, Java,
  Linux, Windows, SIEM/SOAR boundary, and AI DFIR reporting.
- Review GitHub issues, discussions, and support email.
- Pick one user question to turn into public docs.

Tuesday:

- Publish or update one technical article.
- Share the article on LinkedIn/X with a clear technical takeaway.

Wednesday:

- Participate in relevant communities without linking unless directly useful.
- Answer one question in a way that stands alone without the product link.

Thursday:

- Submit to one directory, newsletter, awesome list, or open-source tool index.
- Track status, URL, and contact.

Friday:

- Review metrics and feedback.
- Open issues for product/documentation gaps.
- Prepare next week's post topic.

## Monthly community cycle

Week 1:

- Problem article.
- Example: "How to investigate a suspicious IP on a Linux server."

Week 2:

- Use-case walkthrough.
- Example: "Tracing WebShell clues with web logs, file changes, and process context."

Week 3:

- Comparison or boundary article.
- Example: "Why read-only AI investigation is different from EDR or SOAR."

Week 4:

- Release/follow-up article.
- Example: "What changed in Open Investigator after first community feedback."

## Tracking table

Copy this for each product.

| Date | Channel | URL | Asset used | Status | Result | Follow-up |
|---|---|---|---|---|---|---|
| YYYY-MM-DD | HN | | Show HN post | drafted/submitted/live | | |
| YYYY-MM-DD | Reddit | | discussion post | drafted/mod asked/submitted/live | | |
| YYYY-MM-DD | LinkedIn | | launch post | drafted/live | | |
| YYYY-MM-DD | X | | thread | drafted/live | | |
| YYYY-MM-DD | Product Hunt | | launch assets | not ready/warming/scheduled/live | | |
| YYYY-MM-DD | Directory | | listing | submitted/live/rejected | | |

## Automation prompt

Use this prompt for a weekly recurring automation:

```text
Run the reusable Arvanta community promotion loop for Open Investigator.

Check:
- website status for https://www.arvantacyber.com/open-investigator/
- topic page status and sitemap coverage for:
  - https://www.arvantacyber.com/open-investigator/local-ai-incident-response/
  - https://www.arvantacyber.com/open-investigator/read-only-ai-server-investigation/
  - https://www.arvantacyber.com/open-investigator/webshell-investigation-tool/
  - https://www.arvantacyber.com/open-investigator/java-memory-shell-investigation/
  - https://www.arvantacyber.com/open-investigator/linux-host-investigation/
  - https://www.arvantacyber.com/open-investigator/windows-host-investigation/
  - https://www.arvantacyber.com/open-investigator/open-investigator-vs-siem-soar/
  - https://www.arvantacyber.com/open-investigator/ai-dfir-reporting-tool/
- robots.txt and sitemap presence
- GitHub repo activity at https://github.com/SEc-123/open-investigator
- new issues, stars, forks, releases, and README friction
- current community-posting backlog in docs/promotion/

Produce:
- a short weekly promotion report
- one recommended technical post topic
- the best topic landing page to link for that post
- one community action for HN/Reddit/LinkedIn/X/Product Hunt or directories
- one directory/newsletter/search-console action when community posting is not
  ready
- any docs or website changes that should be made before posting

Do not spam communities or ask for votes. Prefer useful technical content and
feedback requests.
```

## Product Hunt readiness gate

Do not schedule Product Hunt until:

- personal maker account is at least one week old or otherwise eligible
- profile is complete
- demo video exists
- screenshots exist
- maker comment is ready
- GitHub README quick start works on a clean machine
- launch day support owner is available for comments
- no one is asked to create accounts only to vote

## Hacker News readiness gate

Do not submit Show HN until:

- project is usable without sales contact
- README quick start works
- limitations are explicit
- maintainer can answer comments the same day
- title begins with `Show HN:`
- submission points to GitHub or a usable demo, not only a landing page

## Reddit readiness gate

Do not post on Reddit until:

- subreddit rules have been checked
- the post is mostly educational
- affiliation is disclosed
- the account has normal non-promotional participation
- moderator permission is requested where rules are unclear
- post is customized for the subreddit

## Directory targets

Potential targets to review manually:

- GitHub topics: incident-response, dfir, blue-team, security-tools, rust
- GitHub topics already used for Open Investigator: rust, incident-response,
  forensics, dfir, security-tools, blue-team
- awesome incident response lists
- awesome security lists
- open-source security tool directories
- newsletters for blue team, DFIR, SRE, and Java operations
- security Slack/Discord communities where open-source tools are welcome

## Post-launch feedback loop

For every substantive comment:

1. Classify it as bug, docs friction, collector request, safety concern, or
   positioning feedback.
2. Open a GitHub issue or docs task if it is actionable.
3. Reply with the issue link or a clear answer.
4. Add high-frequency questions to README or docs.
5. Mention fixed feedback in the next weekly update.
