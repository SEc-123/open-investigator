# Open Investigator external entry status

Status date: 2026-05-29

This file records browser-driven discovery and community-entry work so future
promotion runs can continue from the current state instead of rediscovering the
same blockers.

## Completed

| Entry | Status | Evidence or note |
|---|---|---|
| GitHub topics/About | Live | Repository topics are `incident-response`, `dfir`, `blue-team`, `security-tools`, `rust`, `linux`, `windows`, `cybersecurity`, `forensics`, and `ai-tools`. |
| Google Search Console property | Verified | URL-prefix property `https://www.arvantacyber.com/` was verified with `google2da9e3bda6247f36.html`. |
| Google sitemap submission | Submitted | `https://www.arvantacyber.com/sitemap.xml` was submitted after verification. |
| Google URL inspection | Requested | Indexing was requested for `https://www.arvantacyber.com/open-investigator/`. Google reported the URL as discovered but not yet indexed immediately after submission. |
| Public verification file | Live | `https://www.arvantacyber.com/google2da9e3bda6247f36.html` returns the required verification content. |
| IndexNow key file | Live | `https://www.arvantacyber.com/13364d5feadbc1c04e4fa1f863949292.txt` returns the required IndexNow key. |
| IndexNow URL push | Accepted | The Open Investigator overview and eight topic pages were submitted to `https://api.indexnow.org/indexnow`; the API returned HTTP `202 Accepted`. |
| Public article pages | Live | `https://www.arvantacyber.com/open-investigator/articles/suspicious-ip-linux-triage/` and `https://www.arvantacyber.com/open-investigator/articles/ai-incident-tool-safety-boundary/` are live and included in sitemap.xml. |
| Arvanta website release | Live | Search verification files, Open Investigator SEO pages, and article pages are live in website release `20260529162121`; public crawl checked 31 pages with 0 broken links. |

## In Progress

| Entry | Current state | Next action |
|---|---|---|
| Bing Webmaster Tools | Needs site access or import from Google Search Console | Add/import `https://www.arvantacyber.com/`, submit `/sitemap.xml`, then inspect the Open Investigator overview and topic pages. IndexNow submission is already accepted as a search-discovery fallback. |
| Hacker News | Account created, Show HN restricted | HN accepted the new account login, but Show HN submission was blocked by the temporary/new-user Show HN restriction page. The next action is to use the account for normal non-promotional participation before submitting occasional Show HN posts. Do not coordinate votes. |
| Reddit | Drafts are ready | Review target subreddit rules, ask moderators where unclear, and use the educational safety-boundary or suspicious-IP article instead of a direct ad. |
| LinkedIn | Login required | Copy is ready. Publish from a founder/operator account with transparent affiliation and one specific use-case link after login. |
| X | Login required | Thread is ready. Publish with commands, safety boundary, GitHub link, and the most specific topic page after login. |
| Product Hunt | Cloudflare/security gate and launch assets not ready | Prepare screenshots, a short demo video, and a warmed personal maker account before launch. Do not use a company/branded account. |
| Directories/newsletters | Queue is ready | Submit one relevant directory or newsletter per week and track date, URL, status, owner, and follow-up. |

## Search Follow-Up

Recheck Google Search Console after Google processes the sitemap:

1. Confirm `/sitemap.xml` has moved out of the initial unknown/crawl-pending
   state.
2. Inspect the eight topic URLs from `community-scale-plan.md`.
3. Request indexing for any topic page that is discovered but not yet indexed.
4. Record crawl/indexing state changes here or in the weekly promotion report.

For Bing Webmaster Tools, use the same sitemap and URL list. If Bing offers
Google Search Console import, prefer that path because the Google property is
already verified.

IndexNow follow-up:

- Overview and topic pages were accepted with HTTP `202`.
- Article-page retry on 2026-05-29 hit Bing-side temporary failures:
  `503 OriginTimeout`, one SSL connect error, and one timeout.
- Because both article pages are live in sitemap.xml, the next weekly loop
  should retry IndexNow and then inspect Bing/GSC state.

## Posting Rules

- Post useful technical material, not repeated launch announcements.
- Disclose affiliation in community posts.
- Do not ask for votes, coordinated comments, or artificial engagement.
- Stop at account, verification-code, CAPTCHA, payment, or unclear moderation
  gates and record the handoff.

## Browser Handoffs

| Platform | Handoff |
|---|---|
| Bing Webmaster Tools | Browser page is on the public Webmaster Tools entry page; the button did not open a usable login flow in the current session. Use Microsoft/Bing login or Google Search Console import manually, then submit `/sitemap.xml`. |
| Hacker News | New `arvantacyber` account reached the submit form, but Show HN was redirected to the temporary Show HN restriction page for new/unfamiliar users. Warm the account through normal participation first. |
| LinkedIn | Login page is required before posting the prepared launch or suspicious-IP follow-up copy. |
| X | Login/onboarding page is required before posting the prepared thread. |
| Product Hunt | Cloudflare security verification blocked automated progress; launch should wait for human browser verification plus media readiness. |
