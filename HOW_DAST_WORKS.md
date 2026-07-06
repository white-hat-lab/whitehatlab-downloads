# How White Hat Labs DAST Works

This guide explains the main workflow in `WhiteHatLabs-DAST-v1.2` and what each tab does.

The app is built for web application penetration testing. It helps you collect URLs from Burp or the crawler, save them inside an engagement, send selected targets to the scanner agent, and build a report from confirmed findings.

The public download contains the packaged app only. Source code is private.

## Main Workflow

Use this flow for a normal test:

1. Start a new engagement.
2. Browse the target through Burp, or run the crawler.
3. Import or add the endpoints you want to test.
4. Send selected endpoints to the scanner.
5. Add credentials, cookies, target notes, or test instructions.
6. Start the scan.
7. Review confirmed findings in the Report tab.
8. Export the final report.

Screenshot placeholder:

```text
screenshots/dast-main-workflow.png
```

## Engagements

An engagement is one saved test workspace.

Each engagement keeps its own data:

- Scanner target list
- Scanner logs
- Agent notes
- Proxy rows imported from Burp
- Crawler results
- Findings
- Report data

Start a new engagement when you begin testing a new target or a new test run.

The app is designed so a new engagement starts clean. Old Burp imports, scan results, and report data should not mix into the new test.

Screenshot placeholder:

```text
screenshots/dast-engagements.png
```

## Scanner Tab

The Scanner tab is where the AI agent tests selected URLs.

Use it when you already know what URLs you want to test.

You can paste one or more target URLs into the target box. The scanner does not need to crawl when you provide exact URLs. It should test the URLs you gave it and report only findings from that scan.

The scanner supports:

- GET and POST targets
- Authentication details
- Cookies or session context
- App notes
- Manual instructions for the agent
- Burp proxy routing
- Codex or Claude backend selection

The agent log should show what the agent is doing. It should read your notes at the start of the scan, use available helper tools when useful, and report confirmed findings with proof.

Use the Scanner tab for focused testing like:

- XSS testing
- IDOR testing
- JWT/session testing
- Access control checks
- Header/security control checks
- File exposure checks
- API behavior checks

Screenshot placeholder:

```text
screenshots/dast-scanner.png
```

## Crawler Tab

The Crawler tab discovers endpoints from a starting URL.

Use it when you want the app to find links, forms, scripts, and paths before scanning.

The crawler can:

- Crawl same-host pages
- Route discovery traffic through Burp
- Run content discovery
- Normalize duplicate URLs
- Follow redirects to find real 200 OK endpoints
- Send discovered endpoints to Scanner
- Add discovered endpoints to Proxy

If the app only finds the home page, the target may require:

- Browser interaction
- Login
- JavaScript-rendered navigation
- Manual browsing through Burp first
- A deeper starting URL

For targets with heavy JavaScript or complicated navigation, browse the app manually through Burp and import those requests instead of relying only on crawler discovery.

Screenshot placeholder:

```text
screenshots/dast-crawler.png
```

## Proxy Tab

The Proxy tab stores selected request rows for the active engagement.

It is not meant to replace Burp. Burp remains the main proxy tool. This tab saves the useful rows from Burp into the current engagement so they can be reviewed, selected, and sent to Scanner.

Use `Import from Burp` when you want to copy current Burp history into the engagement.

The Proxy tab shows normalized attack vectors instead of noisy one-time payload values. This helps remove duplicate rows and makes the table easier to scan.

The table includes:

- Method
- Attack vector
- Status
- Response length
- View action
- Scan action

Rows should be filtered so useful 200 OK targets are easy to find. Redirect-only noise, duplicate rows, and stale rows should not dominate the view.

Click a URL or attack vector to open it in the browser.

Use `Scan` on one row, or select multiple rows and send them to Scanner.

Screenshot placeholder:

```text
screenshots/dast-proxy.png
```

## Burp Tab

The Burp tab talks to the included Burp extension.

It shows what the app can currently read from Burp. This is useful before importing rows into an engagement.

The Burp tab can:

- Check whether Burp is connected
- Show Burp proxy history
- Normalize Burp URLs
- Deduplicate rows
- Send selected Burp rows to Scanner
- Send all visible Burp rows to Scanner
- Clear the displayed Burp view

The Burp tab is a live bridge view. The Proxy tab is the saved engagement copy.

Use this rule:

```text
Burp tab = what Burp currently has
Proxy tab = what this engagement saved
```

If the Burp tab says there are no new rows after the clear point, click `Show all` to load existing Burp history.

Screenshot placeholder:

```text
screenshots/dast-burp.png
```

## Report Tab

The Report tab shows confirmed scanner findings for the selected engagement.

A report should include only what was found in that engagement. It should not include findings from old scans or other engagements.

Each finding should include:

- Severity
- Finding type
- Affected URL
- Method
- Evidence
- Risk reasoning
- Retest steps
- Proof of concept
- Working curl command
- Clickable URL when applicable
- Request and response evidence

The report can be exported as:

- CSV
- DOCX

If a report template is configured, the app can build the final report using the uploaded template and the findings from the active engagement.

Screenshot placeholder:

```text
screenshots/dast-report.png
```

## Network Tab

The Network tab is for connection and environment checks.

Use it to understand whether the app can reach the services it depends on.

It can help verify:

- App server status
- Burp proxy reachability
- Burp bridge reachability
- Local ports
- Target reachability
- Docker host networking issues

This tab is useful when the scanner or crawler cannot connect to a target or Burp.

Screenshot placeholder:

```text
screenshots/dast-network.png
```

## New Engagement Button

Click `New Engagement` to create a fresh test workspace.

A new engagement should start empty:

- No saved proxy rows
- No old crawler endpoints
- No old scanner findings
- No old report data

After creating the engagement, select it from the engagement list before importing Burp rows or starting a scan.

Screenshot placeholder:

```text
screenshots/dast-new-engagement.png
```

## Import From Burp

Use `Import from Burp` when you want to copy Burp traffic into the active engagement.

Before importing:

1. Start or select an engagement.
2. Open Burp Suite.
3. Make sure the White Hat Labs Burp extension is loaded.
4. Browse the target through Burp.
5. Click `Import from Burp`.

The imported rows are saved to the active engagement.

Screenshot placeholder:

```text
screenshots/dast-import-from-burp.png
```

## Send To Scanner

Use `Send to Scanner` when you want the scanner agent to test selected endpoints.

You can send:

- One row
- Selected rows
- All visible rows
- Crawler results
- Burp rows
- Proxy rows saved in the engagement

After sending rows to Scanner, review the target list, add credentials or notes, and start the scan.

Screenshot placeholder:

```text
screenshots/dast-send-to-scanner.png
```

## Authentication

Some targets need login, cookies, or tokens.

You can provide:

- Login URL
- Username
- Password
- Cookie override
- Notes for the agent

For authenticated testing, first confirm the target works in the browser or Burp with the same session context.

If the app needs help during a scan, the agent can pause and ask for missing information such as a password, token, or role detail.

Screenshot placeholder:

```text
screenshots/dast-authentication.png
```

## Agent Notes

Agent notes are read at the beginning of the scan.

Use notes to tell the agent what matters for the test.

Good examples:

```text
Test for IDOR. Try changing object IDs and compare access between normal users.
```

```text
JWT is stored in the JWT cookie. Check claim tampering, bad signature, expired token, and role changes.
```

```text
This is an XXE endpoint. Test safe XML payloads only and confirm impact before reporting.
```

Keep notes short and specific. The agent should still decide which tools and checks are useful.

Screenshot placeholder:

```text
screenshots/dast-agent-notes.png
```

## Tools And Scripts

The scanner can use helper scripts and installed tools when available.

The app should tell the agent that tools and scripts are available, but the agent should choose when to use them.

Examples of useful tool areas:

- URL/request replay
- Response diffing
- JWT checks
- Header checks
- Reflection checks
- IDOR comparison
- File exposure checks
- Directory discovery
- Report finding creation

The agent should not report a finding only because a tool ran. It should report only when there is clear proof.

## What The App Should Not Do

The app should not:

- Mix old engagement data into a new engagement
- Report findings from a different scan
- Treat every redirect as a real endpoint
- Fill reports with unconfirmed issues
- Replace Burp as the main proxy
- Expose source code in public downloads
- Require users to manually edit private source files

## Success Check

The app is working correctly when:

- A new engagement starts empty
- Burp connects through the included extension
- Burp rows can be imported on demand
- Proxy rows are saved per engagement
- Scanner receives only the selected targets
- Agent logs show live progress
- Reports include only confirmed findings from the selected engagement
- Exported reports include retest steps, proof, curl, evidence, and clickable URLs

