# How The Read-Out Works

The Read-Out builds a final client report from three inputs:

1. A DOCX customer template
2. One or more source DOCX reports
3. Evidence screenshots

It is a report generator only. It does not scan targets.

## Report Template

Upload the active customer DOCX template. The app stores it as:

```text
report_templates/default_pentest_template.docx
```

The final DOCX is generated from that template.

## Source Reports

Upload source reports through the UI or place them here:

```text
report_templates/source_reports/
```

The app extracts report context, affected URLs, findings, evidence, retest steps, curl commands, and response details where available.

## Evidence Screenshots

Upload screenshots through the UI or place them here:

```text
report_templates/evidence_screenshots/
```

Use finding-style names:

```text
H1.png
H1-1.png
H1-2.png
L1.png
M1.png
```

The prefix maps screenshots to finding severity and number.

## Outputs

- `Open HTML Report` opens the merged report in the browser.
- `Download Final DOCX` downloads the final Word report.

Recommended workflow:

1. Upload the customer template.
2. Upload all source reports.
3. Upload evidence screenshots.
4. Open the HTML report to review.
5. Download the final DOCX.
