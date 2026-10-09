# Cadence Case Study 2: PII Detection and Redaction

This deliverable focuses on the supplied Case Study 2 brief and its three supporting artifacts. It includes an 18-slide stakeholder deck, a local upload prototype with a session-level reviewer dashboard, synthetic adversarial fixtures, evaluation results, and a sample-inventory summary. The deck covers the solution blueprint, architecture, extraction and detection logic, measured synthetic results, cybersecurity relevance, a dashboard walkthrough, and a relative three-week team submission plan.

**Security scope:** this remains a local, single-user prototype. It is not approved for real organizational documents or production deployment. Its detector is pattern-based and cannot promise complete PII coverage. The dashboard summarizes only the current browser session; it does not create a durable audit log or identify the reviewer. The Vercel version is a static sample-only demo; it does not run the local analysis workflow and must not accept real uploads.

The team ZIP includes the three Case Study 2 sample files in `Sample Files/`, so they are ready to select in the upload dialog. The original recruitment ZIP remains unchanged.

## Step-by-step demo

1. With Python 3.10 or newer, create and prepare a virtual environment: `python -m venv .venv`, then `.venv\Scripts\python -m pip install -r requirements.txt`.
2. Launch `Run Cadence PII Guard.bat` (or run `.venv\Scripts\python cadence_pii_guard.py`).
3. Open `http://127.0.0.1:8765` in a browser.
4. Upload one or more PDF, DOCX, PPTX, XLSX or text files. The per-file limit is 20 MB, which accommodates the supplied scanned policy PDF.
5. For a scanned PDF, install Tesseract (Windows installer instructions: [Tesseract installation guide](https://tesseract-ocr.github.io/tessdoc/Installation.html); Windows builds are linked there). Keep the installer's default `C:\Program Files\Tesseract-OCR` location, then close and reopen the demo. This build finds the Poppler PDF renderer bundled with Codex automatically. On other computers, install Poppler and put `pdftoppm.exe` on `PATH` or set `POPPLER_BIN` to its `bin` folder.
6. Select **Try local OCR**, then upload the scanned policy PDF and click **Extract, detect and redact**. If Tesseract is missing or any page has OCR confidence below 65%, the PDF is quarantined for manual review.
7. Review the dashboard totals, detection breakdown, and file queue, then inspect each eligible file's tagged output and source locations. The queue masks original filenames with sequential evidence labels.
8. Tick the reviewer approval box only after reviewing the output. The download stays disabled until approval, and quarantined files cannot be approved.
9. Download the redacted text. Downloads use a generic filename. This prototype has no model connector; any downstream use remains a separate reviewed action.

To run the local regression suite after installing requirements:

```powershell
.venv\Scripts\python -m unittest discover -s tests -v
```

OCR confidence is checked per page; the prototype quarantines a page below its 65% mean word-confidence threshold. The demo does not install Tesseract for you. After installing it, restart the demo so it can find the executable. If a page fails OCR or falls below the confidence threshold, do not approve or use the quarantined result; review the source page manually.

The app binds to localhost, holds uploads in memory, writes only temporary OCR page images when OCR runs, and makes no remote calls or LLM calls. It applies same-origin and per-process request-token checks, security response headers, upload count/request/file limits, PDF signature/page limits, Office ZIP size/ratio checks, OCR timeouts, and fail-closed handling for invalid encodings. These controls reduce risk; they do not turn the prototype into an authenticated organizational service.

## What it extracts and detects

- PDF page text, with optional per-page local OCR
- DOCX paragraphs and tables in document order
- DOCX headers and footers, including document-control fields
- PPTX slide text, shapes and table rows in slide order; table headers are carried with each data cell so labeled phones can be detected
- XLSX sheet and row context, plus plain text/CSV/Markdown
- PII patterns for emails, common Indian and North American phone formats, labeled phone/address/DOB fields, LinkedIn/GitHub profile links, employee IDs, government identifiers, bank account strings, and street addresses. Personal-name detection uses supplied sample names, explicit name labels, and a cautious contact-header heuristic.

Each redaction is tagged, such as `[REDACTED:EMAIL]`. The audit view records entity type and nearest page, slide, paragraph, table or sheet location without returning the matched value.

## Limits and control

This prototype does not use a trained general-purpose named-entity recognizer. Its name/header heuristic can miss names outside common formats or mistake a title for a name; phone/address patterns vary by country. It may miss PII in scanned PDF pages unless OCR is enabled, low-quality OCR, images, charts, floating text boxes, comments, tracked changes, formulas, unsupported layouts, or formats it does not support. Office files containing images/objects, comments/notes, hidden spreadsheet tabs, or formulas are held for review where detected. Always inspect the original and tagged output before approval. No near-100% coverage or 80% structure-retention result is claimed; those targets need measured evaluation against a labeled test set.

### Security boundaries and edge cases

- **Document text is untrusted data.** A document can contain prompt injection, forged instructions, or claims such as “I am an employee.” This app has no LLM, plugins, tools, or downstream actions, so document instructions cannot authorize actions here. If an LLM is added later, it must receive only approved, redacted content in an isolated workflow; model text must never grant tool permissions. Injection filters alone are not a security boundary.
- **Employee identity is not inferred from a résumé or email address.** A real organizational deployment needs the organization’s identity provider, MFA, server-side role/access checks, reviewer identity, and auditable authorization. The local checkbox is a human review step in the UI, not identity verification or a production approval record.
- **Uninspected content fails closed.** Unsupported formats, invalid text encoding, malformed or spoofed files, encrypted PDFs, extraction errors, oversized packages, and detected Office content outside the text extractor are quarantined. The supported formats still have layout-specific gaps; manual review is required.
- **Resource limits:** up to 10 files per request, 20 MB per file, 70 MB total request, 100 PDF pages, 50 OCR pages, 30 seconds per OCR subprocess, 5 minutes of OCR per PDF, and bounded Office package expansion/cell counts. These limits are prototype guardrails, not a substitute for isolated workers and infrastructure-level quotas.
- **No malware scanning or sanitization:** this prototype does not scan uploads with an endpoint security product, perform content disarm/reconstruction, preserve a sanitized source document, or provide immutable audit logs. It returns redacted text only.
- **Before organizational use:** require security review, SSO/MFA, least-privilege RBAC, managed isolated processing, malware scanning, approved temporary storage/deletion, encryption and key management, retention policy, audit logging, dependency patching, monitoring/rate limits, incident response, and independently labeled precision/recall testing by file type and PII class. Never deploy the local Python upload server directly to Vercel.

## Expected outcomes and schedule

The deck defines structure retention as correctly extracted labeled structure units with source locations divided by all labeled source units. It defines PII coverage as recall against an independently labeled set, reported by PII class and file format. Both outcome targets remain unverified until the evaluation is run and reviewed.

The three-week schedule is relative to the official release date because no calendar release date or team-member names were supplied. It assigns work by role and lists the final team package: deck, runnable demo and source, evaluation report, evidence inventory, and setup/run guide.

## Measure the outcome targets

`evaluate_cadence_pii.py` reports structure retention and span-level precision/recall by PII type against an independently reviewed gold manifest. Start with `Evaluation_Manifest_Template.json`; extract the three supporting files to a private evaluation folder, complete the gold structure locators and entity spans, and run:

```powershell
.venv\Scripts\python evaluate_cadence_pii.py Evaluation_Manifest_Template.json --output evaluation_report.json
```

Entity spans use offsets in the normalized extracted text (`start`, `end`) and a detection `type`, such as `EMAIL` or `PERSON_NAME`. Gold annotations should be reviewed by a second person. The template is intentionally empty: running it before annotation cannot establish coverage or retention. The report includes counts and scores only, not matched PII values.

### Reproduce the synthetic adversarial challenge

The `Adversarial Challenge` folder contains ten synthetic fixtures covering prompt injection, an employee impersonation claim, table-labeled contacts in CSV/DOCX/PPTX/XLSX, benign policy controls for false-positive checks, image-only contacts inside a DOCX, a partially unreadable scanned PDF, a fake PDF extension, and a malformed CSV row. All identities and values are fictitious. The manifest contains the expected PII values; keep it with the synthetic corpus and do not replace these fixtures with real resumes or customer records.

From this folder, run:

```powershell
python build_adversarial_challenge.py
python evaluate_cadence_pii.py "Adversarial Challenge\Gold_Manifest.json" --output "Adversarial Challenge\Evaluation_Report.json"
python -m unittest discover -s tests -v
```

The evaluator writes JSON and Markdown summaries. Scores include precision, recall, and F1 by file format and PII type, plus structure retention and quarantine expectations. Results apply only to this small curated test set; they do not establish general accuracy or production readiness. See `Adversarial Challenge\Evaluation_Report.md` for the current run.
#   P I I _ G u a r d  
 