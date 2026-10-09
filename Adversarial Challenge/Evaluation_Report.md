# Synthetic Adversarial Evaluation

This report scores the fixtures listed in `Gold_Manifest.json`. All names, addresses, identifiers, and contact details are synthetic. Results are specific to this small, pattern-based prototype test set and do not estimate performance on organizational data.

## File type summary

| Format | Files | Held for review | Locator retention | Micro precision | Micro recall | Micro F1 |
|---|---:|---:|---:|---:|---:|---:|
| CSV | 2 | 1 | 100.0% | 100.0% | 100.0% | 100.0% |
| DOCX | 2 | 1 | 100.0% | 100.0% | 80.0% | 88.9% |
| PDF | 2 | 2 | 100.0% | 88.9% | 100.0% | 94.1% |
| PPTX | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| TXT | 2 | 0 | — | 100.0% | 100.0% | 100.0% |
| XLSX | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |

## PII recall by format

| PII type | CSV | DOCX | PDF | PPTX | TXT | XLSX | Overall precision | Overall recall | Overall F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ADDRESS | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| BANK_ACCOUNT | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| DOB | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| EMAIL | 100.0% | 50.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 87.5% | 93.3% |
| EMPLOYEE_ID | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| GOVERNMENT_ID | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| PAYMENT_CARD | — | — | — | — | — | — | — | — | — |
| PERSON_NAME | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 85.7% | 100.0% | 92.3% |
| PHONE | 100.0% | 50.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 85.7% | 92.3% |
| US_SSN | — | — | — | — | — | — | — | — | — |

## Adversarial checks

| Check | Passed | Failed |
|---|---:|---:|
| prompt injection inert | 1 | 0 |
| impersonation claim no authority | 1 | 0 |
| table labeled contact details | 5 | 0 |
| non pii false positive controls | 1 | 0 |
| embedded media quarantined | 1 | 0 |
| partial ocr page quarantine | 1 | 0 |
| spoofed extension quarantined | 1 | 0 |
| malformed row quarantined | 1 | 0 |

Expected quarantines: 4/4; missed: 0; unexpected: 0.

## Interpretation

- The scanned PDF retained the labeled page structure and detected all labeled synthetic PII values on the readable page. The second unreadable page was quarantined, so the PDF as a whole remained held for review.
- One scanned-PDF person-name false positive came from the conservative first-page résumé name heuristic. This is recorded in precision instead of being hidden.
- The spoofed `.pdf` extension and malformed CSV were rejected and quarantined. The injection text and the claim of employee authority remained untrusted document content; this prototype makes no LLM calls and has no employee-authentication path.
- The DOCX containing contact details only inside an image was quarantined. Its embedded image text was not OCRed, so the PII recall misses in that file are surfaced in the DOCX row; quarantine keeps this incomplete extraction from release.
- Locator retention is the share of 12 explicitly labeled page/row/sheet markers present in extracted text. It does not score formatting or preceding/succeeding content preservation and does not verify the 80% structure-retention target. Small sample size and curated patterns mean these scores must not be represented as production accuracy.

Rebuild fixtures and report with `python build_adversarial_challenge.py` followed by `python evaluate_cadence_pii.py "Adversarial Challenge/Gold_Manifest.json" --output "Adversarial Challenge/Evaluation_Report.json"`. The evaluator writes this Markdown summary alongside the JSON output.
