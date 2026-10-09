# Edge-Case Catalog Review for Cadence PII Guard

## Scope

This review compares the four supplied edge-case catalog screenshots with the current local prototype and its synthetic challenge suite. The screenshots are treated as proposed test cases and design expectations. They are not proof that the prototype already implements those controls.

## File identity and ingestion

| Catalog case | Current coverage | Assessment and useful next step |
|---|---|---|
| DOCX/PPTX renamed as PDF, or PDF/PNG renamed as DOCX | PDF signature and Office package structure are checked; mismatches should be quarantined. New unit tests exercise real DOCX-as-PDF and PDF-as-DOCX. | Covered for the DOCX/PDF mismatch cases. The app rejects mismatches instead of guessing and routing by content, which is safer for this prototype. It does not report a general, independently verified MIME classification. |
| Renamed EXE, ZIP, unknown extension | Unsupported suffixes are rejected; Office files are checked as ZIP packages. | Basic rejection is covered by the supported-format allowlist. It is not malware scanning. |
| Empty, truncated, corrupt, ZIP bomb | Empty input, malformed Office ZIP and an extreme compression ratio have regression tests; file and request sizes and archive expansion are bounded. | Good prototype safeguards. Add a truncated-but-signature-valid PDF fixture if this becomes a release gate. |
| Password-protected or encrypted PDF/DOCX | Encrypted PDFs are explicitly held; encrypted DOCX packages fail Office inspection and are held. | Fail closed. No decrypt workflow is implemented. |
| Old `.doc`, `.ppt`, `.xls` formats | Not in the supported format list. | Rejected as unsupported. Do not silently convert these in the demo. |
| Polyglot file, valid as two formats | No polyglot detector or anti-malware engine. Basic signature/package checks are not enough to establish safety. | Explicitly untested and not production safe. Reject ambiguity; use isolated parsing, malware scanning/sandboxing, and content disarm/reconstruction in a real service. |
| Duplicate file uploads / duplicate names | No stable document ID, content hash, or deduplication record. | Low priority for a single-user demo. For auditable workflows, use a generated document ID; avoid exposing a raw file hash as a user identifier. |
| Uppercase or double extension | Extension is normalized to lowercase and the final suffix is selected; content/package checks still apply to the selected parser. | Basic handling exists. A mismatch audit event and tests for more extension combinations would improve the release test set. |

## Hidden content that extraction may miss

| Catalog case | Current coverage | Assessment and useful next step |
|---|---|---|
| Images inside DOCX/PPTX/PDF | Office media/embedded-object packages are flagged for review; the new DOCX fixture puts synthetic email/phone text only in an image and verifies quarantine. No embedded-image OCR is performed. | Safe withholding, but PII detection is incomplete for that document. The DOCX recall in the report includes these misses; they are not released from quarantine. PDF page OCR works only when the OCR option is selected. |
| Scanned PDF with no text | Local OCR is supported when selected. A low-confidence page causes the whole PDF to be quarantined. | Covered by the partial-scan fixture. |
| Text layer is present but wrong/garbled | The app uses a text layer with at least 20 characters and does not compare it to OCR. | Gap. A useful future test should compare extracted text with OCR on synthetic corrupt-text PDFs, then quarantine disagreement rather than silently trusting one source. |
| Rotated, skewed, dark, low-resolution scans | PDF pages are rendered at a bounded size; there is no deskew/rotation correction or multi-pass OCR retry. | Partial coverage only. Add fixtures for rotated and degraded pages before claiming scan robustness. |
| Handwriting, signatures, stamps | Only OCR page confidence is checked; there is no handwriting-specific detector or per-region review flag. | Gap. Treat low confidence as unreadable and quarantine; never claim handwriting coverage. |
| Hidden slides, notes, comments, tracked changes | Office package inspection flags notes/comments and related parts; PPTX visible slide shapes and tables are extracted. | Partial. Hidden-slide state and tracked-change behavior need dedicated fixtures. Do not assume every hidden part is inspected. |
| Headers, footers, footnotes, text boxes, SmartArt, groups | DOCX headers/footers and body tables/paragraphs are extracted; PPTX text shapes and tables are extracted. Footnotes/endnotes trigger review. | Partial. Grouped shapes, SmartArt, footnotes, and complex reading order need explicit tests; unsupported content should remain quarantined. |
| Metadata (author, dates, custom properties, EXIF) | Not extracted or reported. | Gap. Metadata can hold personal data; either inspect it or state that metadata is out of scope and quarantine files where that matters. |
| Hidden text, hyperlink/mailto targets | Visible text is parsed; hyperlink targets and hidden formatting are not systematically traversed. | Gap. Add a DOCX/PPTX fixture where the displayed text differs from a `mailto:` target, and inspect both or quarantine. |
| Embedded objects, charts, QR/barcodes | Embedded objects/media can trigger Office quarantine; there is no recursive attachment parsing, chart-data extraction, or QR/barcode decoder. | Quarantine is the safe current behavior where the package check detects the object. Add explicit chart/QR tests; do not claim these values are scanned. |

## Detection and false positives

| Catalog case | Current coverage | Assessment and useful next step |
|---|---|---|
| Policy IDs, dates, amounts, and versions mistaken for PII | Added a benign policy-text control with synthetic policy codes, a date, amounts, versions, and invalid card-like digits. The current detector passes this control after tightening unlabelled phone matching. | Useful regression control. It is a small sample and does not prove low false-positive rates generally. |
| Unlabeled PII in prose | Most detection uses regular expressions, labels, and a small supplied name list/header heuristic; there is no general NER model. | Important known limitation. State the supported patterns and country assumptions; do not claim arbitrary names or unlabeled PII are detected. |
| Same name for different people / name variants across files | The app redacts spans independently and does not link identities across files. | This avoids unsafe identity merging. Stable person tokens or cross-file resolution are not implemented and should not be added without a clear need, key management, and reviewer controls. |
| Common words or company names mistaken for names | Name detection includes a cautious first-page/header heuristic and supplied names, but no organization/name disambiguation model. | Possible false positives remain; the scanned-PDF challenge shows one name false positive. Keep it visible in precision results. |
| PII split across lines/cells/pages | Table extractors carry headers into row text, and DOCX preserves body/table order. | Labeled table values are tested in CSV/DOCX/PPTX/XLSX. Arbitrary split identifiers and cross-page reconstruction are not supported. |
| Obfuscated PII / Unicode lookalikes | Strict text decoding and some Unicode-aware matching are used, but there is no comprehensive NFKC normalization before detection, confusable detection, or `[at]`/`dot` email normalization. | Gap. Add Unicode/full-width digits, combining marks, and obfuscated-email fixtures before making cross-language claims. Do not normalize suspicious content into an automatic release. |
| OCR errors in identifiers | Page-level average OCR confidence is used; there is no fuzzy checksum validation or per-entity OCR confidence. | Gap. Current behavior is quarantine on low page confidence, not correction of uncertain identifiers. |
| Multiple overlapping PII types | Overlapping spans are merged; different labels may collapse to a generic `PII` tag. | Improve priority/overlap handling and add a test before reporting class-specific precision on heavily overlapping strings. |

## Redaction, review, and output safety

| Catalog case | Current coverage | Assessment and useful next step |
|---|---|---|
| Mapping vault/logs expose raw PII | There is no mapping vault or persistent audit log; redaction is one-way `[REDACTED:TYPE]` text. | This is a simpler privacy boundary for the demo. If reversibility is later required, keep a separate encrypted, access-controlled vault and never log raw PII. |
| Stable tokens across files | Not implemented. | Do not use plain hashes for email/name tokens. If cross-file linking is required, design keyed, scoped pseudonyms with rotation and access controls as a separate feature. |
| Redaction breaks table structure / 80% retention goal | Extracted text includes source markers; the challenge measures 12 labeled page/row/sheet locator markers. | The 12/12 locator result is only a narrow proxy. It does not measure formatting or context retention and does not validate the 80% outcome. Add independently labeled paragraphs/cells and compare the resulting redacted structure before citing that target. |
| Low-confidence findings / human review | OCR page confidence below 65% quarantines the file; there is no per-entity confidence or review queue. | Fail closed at page level. A production review queue and reviewer identity are absent. |
| Detector/OCR crash mid-document | OCR failures are recorded and the file is blocked; PDF page and time caps are applied. The app has no LLM, so there is no downstream model path. | Useful fail-closed behavior. Add a forced mid-document failure test if this is a release gate. |
| Very large documents / progress UI | File/request limits, PDF page/OCR limits, timeouts, Office expansion and spreadsheet cell limits are present. | Bounded, but no streaming or progress UI; large DOCX/OCR workloads may be rejected or take time. Do not claim a progress interface exists. |

## Recommended case-study additions

1. Keep the new benign-text false-positive control and embedded-image quarantine case in the demo package.
2. Add direct regression tests for cross-extension real DOCX/PDF mismatches, empty inputs, and malformed/truncated PDFs. The first two mismatch cases and empty-file case are now covered by the regression suite.
3. Add tests for garbled PDF text layers, rotated scans, hidden slide/notes, hyperlink targets, metadata, Unicode/obfuscation, and overlap resolution only if the team intends to claim those behaviors. Otherwise explicitly state they are unsupported or quarantined.
4. Keep the security boundary clear: extension/signature checks catch simple renaming, but they are not malware scanning or polyglot detection. A public deployment needs isolated parsing, malware scanning, and a reviewed upload/storage lifecycle.
5. Present results with the manifest and false negatives included. In particular, the image-only DOCX is quarantined because its image text is not OCRed; the prototype should not be described as having detected those image contacts.

The current challenge remains synthetic and small. Its scores are regression evidence for these fixtures, not a general accuracy or organizational-security certification.
