# Sample evidence inventory

These counts describe extraction from the supplied supporting artifacts. Counts for the organization PPTX are pattern occurrences, so repeated directory details on multiple slides are counted more than once.

| Artifact | Structural inventory | PII observations |
|---|---|---|
| Cadence Group Risk Management Policy v6.0 (PDF) | 35 scanned pages; no usable embedded text layer | The rendered cover page visibly contains names, employee identifiers, email addresses, phone numbers and a postal address. The remaining pages require OCR; full-document counts are intentionally not reported. |
| Cadence Financial Group Organizational Pack (PPTX) | 9 slides; 3 native tables; 16 named role holders | 34 email-address occurrences and 34 phone-number occurrences are present across the deck's repeated directory content. |
| Cadence TPRM Training (DOCX) | 402 paragraphs; 16 tables; 221 table rows | Four named individuals appear in document-control/footer metadata; no email, phone, SSN or employee-ID pattern was found in extracted text. |

The training artifact and organization pack identify sample details as synthetic. Findings are useful for demonstrating extraction and redaction logic, not for claiming complete PII coverage. The case brief target of at least 80% structure retention and near-100% detection requires a labeled evaluation set and OCR quality scoring before it can be claimed.
