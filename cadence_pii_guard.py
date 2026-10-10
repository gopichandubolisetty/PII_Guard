from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.util
import ipaddress
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import secrets
import zipfile
import time
from collections import Counter
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_REQUEST_BYTES = 70 * 1024 * 1024
MAX_FILES_PER_REQUEST = 10
MAX_ARCHIVE_ENTRIES = 10_000
MAX_ARCHIVE_UNPACKED_BYTES = 50 * 1024 * 1024
MAX_ARCHIVE_RATIO = 100
MAX_PDF_PAGES = 100
MAX_OCR_PAGES = 50
MAX_OCR_SECONDS = 300
MIN_OCR_CONFIDENCE = 0.65
CSRF_TOKEN = secrets.token_urlsafe(32)

# Directory seed terms are from the supplied Cadence training artifacts, which label
# the organization data as synthetic. Replace this list with an approved data source
# for another environment; never treat it as complete named-entity recognition.
PERSON_SEEDS = [
    "Marguerite Vossberg", "Desmond Achterberg", "Priyanka Raghunathan",
    "Tobias Lindqvist", "Adaeze Okonkwo-Bell", "Rosalind Featherstone",
    "Bartholomew Nkemdirim", "Yasmin El-Katib", "Emiliano Bertucci",
    "Colette Marchetti", "Hyun-Woo Park", "Nikolai Brandvold", "Imani Oduya",
    "Gerhardt Wenzel", "Solveig Aarnio", "Rafael Quintanilla",
    "Miriam T. Achebe", "Anthony P. Brightwell", "Delphine R. Okonjo",
    "Daniela Figueroa", "Siddharth Gaikwad", "Srinivas Teppa", "Nikhil Karkera",
]

CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def luhn_valid(value: str) -> bool:
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


PATTERNS = [
    ("EMAIL", re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w-])", re.I)),
    # Common Indian mobile formats (with or without +91 and separators).
    ("PHONE", re.compile(r"(?<!\d)(?:\+?91[ .-]?)?[6-9]\d{4}[ .-]\d{5}(?!\d)")),
    # Common North American format.
    ("PHONE", re.compile(r"(?<!\d)(?:\+?1[ .-]?)?(?:\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}|\d{3}[ .-]\d{3}[ .-]\d{4})(?!\d)")),
    ("US_SSN", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    ("EMPLOYEE_ID", re.compile(r"(?i)\bEMP[-\s#]*\d{4,10}\b")),
    ("DOB", re.compile(r"(?i)(?:DOB|date of birth|birth date)\s*[:=-]?\s*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})")),
    ("GOVERNMENT_ID", re.compile(r"(?i)(?:passport|national ID|tax ID|taxpayer ID|SSN|social security number|driver'?s license)\s*(?:(?:no\.?|number|#)\s*[:=]?|[:=])\s*[A-Z0-9-]{5,20}")),
    # Require an explicit account-number label so ordinary prose such as
    # "account becomes linked" is not treated as a secret.
    ("BANK_ACCOUNT", re.compile(r"(?i)\b(?:account|acct)\s*(?:(?:no\.?|number|#)\s*[:=]?|:)\s*[A-Z0-9-]{6,24}\b")),
    ("ADDRESS", re.compile(r"\b\d{1,6}\s+[A-Z][A-Za-z0-9.' -]{1,45}\s(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Way)\b[^\n|]{0,60}", re.I)),
    ("PROFILE_URL", re.compile(r"(?i)\bhttps?://(?:www\.)?(?:linkedin\.com/in|github\.com)/[A-Za-z0-9_./%-]+")),
]

# Resume-specific, label-aware patterns. The named value group deliberately
# leaves labels such as "Phone:" and "Address:" visible in the redacted copy.
CONTEXT_PATTERNS = [
    ("PERSON_NAME", re.compile(
        r"(?im)\b(?:full\s+name|candidate\s+name|candidate|name)\s*[:=|\-]\s*"
        r"(?P<value>[A-Z][\w'’.-]{1,30}(?:[ \t]+(?:[A-Z][\w'’.-]{1,30}|[A-Z]\.)){1,3})"
    )),
    ("PHONE", re.compile(
        r"(?im)\b(?:phone|mobile|cell|telephone|tel|contact|m)\s*(?:number|no\.?|#)?\s*[:=\-]?\s*"
        r"(?P<value>\+?\d[\d ()./\-]{5,}\d(?:\s*(?:ext\.?|x)\s*\d{1,6})?)"
    )),
    ("ADDRESS", re.compile(
        r"(?im)\b(?:home\s+address|mailing\s+address|address|residing\s+at)\s*[:=\-]\s*"
        r"(?P<value>[^\n|]{8,120})"
    )),
    ("DOB", re.compile(
        r"(?im)\b(?:dob|date\s+of\s+birth|birth\s+date)\s*[:=\-]\s*"
        r"(?P<value>(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}|"
        r"[A-Z][a-z]+\s+\d{1,2},?\s+\d{4}))"
    )),
]

RESUME_HEADER_NAME = re.compile(
    r"^(?P<value>(?:[A-Z][A-Za-z'’.-]{1,30}|[A-Z]{2,}(?:[-'][A-Z]{2,})?)"
    r"(?:\s+(?:[A-Z][A-Za-z'’.-]{1,30}|[A-Z]{2,}(?:[-'][A-Z]{2,})?)){1,3})$"
)
HEADER_NAME_EXCLUSIONS = {
    "resume", "curriculum vitae", "professional summary", "software engineer",
    "data scientist", "web developer", "project manager", "product manager",
    "business analyst", "data analyst", "full stack developer", "student resume",
}


def find_command(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    candidates = []
    if name == "pdftoppm":
        poppler_bin = os.environ.get("POPPLER_BIN")
        if poppler_bin:
            candidates.append(Path(poppler_bin) / "pdftoppm.exe")
        # Codex desktop bundles Poppler in its managed runtime. This fallback
        # lets the demo use that local executable without a separate Poppler install.
        candidates.append(
            Path.home()
            / ".cache"
            / "codex-runtimes"
            / "codex-primary-runtime"
            / "dependencies"
            / "native"
            / "poppler"
            / "Library"
            / "bin"
            / "pdftoppm.exe"
        )
        candidates.extend([
            Path(r"C:\Program Files\poppler\Library\bin\pdftoppm.exe"),
            Path(r"C:\Program Files\Poppler\bin\pdftoppm.exe"),
        ])
        try:
            candidates.extend(Path(r"C:\Program Files").glob("Release-*/poppler-*/Library/bin/pdftoppm.exe"))
            candidates.extend(Path(r"C:\Program Files").glob("poppler-*/Library/bin/pdftoppm.exe"))
            candidates.extend(Path(r"C:\Program Files").glob("poppler-*/bin/pdftoppm.exe"))
        except Exception:
            pass
    elif name == "tesseract":
        candidates.extend([
            Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe"),
            Path(r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"),
        ])
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def ocr_page(pdf_bytes: bytes, page_no: int) -> tuple[str, float]:
    pdftoppm = find_command("pdftoppm")
    tesseract = find_command("tesseract")
    if not pdftoppm or not tesseract:
        raise RuntimeError("Local OCR requires both Poppler (pdftoppm) and Tesseract.")
    with tempfile.TemporaryDirectory(prefix="cadence_ocr_") as work:
        root = Path(work)
        pdf = root / "source.pdf"
        prefix = root / "page"
        pdf.write_bytes(pdf_bytes)
        subprocess.run([pdftoppm, "-f", str(page_no), "-l", str(page_no), "-scale-to", "2500", "-png", "-singlefile", str(pdf), str(prefix)], check=True, capture_output=True, timeout=30)
        image = Path(str(prefix) + ".png")
        result = subprocess.run([tesseract, str(image), "stdout", "--psm", "6", "tsv"], check=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        rows = csv.DictReader(io.StringIO(result.stdout), delimiter="\t")
        lines: dict[tuple[str, str, str], list[str]] = {}
        confidences = []
        for row in rows:
            word = (row.get("text") or "").strip()
            if not word:
                continue
            try:
                confidence = float(row.get("conf", "-1"))
            except ValueError:
                continue
            if confidence < 0:
                continue
            key = (row.get("block_num", ""), row.get("par_num", ""), row.get("line_num", ""))
            lines.setdefault(key, []).append(word)
            confidences.append(confidence)
        if not confidences:
            return "", 0.0
        return "\n".join(" ".join(words) for words in lines.values()), sum(confidences) / len(confidences) / 100.0


def extract_pdf(data: bytes, use_ocr: bool) -> tuple[str, list[str]]:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        return "", ["Encrypted PDF is not processed; decrypt through an approved workflow and review manually."]
    if len(reader.pages) > MAX_PDF_PAGES:
        return "", [f"PDF exceeds the {MAX_PDF_PAGES}-page processing limit; manual review required."]
    chunks, failures = [], []
    ocr_started = time.perf_counter()
    for page_no, page in enumerate(reader.pages, 1):
        text = (page.extract_text() or "").strip()
        if len(text) < 20 and use_ocr:
            if time.perf_counter() - ocr_started >= MAX_OCR_SECONDS:
                failures.append(f"Page {page_no}: total OCR time limit reached; manual review required.")
                chunks.append(f"[PAGE {page_no}]\n[NO REVIEWABLE TEXT — QUARANTINED]")
                continue
            if page_no > MAX_OCR_PAGES:
                failures.append(f"Page {page_no}: OCR page limit exceeded; manual review required.")
                chunks.append(f"[PAGE {page_no}]\n[NO REVIEWABLE TEXT — QUARANTINED]")
                continue
            try:
                text, confidence = ocr_page(data, page_no)
                text = text.strip()
                if confidence < MIN_OCR_CONFIDENCE:
                    failures.append(f"Page {page_no}: OCR confidence {confidence:.0%} is below the {MIN_OCR_CONFIDENCE:.0%} release threshold.")
            except Exception as exc:
                failures.append(f"Page {page_no}: OCR could not run ({type(exc).__name__}); manual review required.")
        elif len(text) < 20:
            failures.append(f"Page {page_no}: no usable text layer; OCR was not selected.")
        if len(text) < 20:
            failures.append(f"Page {page_no}: less than 20 characters extracted; page requires manual review.")
            text = "[NO REVIEWABLE TEXT — QUARANTINED]"
        chunks.append(f"[PAGE {page_no}]\n{text}")
    return "\n\n".join(chunks), failures


def extract_docx(data: bytes) -> str:
    from docx import Document
    from docx.text.paragraph import Paragraph
    from docx.table import Table
    from docx.oxml.text.paragraph import CT_P
    from docx.oxml.table import CT_Tbl
    doc = Document(io.BytesIO(data))
    chunks = []
    paragraph_no = 0
    table_no = 0
    # Walk the Word body in document order, preserving paragraph and table locations.
    for element in doc.element.body.iterchildren():
        if isinstance(element, CT_P):
            text = Paragraph(element, doc).text.strip()
            if text:
                paragraph_no += 1
                chunks.append(f"[PARAGRAPH {paragraph_no}] {text}")
        elif isinstance(element, CT_Tbl):
            table_no += 1
            table = Table(element, doc)
            chunks.append(f"[TABLE {table_no}]")
            headers = [cell.text.strip() for cell in table.rows[0].cells] if table.rows else []
            for row_no, row in enumerate(table.rows, 1):
                values = [cell.text.strip() for cell in row.cells]
                if row_no > 1 and len(headers) == len(values):
                    row_text = " | ".join(f"{headers[i]}: {value}" for i, value in enumerate(values) if value)
                else:
                    row_text = " | ".join(values)
                chunks.append(f"[TABLE {table_no} ROW {row_no}] {row_text}")
    # Header/footer parts may hold document-control identities that body-only
    # extraction misses. Process each unique linked part once.
    seen_parts: set[str] = set()
    for section_no, section in enumerate(doc.sections, 1):
        stories = [
            ("HEADER", section.header),
            ("FIRST_PAGE_HEADER", section.first_page_header),
            ("EVEN_PAGE_HEADER", section.even_page_header),
            ("FOOTER", section.footer),
            ("FIRST_PAGE_FOOTER", section.first_page_footer),
            ("EVEN_PAGE_FOOTER", section.even_page_footer),
        ]
        for story_name, story in stories:
            part_name = str(story.part.partname)
            if part_name in seen_parts:
                continue
            seen_parts.add(part_name)
            story_label = f"{story_name} SECTION {section_no}"
            for para_no, paragraph in enumerate(story.paragraphs, 1):
                text = paragraph.text.strip()
                if text:
                    chunks.append(f"[{story_label} PARAGRAPH {para_no}] {text}")
            for header_table_no, table in enumerate(story.tables, 1):
                chunks.append(f"[{story_label} TABLE {header_table_no}]")
                headers = [cell.text.strip() for cell in table.rows[0].cells] if table.rows else []
                for row_no, row in enumerate(table.rows, 1):
                    values = [cell.text.strip() for cell in row.cells]
                    if row_no > 1 and len(headers) == len(values):
                        row_text = " | ".join(f"{headers[i]}: {value}" for i, value in enumerate(values) if value)
                    else:
                        row_text = " | ".join(values)
                    chunks.append(f"[{story_label} TABLE {header_table_no} ROW {row_no}] {row_text}")
    return "\n".join(chunks)

def extract_pptx(data: bytes) -> str:
    from pptx import Presentation
    deck = Presentation(io.BytesIO(data))
    chunks = []
    for slide_no, slide in enumerate(deck.slides, 1):
        chunks.append(f"[SLIDE {slide_no}]")
        for shape_no, shape in enumerate(slide.shapes, 1):
            if getattr(shape, "has_table", False):
                table = shape.table
                headers = [cell.text.strip() for cell in table.rows[0].cells] if table.rows else []
                for row_no, row in enumerate(table.rows, 1):
                    values = [cell.text.strip() for cell in row.cells]
                    if row_no > 1 and len(headers) == len(values):
                        row_text = " | ".join(f"{headers[i]}: {value}" for i, value in enumerate(values) if value)
                    else:
                        row_text = " | ".join(values)
                    chunks.append(f"[SLIDE {slide_no} TABLE ROW {row_no}] {row_text}")
            elif getattr(shape, "text", "").strip():
                chunks.append(f"[SLIDE {slide_no} SHAPE {shape_no}] {shape.text.strip()}")
    return "\n".join(chunks)


def extract_xlsx(data: bytes) -> str:
    import openpyxl
    book = openpyxl.load_workbook(io.BytesIO(data), data_only=True, read_only=True)
    chunks = []
    for sheet in book.worksheets:
        chunks.append(f"[SHEET {sheet.title}]")
        rows = sheet.iter_rows(values_only=True)
        first = next(rows, ())
        headers = [str(value).strip() if value is not None else "" for value in first]
        if any(headers):
            chunks.append(f"[SHEET {sheet.title} ROW 1] " + " | ".join(v for v in headers if v))
        for row_no, row in enumerate(rows, 2):
            vals = [f"{headers[i]}: {str(value).strip()}" if i < len(headers) and headers[i] else str(value).strip()
                    for i, value in enumerate(row) if value is not None and str(value).strip()]
            if vals:
                chunks.append(f"[SHEET {sheet.title} ROW {row_no}] " + " | ".join(vals))
    return "\n".join(chunks)


def extract_csv(data: bytes) -> str:
    try:
        content = data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("CSV is not valid UTF-8.") from exc
    csv.field_size_limit(1024 * 1024)
    reader = csv.reader(io.StringIO(content, newline=""))
    headers = next(reader, [])
    if not headers or len(headers) > 1000:
        raise ValueError("CSV has no usable header or too many columns.")
    chunks = []
    for row_no, values in enumerate(reader, 2):
        if row_no > 100_001:
            raise ValueError("CSV exceeds the 100,000-row processing limit.")
        if len(values) > len(headers):
            raise ValueError(f"CSV row {row_no} contains more cells than its header; extraction quarantined.")
        fields = []
        for index, value in enumerate(values):
            header = headers[index].strip()
            value = value.strip()
            if header and value:
                fields.append(f"{header}: {value}")
        if fields:
            chunks.append(f"[CSV ROW {row_no}] " + " | ".join(fields))
    return "\n".join(chunks)


def extract_document(filename: str, data: bytes, use_ocr: bool) -> tuple[str, list[str]]:
    suffix = Path(filename).suffix.lower()
    if not data:
        return "", ["Empty file; no extraction attempted."]
    if suffix == ".pdf":
        if not data.startswith(b"%PDF-"):
            return "", ["File signature does not match PDF extension; quarantined."]
        return extract_pdf(data, use_ocr)
    if suffix in {".docx", ".pptx", ".xlsx"}:
        valid, notices = inspect_office_package(data, suffix)
        if not valid:
            return "", notices
    else:
        notices = []
    if suffix == ".docx":
        return extract_docx(data), notices
    if suffix == ".pptx":
        return extract_pptx(data), notices
    if suffix == ".xlsx":
        return extract_xlsx(data), notices
    if suffix == ".csv":
        return extract_csv(data), []
    if suffix in {".txt", ".md", ".log"}:
        try:
            text = data.decode("utf-8-sig", errors="strict")
            if "\x00" in text:
                return "", ["Binary control bytes found in text upload; quarantined."]
            return text, []
        except UnicodeDecodeError:
            return "", ["Text is not valid UTF-8; no lossy decoding was attempted."]
    return "", [f"Unsupported format: {suffix or 'no extension'}."]


def inspect_office_package(data: bytes, suffix: str) -> tuple[bool, list[str]]:
    """Reject malformed/oversized Office containers and quarantine content skipped by parsers."""
    expected = {".docx": "word/document.xml", ".pptx": "ppt/presentation.xml", ".xlsx": "xl/workbook.xml"}[suffix]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            names = [item.filename.casefold() for item in entries]
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                return False, ["Office package has too many internal entries; quarantined."]
            if expected.casefold() not in names:
                return False, ["Office package is missing its required document part; quarantined."]
            total_size = sum(item.file_size for item in entries)
            compressed = max(1, sum(item.compress_size for item in entries))
            if total_size > MAX_ARCHIVE_UNPACKED_BYTES or total_size / compressed > MAX_ARCHIVE_RATIO:
                return False, ["Office package exceeds decompression safety limits; quarantined."]
            if any(Path(item.filename.replace("\\", "/")).is_absolute() or ".." in Path(item.filename.replace("\\", "/")).parts for item in entries):
                return False, ["Office package contains unsafe member paths; quarantined."]
    except (zipfile.BadZipFile, OSError, ValueError):
        return False, ["Office file is malformed or does not match its extension; quarantined."]
    review_flags = []
    if any("/media/" in f"/{name}" or "/embeddings/" in f"/{name}" for name in names):
        review_flags.append("Embedded images or objects are not fully inspected; manual review required.")
    if any(any(token in name for token in ("comments", "footnotes", "endnotes", "notes/", "vbaproject")) for name in names):
        review_flags.append("Comments, notes, footnotes, endnotes, or macro-related content may not be fully inspected; manual review required.")
    if suffix == ".xlsx":
        try:
            import openpyxl
            workbook = openpyxl.load_workbook(io.BytesIO(data), data_only=False, read_only=True)
            declared_cells = sum((sheet.max_row or 0) * (sheet.max_column or 0) for sheet in workbook.worksheets)
            if declared_cells > 500_000:
                return False, ["Spreadsheet declares more than 500,000 cells; quarantined for bounded processing."]
            if any(sheet.sheet_state != "visible" for sheet in workbook.worksheets):
                review_flags.append("Hidden spreadsheet tabs require manual review.")
            if any(cell.data_type == "f" for sheet in workbook.worksheets for row in sheet.iter_rows() for cell in row):
                review_flags.append("Formula cells may have missing or stale cached results; manual review required.")
        except Exception:
            return False, ["Spreadsheet structure could not be safely inspected; quarantined."]
    return True, review_flags


def locator_for(text: str, offset: int) -> str:
    prefix = text[:offset]
    tokens = list(re.finditer(r"\[(PAGE|SLIDE|PARAGRAPH|CSV[^\]]*|TABLE[^\]]*|SHEET[^\]]*|HEADER[^\]]*|FOOTER[^\]]*|FIRST_PAGE_HEADER[^\]]*|FIRST_PAGE_FOOTER[^\]]*|EVEN_PAGE_HEADER[^\]]*|EVEN_PAGE_FOOTER[^\]]*)[^\]]*\]", prefix, re.I))
    return tokens[-1].group(0)[1:-1] if tokens else "document body"


def redact_text(text: str) -> tuple[str, Counter, list[dict]]:
    spans: list[tuple[int, int, str]] = []
    for match in CARD_CANDIDATE.finditer(text):
        digits = "".join(ch for ch in match.group(0) if ch.isdigit())
        if luhn_valid(digits) and len(set(digits)) > 1:
            spans.append((match.start(), match.end(), "PAYMENT_CARD"))
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            spans.append((match.start(), match.end(), label))
    for label, pattern in CONTEXT_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span("value")
            value = text[start:end].strip()
            leading = len(text[start:end]) - len(text[start:end].lstrip())
            trailing = len(text[start:end]) - len(text[start:end].rstrip())
            start += leading
            end -= trailing
            if label == "PHONE":
                digits = re.sub(r"\D", "", value)
                # Do not treat short extensions or incidental numbers as phones.
                if not 7 <= len(digits) <= 15:
                    continue
            if value:
                spans.append((start, end, label))

    # Many CVs put an unlabeled full name on the first line. Only use this
    # conservative header guess when a phone/email is also present near the top.
    top = text[:1800]
    if re.search(r"(?i)@|(?:\+?\d[\d ()./-]{7,}\d)", top):
        excluded = {phrase.casefold() for phrase in HEADER_NAME_EXCLUSIONS}
        for line_match in list(re.finditer(r"(?m)^\s*(.{2,100}?)\s*$", top))[:8]:
            raw_line = line_match.group(1)
            leading_space = len(raw_line) - len(raw_line.lstrip())
            line = raw_line.strip()
            marker = re.match(r"^\[(?:PAGE|PARAGRAPH|TABLE[^\]]*)[^\]]*\]\s*", line, re.I)
            content_start = marker.end() if marker else 0
            candidate_text = line[content_start:]
            candidate = RESUME_HEADER_NAME.fullmatch(candidate_text)
            if candidate and candidate_text.casefold() not in excluded:
                start = line_match.start(1) + leading_space + content_start + candidate.start("value")
                end = line_match.start(1) + leading_space + content_start + candidate.end("value")
                spans.append((start, end, "PERSON_NAME"))
                break
    for name in PERSON_SEEDS:
        for match in re.finditer(re.escape(name), text, re.I):
            spans.append((match.start(), match.end(), "PERSON_NAME"))

    spans.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    merged: list[tuple[int, int, str]] = []
    for start, end, label in spans:
        if merged and start < merged[-1][1]:
            old_start, old_end, old_label = merged[-1]
            merged[-1] = (old_start, max(old_end, end), old_label if old_label == label else "PII")
        else:
            merged.append((start, end, label))
    counts: Counter = Counter()
    locs: list[dict] = []
    output, pos = [], 0
    for start, end, label in merged:
        output.append(text[pos:start])
        output.append(f"[REDACTED:{label}]")
        counts[label] += 1
        locs.append({"type": label, "location": locator_for(text, start), "start": start, "end": end})
        pos = end
    output.append(text[pos:])
    return "".join(output), counts, locs


PAGE = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cadence PII Guard</title><style>
:root{font:16px/1.5 Segoe UI,Arial,sans-serif;color:#132f4c;background:#f4f7fa}body{margin:0}.wrap{max-width:1100px;margin:34px auto;padding:0 20px}.hero{background:#102c49;color:#fff;padding:30px 34px;border-radius:12px;border-bottom:6px solid #d6aa4b}.hero h1{margin:0 0 6px;font-size:30px}.hero p{margin:0;color:#dbe6ef}.card{background:white;border:1px solid #d8e2ea;border-radius:12px;padding:24px;margin-top:18px}.guard{background:#fff7e7;border-left:4px solid #d6aa4b;padding:12px 16px}.primary{background:#146d78;color:white;border:0;border-radius:7px;padding:10px 18px;font:inherit;cursor:pointer}.pill{display:inline-block;background:#e3f1ef;border-radius:20px;padding:4px 10px;margin:3px 5px 3px 0}.bad{color:#963a31;font-weight:700}.good{color:#27623e;font-weight:700}textarea{width:100%;height:300px;box-sizing:border-box;border:1px solid #d8e2ea;border-radius:8px;padding:14px;background:#f7f9fb;font:13px/1.5 Consolas,monospace;white-space:pre;overflow:auto}button:disabled{opacity:.45;cursor:not-allowed}small{color:#586e80}</style></head><body><main class="wrap"><header class="hero"><h1>Cadence PII Guard</h1><p>Local evidence extraction, tagged redaction and reviewer gate</p></header><section class="card"><h2>1. Upload evidence files</h2><p>PDF, DOCX, PPTX, XLSX, TXT, CSV and Markdown are supported. Maximum 20 MB per file.</p><div class="guard"><b>Fail-closed rule:</b> unreadable pages, unsupported files and extraction failures stay quarantined. This prototype makes no LLM calls.</div><form id="form"><p><input type="file" name="files" multiple required accept=".pdf,.docx,.pptx,.xlsx,.txt,.csv,.md,.log"></p><label><input type="checkbox" name="ocr" value="yes"> 2. Try local OCR for scanned PDF pages (requires Tesseract + Poppler; pages below 65% confidence are quarantined)</label><p><button class="primary">Extract, detect and redact</button></p></form><div id="status"></div></section><div id="results"></div></main><script>
const form=document.getElementById('form');form.addEventListener('submit',async e=>{e.preventDefault();const status=document.getElementById('status'),results=document.getElementById('results');status.textContent='Processing files locally…';results.replaceChildren();try{const response=await fetch('/analyze',{method:'POST',body:new FormData(form)});const data=await response.json();status.textContent='';for(const item of data.files){const card=document.createElement('section');card.className='card';const title=document.createElement('h2');title.textContent=item.name;card.appendChild(title);const gate=document.createElement('p');gate.className=item.blocked?'bad':'good';gate.textContent=item.blocked?'QUARANTINED — extraction needs review':'EXTRACTION COMPLETE — reviewer approval still required';card.appendChild(gate);if(item.reasons.length){const reason=document.createElement('p');reason.textContent=item.reasons.join(' ');card.appendChild(reason)}const counts=document.createElement('div');for(const [key,value] of Object.entries(item.counts)){const chip=document.createElement('span');chip.className='pill';chip.textContent=key+': '+value;counts.appendChild(chip)}if(!Object.keys(item.counts).length)counts.textContent='No supported pattern detected; manual review is still required.';card.appendChild(counts);const previewTitle=document.createElement('p');previewTitle.innerHTML='<b>Tagged redacted text</b>';card.appendChild(previewTitle);const area=document.createElement('textarea');area.readOnly=true;area.value=item.blocked?'[QUARANTINED: do not pass this incomplete extraction downstream]\n\n'+item.redacted:item.redacted;card.appendChild(area);const approval=document.createElement('input');approval.type='checkbox';approval.disabled=item.blocked;const approvalLabel=document.createElement('label');approvalLabel.style.display='block';approvalLabel.style.margin='14px 0';approvalLabel.append(approval,document.createTextNode(' I reviewed the tagged output and approve this file for local release.'));card.appendChild(approvalLabel);const download=document.createElement('button');download.className='primary';download.textContent='Download redacted text';download.disabled=true;download.title=item.blocked?'Resolve extraction gaps and review before release':'';download.onclick=()=>{const link=document.createElement('a');link.href=URL.createObjectURL(new Blob([item.redacted],{type:'text/plain;charset=utf-8'}));link.download=item.name.replace(/\.[^.]+$/,'')+'_redacted.txt';link.click();URL.revokeObjectURL(link.href)};approval.addEventListener('change',()=>{download.disabled=item.blocked||!approval.checked});card.appendChild(download);const audit=document.createElement('details');const summary=document.createElement('summary');summary.textContent='Source traceability';audit.appendChild(summary);const pre=document.createElement('pre');pre.textContent=JSON.stringify(item.locations,null,2);audit.appendChild(pre);card.appendChild(audit);results.appendChild(card)}}catch(error){status.textContent='Processing failed: '+error.message}});
</script></body></html>"""


PAGE = PAGE.replace("body:new FormData(form)", "headers:{'X-CSRF-Token':'" + CSRF_TOKEN + "'},body:new FormData(form)")
PAGE = PAGE.replace(
    "title.textContent=item.name;",
    "title.dataset.fileType=(item.name.split('.').pop()||'file').toUpperCase();title.textContent='Evidence file';"
)
PAGE = PAGE.replace(
    "This prototype makes no LLM calls.",
    "No LLM or employee login is connected. Do not use for live company records; it has no malware scanner or permanent audit log."
)
PAGE = PAGE.replace(
    "</style>",
    ".nav{display:flex;gap:12px;margin:12px 0}.nav a{color:#146d78;font-weight:700;text-decoration:none;padding:6px 10px}"
    ".metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:14px 0}"
    ".metric{background:#fff;border:1px solid #d8e2ea;border-radius:10px;padding:14px 16px}.metric strong{display:block;font-size:28px;color:#102c49}"
    ".metric span{color:#586e80;font-size:14px}.dash-grid{display:grid;grid-template-columns:1fr 1.2fr;gap:14px}"
    ".bar-row{display:grid;grid-template-columns:130px 1fr 34px;align-items:center;gap:8px;margin:9px 0;font-size:14px}"
    ".bar-track{height:10px;background:#e8eef2;border-radius:8px;overflow:hidden}.bar-fill{height:100%;background:#187a83;border-radius:8px}"
    ".table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid #e0e7ec}th{color:#536d81;font-size:12px;text-transform:uppercase}"
    ".small-button{border:1px solid #b8cbd5;border-radius:6px;background:#fff;color:#146d78;padding:5px 9px;font:inherit;cursor:pointer}"
    ".status-chip{display:inline-block;padding:2px 8px;border-radius:20px;background:#e3f1ef}.status-chip.held{background:#f8eae7;color:#963a31}"
    ".warning{font-size:13px;color:#586e80}.muted{color:#586e80}details pre{white-space:pre-wrap;overflow-wrap:anywhere}"
    "@media(max-width:760px){.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.dash-grid{grid-template-columns:1fr}.wrap{margin:14px auto;padding:0 12px}.card{padding:16px}}"
    "</style>"
)
PAGE = PAGE.replace(
    "</header><section class=\"card\"><h2>1. Upload evidence files</h2>",
    "</header><nav class=\"nav\"><a href=\"#upload\">Upload evidence</a><a href=\"#dashboard\">Review dashboard</a></nav><section class=\"card\" id=\"upload\"><h2>1. Upload evidence files</h2>"
)
PAGE = PAGE.replace(
    "<div id=\"results\"></div>",
    "<section id=\"dashboard\" class=\"card\" hidden aria-live=\"polite\"><h2>2. Review dashboard</h2>"
    "<p class=\"muted\">Session summary only. The dashboard does not save an audit log.</p>"
    "<div class=\"metric-grid\"><div class=\"metric\"><strong id=\"mFiles\">0</strong><span>Files processed</span></div>"
    "<div class=\"metric\"><strong id=\"mHeld\">0</strong><span>Quarantined</span></div>"
    "<div class=\"metric\"><strong id=\"mPending\">0</strong><span>Awaiting review</span></div>"
    "<div class=\"metric\"><strong id=\"mDetections\">0</strong><span>PII spans tagged</span></div></div>"
    "<div class=\"dash-grid\"><section class=\"card\"><h3>Detection breakdown</h3><div id=\"typeBreakdown\"></div></section>"
    "<section class=\"card\"><h3>File review queue</h3><label for=\"queueFilter\" class=\"muted\">Filter by format or status</label>"
    "<p><input id=\"queueFilter\" type=\"search\" placeholder=\"For example: PDF or quarantined\"></p>"
    "<div class=\"table-wrap\"><table><thead><tr><th>Evidence</th><th>Format</th><th>PII spans</th><th>Status</th><th></th></tr></thead><tbody id=\"queueRows\"></tbody></table></div></section></div>"
    "<p class=\"warning\">Pattern counts do not prove that all PII was found. Review every eligible result before release.</p></section><div id=\"results\"></div>"
)
PAGE = PAGE.replace("link.download=item.name.replace(/\\.[^.]+$/,'')+'_redacted.txt';", "link.download='cadence_evidence_redacted.txt';")
DASHBOARD_SCRIPT = r"""const resultsNode=document.getElementById('results'),dash=document.getElementById('dashboard');
function refreshDashboard(){const cards=[...resultsNode.querySelectorAll(':scope > section.card')];if(!cards.length){dash.hidden=true;return}dash.hidden=false;const typeTotals={};let held=0,total=0,pending=0;const rows=document.getElementById('queueRows');rows.replaceChildren();cards.forEach((card,index)=>{const title=card.querySelector('h2');const ext=title.dataset.fileType||'FILE';title.textContent='Evidence '+String(index+1).padStart(2,'0')+' · '+ext;const isHeld=Boolean(card.querySelector('.bad'));if(isHeld)held++;const chips=[...card.querySelectorAll('.pill')];let count=0;chips.forEach(chip=>{const match=chip.textContent.match(/^(.+):\s*(\d+)$/);if(match){const n=Number(match[2]);typeTotals[match[1]]=(typeTotals[match[1]]||0)+n;count+=n}});total+=count;const approval=card.querySelector('input[type=checkbox]');if(approval&&!approval.disabled&&!approval.checked)pending++;const tr=document.createElement('tr');tr.dataset.search=(ext+' '+(isHeld?'quarantined':'awaiting review')).toLowerCase();const evidence=document.createElement('td');evidence.textContent='Evidence '+String(index+1).padStart(2,'0');const format=document.createElement('td');format.textContent=ext;const spans=document.createElement('td');spans.textContent=String(count);const state=document.createElement('td');state.innerHTML=isHeld?'<span class=\"status-chip held\">Quarantined</span>':(approval&&approval.checked?'<span class=\"status-chip\">Approved locally</span>':'<span class=\"status-chip\">Awaiting review</span>');const action=document.createElement('td');const button=document.createElement('button');button.className='small-button';button.textContent='Review';button.addEventListener('click',()=>{card.scrollIntoView({behavior:'smooth',block:'start'});card.focus({preventScroll:true})});action.appendChild(button);tr.append(evidence,format,spans,state,action);rows.appendChild(tr);if(approval)approval.addEventListener('change',()=>{const stateCell=tr.cells[3];stateCell.innerHTML=approval.checked?'<span class=\"status-chip\">Approved locally</span>':'<span class=\"status-chip\">Awaiting review</span>';document.getElementById('mPending').textContent=String([...cards].filter(c=>{const a=c.querySelector('input[type=checkbox]');return a&&!a.disabled&&!a.checked}).length)})});document.getElementById('mFiles').textContent=String(cards.length);document.getElementById('mHeld').textContent=String(held);document.getElementById('mPending').textContent=String(pending);document.getElementById('mDetections').textContent=String(total);const area=document.getElementById('typeBreakdown');area.replaceChildren();const entries=Object.entries(typeTotals).sort((a,b)=>b[1]-a[1]);if(!entries.length){const p=document.createElement('p');p.className='muted';p.textContent='No supported patterns were detected. Manual review is still required.';area.appendChild(p)}const max=Math.max(1,...entries.map(x=>x[1]));entries.forEach(([name,value])=>{const row=document.createElement('div');row.className='bar-row';const label=document.createElement('span');label.textContent=name;const track=document.createElement('div');track.className='bar-track';const fill=document.createElement('div');fill.className='bar-fill';fill.style.width=(value/max*100)+'%';track.appendChild(fill);const number=document.createElement('strong');number.textContent=String(value);row.append(label,track,number);area.appendChild(row)});document.getElementById('queueFilter').value=''}
document.getElementById('queueFilter').addEventListener('input',e=>{const term=e.target.value.toLowerCase();document.querySelectorAll('#queueRows tr').forEach(row=>row.hidden=!row.dataset.search.includes(term))});
new MutationObserver(()=>requestAnimationFrame(refreshDashboard)).observe(resultsNode,{childList:true});"""
PAGE = PAGE.replace("</script></body></html>", "</script><script>" + DASHBOARD_SCRIPT + "</script></body></html>")
INLINE_SCRIPT_HASHES = " ".join(
    "'sha256-" + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii") + "'"
    for script in re.findall(r"<script>(.*?)</script>", PAGE, re.S)
)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlparse(self.path).path != "/":
            self.send_error(404); return
        body = PAGE.encode("utf-8")
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.add_security_headers(); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def add_security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", f"default-src 'none'; style-src 'unsafe-inline'; script-src {INLINE_SCRIPT_HASHES}; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def do_POST(self):
        if self.path != "/analyze":
            self.send_error(404); return
        port = self.server.server_address[1]
        allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        if (self.headers.get("Host", "").lower() not in allowed_hosts
                or self.headers.get("Origin", "") not in {f"http://{host}" for host in allowed_hosts}
                or not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), CSRF_TOKEN)):
            self.send_error(403, "Local origin or request token check failed."); return
        if self.headers.get_content_type() != "multipart/form-data" or not self.headers.get_param("boundary"):
            self.send_error(415, "Expected a multipart form upload."); return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400); return
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self.send_error(413); return
        try:
            raw = self.rfile.read(length)
        except (TimeoutError, OSError):
            self.send_error(408); return
        if len(raw) != length:
            self.send_error(400, "Incomplete request body."); return
        headers = f"Content-Type: {self.headers.get('Content-Type')}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
        message = BytesParser(policy=policy.default).parsebytes(headers + raw)
        parts = list(message.iter_parts())
        upload_parts = [part for part in parts if part.get_filename()]
        if not upload_parts or len(upload_parts) > MAX_FILES_PER_REQUEST:
            self.send_error(400 if not upload_parts else 413, f"Select between 1 and {MAX_FILES_PER_REQUEST} files."); return
        use_ocr = any(part.get_param("name", header="content-disposition") == "ocr" for part in parts)
        results = []
        for part in upload_parts:
            filename = part.get_filename()
            if not filename:
                continue
            filename = Path(filename.replace("\\", "/")).name
            data = part.get_payload(decode=True) or b""
            if len(data) > MAX_FILE_BYTES:
                results.append({"name": filename, "blocked": True, "reasons": ["File exceeds 20 MB limit."], "counts": {}, "locations": [], "redacted": ""}); continue
            try:
                text, reasons = extract_document(filename, data, use_ocr)
                if not text.strip():
                    reasons.append("No usable text was extracted; manual review required.")
                redacted, counts, locations = redact_text(text)
                results.append({"name": filename, "blocked": bool(reasons), "reasons": reasons, "counts": dict(counts), "locations": locations, "redacted": redacted})
            except Exception as exc:
                results.append({"name": filename, "blocked": True, "reasons": [f"Extraction failed ({type(exc).__name__}); file quarantined."], "counts": {}, "locations": [], "redacted": ""})
        payload = json.dumps({"files": results}, ensure_ascii=False).encode("utf-8")
        self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8"); self.add_security_headers(); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print("[local] " + (fmt % args))


def main():
    parser = argparse.ArgumentParser(description="Local PII extraction and redaction demonstration")
    parser.add_argument("--host", default="127.0.0.1", help="Loopback address only; external binding is blocked")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    try:
        if not ipaddress.ip_address(args.host).is_loopback:
            parser.error("For safety, the prototype only binds to a loopback address.")
    except ValueError:
        parser.error("--host must be a loopback IP address such as 127.0.0.1.")
    required_modules = {"pypdf": "pypdf", "docx": "python-docx", "pptx": "python-pptx", "openpyxl": "openpyxl"}
    missing = [package for module, package in required_modules.items() if importlib.util.find_spec(module) is None]
    if missing:
        parser.exit(2, "Missing Python packages: " + ", ".join(missing) + ". Run: python -m pip install -r requirements.txt\n")
    server = HTTPServer((args.host, args.port), Handler)
    print(f"Open http://{args.host}:{args.port} in a browser. Press Ctrl+C to stop.")
    print("Files remain in memory; no external model or remote service is called.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

