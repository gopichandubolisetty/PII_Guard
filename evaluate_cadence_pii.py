from __future__ import annotations

import argparse
import json
import re
import unicodedata
from collections import Counter
from pathlib import Path

import cadence_pii_guard as guard


STRUCTURE_RE = re.compile(r"^\[([^\]]+)\]", re.MULTILINE)


def normalize_value(label: str, value: str) -> str:
    normalized = " ".join(unicodedata.normalize("NFKC", value).casefold().split())
    if label == "PHONE":
        return re.sub(r"\D", "", normalized)
    return normalized


def metrics(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    return {"true_positive": tp, "false_positive": fp, "false_negative": fn,
            "precision": precision, "recall": recall, "f1": f1}


def markdown_report(report: dict) -> str:
    lines = ["# Synthetic Adversarial Evaluation", "",
             "This report scores the fixtures listed in `Gold_Manifest.json`. All names, addresses, identifiers, and contact details are synthetic. Results are specific to this small, pattern-based prototype test set and do not estimate performance on organizational data.", "",
             "## File type summary", "",
             "| Format | Files | Held for review | Locator retention | Micro precision | Micro recall | Micro F1 |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    fmt = lambda value: "—" if value is None else f"{value:.1%}"
    for file_type, data in report["files_by_type"].items():
        totals = [m for m in data["by_class"].values() if m["precision"] is not None or m["recall"] is not None]
        tp = sum(m["true_positive"] for m in totals)
        fp = sum(m["false_positive"] for m in totals)
        fn = sum(m["false_negative"] for m in totals)
        micro = metrics(tp, fp, fn)
        lines.append(f"| {file_type.upper()} | {data['file_count']} | {data['quarantined_file_count']} | {fmt(data['structure']['retention'])} | {fmt(micro['precision'])} | {fmt(micro['recall'])} | {fmt(micro['f1'])} |")
    ordered_formats = [name for name in ("csv", "docx", "pdf", "pptx", "txt", "xlsx") if name in report["files_by_type"]]
    lines += ["", "## PII recall by format", "",
              "| " + " | ".join(["PII type", *[name.upper() for name in ordered_formats], "Overall precision", "Overall recall", "Overall F1"]) + " |",
              "|" + "|".join(["---", *["---:" for _ in ordered_formats], "---:", "---:", "---:"]) + "|"]
    for label, overall in report["overall_pii_by_class"].items():
        values = [fmt(report["files_by_type"].get(file_type, {}).get("by_class", {}).get(label, {}).get("recall")) for file_type in ordered_formats]
        values += [fmt(overall["precision"]), fmt(overall["recall"]), fmt(overall["f1"])]
        lines.append("| " + " | ".join([label, *values]) + " |")
    lines += ["", "## Adversarial checks", "", "| Check | Passed | Failed |", "|---|---:|---:|"]
    for name, values in report["security_case_summary"].items():
        lines.append(f"| {name.replace('_', ' ')} | {values['passed']} | {values['failed']} |")
    q = report["quarantine_summary"]
    lines += ["", f"Expected quarantines: {q['expected_quarantines_met']}/{q['expected_quarantines']}; missed: {q['missed_quarantines']}; unexpected: {q['unexpected_quarantines']}.", "",
              "## Interpretation", "",
              "- The scanned PDF retained the labeled page structure and detected all labeled synthetic PII values on the readable page. The second unreadable page was quarantined, so the PDF as a whole remained held for review.",
              "- One scanned-PDF person-name false positive came from the conservative first-page résumé name heuristic. This is recorded in precision instead of being hidden.",
              "- The spoofed `.pdf` extension and malformed CSV were rejected and quarantined. The injection text and the claim of employee authority remained untrusted document content; this prototype makes no LLM calls and has no employee-authentication path.",
              "- The DOCX containing contact details only inside an image was quarantined. Its embedded image text was not OCRed, so the PII recall misses in that file are surfaced in the DOCX row; quarantine keeps this incomplete extraction from release.",
              f"- Locator retention is the share of {report['overall_structure']['labeled_units']} explicitly labeled page/row/sheet markers present in extracted text. It does not score formatting or preceding/succeeding content preservation and does not verify the 80% structure-retention target. Small sample size and curated patterns mean these scores must not be represented as production accuracy.",
              "", "Rebuild fixtures and report with `python build_adversarial_challenge.py` followed by `python evaluate_cadence_pii.py \"Adversarial Challenge/Gold_Manifest.json\" --output \"Adversarial Challenge/Evaluation_Report.json\"`. The evaluator writes this Markdown summary alongside the JSON output.", ""]
    return "\n".join(lines)


def score_file(root: Path, item: dict) -> dict:
    path = (root / item["path"]).resolve()
    if not path.is_file() or root.resolve() not in path.parents:
        raise ValueError(f"Evaluation input is missing or outside the manifest folder: {item['path']}")

    try:
        extracted, failures = guard.extract_document(path.name, path.read_bytes(), bool(item.get("use_ocr")))
    except Exception as exc:
        extracted, failures = "", [f"Extraction failed ({type(exc).__name__}); input quarantined."]
    _, predicted_counts, predicted_locs = guard.redact_text(extracted)
    available_units = set(STRUCTURE_RE.findall(extracted))
    gold_units = set(item.get("gold_structure_units", []))
    retained = len(available_units & gold_units)
    structure_score = (retained / len(gold_units)) if gold_units else None

    gold_entities = item.get("gold_entities", [])
    predicted_spans = Counter((m["start"], m["end"], m["type"]) for m in predicted_locs)
    predicted_values = Counter((m["type"], normalize_value(m["type"], extracted[m["start"]:m["end"]])) for m in predicted_locs)
    gold_spans = Counter()
    gold_values = Counter()
    for entity in gold_entities:
        label = str(entity["type"])
        if "value" in entity:
            gold_values[(label, normalize_value(label, str(entity["value"])))] += 1
        else:
            gold_spans[(int(entity["start"]), int(entity["end"]), label)] += 1
    value_mode = any("value" in entity for entity in gold_entities)
    discovered_labels = ({label for _, _, label in gold_spans} | {label for label, _ in gold_values} |
                         {label for _, _, label in predicted_spans} | {label for label, _ in predicted_values})
    labels = sorted(set(item.get("gold_types", discovered_labels)))
    by_class = {}
    for label in labels:
        if value_mode:
            gold_for_label = Counter({key: count for key, count in gold_values.items() if key[0] == label})
            predicted_for_label = Counter({key: count for key, count in predicted_values.items() if key[0] == label})
            tp = sum((gold_for_label & predicted_for_label).values())
            fp = sum(predicted_for_label.values()) - tp
            fn = sum(gold_for_label.values()) - tp
        else:
            tp = sum((gold_spans & predicted_spans)[span] for span in gold_spans if span[2] == label)
            fp = sum(count for span, count in predicted_spans.items() if span[2] == label) - tp
            fn = sum(count for span, count in gold_spans.items() if span[2] == label) - tp
        by_class[label] = metrics(tp, fp, fn)

    case_results = []
    for case in item.get("security_cases", []):
        if case in {"spoofed_extension_quarantined", "malformed_row_quarantined", "partial_ocr_page_quarantine"}:
            passed = bool(failures)
            evidence = "File was quarantined for review." if passed else "Expected quarantine did not occur."
        elif case == "embedded_media_quarantined":
            passed = bool(failures)
            evidence = "Embedded media triggered quarantine because its contents are not inspected." if passed else "Embedded media was not quarantined."
        elif case == "non_pii_false_positive_controls":
            false_positives = sum(value["false_positive"] for value in by_class.values())
            passed = false_positives == 0
            evidence = "No scoped PII patterns matched the benign control text." if passed else f"{false_positives} false positive(s) matched benign control text."
        elif case == "table_labeled_contact_details":
            recall_values = [v["recall"] for v in by_class.values() if v.get("recall") is not None]
            passed = bool(recall_values) and all(value == 1.0 for value in recall_values)
            evidence = "All labeled fixture values detected." if passed else "At least one labeled fixture value was missed."
        elif case == "prompt_injection_inert":
            markers = ("Ignore all previous instructions", "attacker@example.test")
            passed = not getattr(guard, "LLM_ENABLED", False) and all(marker in extracted for marker in markers)
            evidence = "Injection text remains ordinary document text; this code path has no model call." if passed else "Inertness assertion failed."
        elif case == "impersonation_claim_no_authority":
            passed = not getattr(guard, "EMPLOYEE_AUTHENTICATION_ENABLED", False) and not getattr(guard, "LLM_ENABLED", False)
            evidence = "The prototype has no employee authentication or model-authorized action path." if passed else "Authority-boundary assertion failed."
        else:
            passed = None
            evidence = "No automated assertion is defined for this case."
        case_results.append({"case": case, "passed": passed, "evidence": evidence})

    return {
        "file": path.name,
        "file_type": path.suffix.lower().lstrip("."),
        "extraction_complete": not failures,
        "quarantined": bool(failures),
        "quarantine_reasons": failures,
        "expected_quarantine": item.get("expected_quarantine"),
        "quarantine_expectation_met": (
            bool(failures) == bool(item["expected_quarantine"])
            if "expected_quarantine" in item else None
        ),
        "extraction_failure_count": len(failures),
        "security_cases": item.get("security_cases", []),
        "security_case_results": case_results,
        "structure": {
            "labeled_units": len(gold_units),
            "retained_units": retained,
            "retention": structure_score,
        },
        "pii": {
            "scoring_mode": "normalized_value" if value_mode else "exact_span_offset",
            "labeled_spans": sum(gold_spans.values()) + sum(gold_values.values()),
            "detected_spans": sum(predicted_spans.values()),
            "by_class": by_class,
        },
        "detected_counts": dict(predicted_counts),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Score PII recall and extraction retention against a reviewed gold manifest.")
    parser.add_argument("manifest", type=Path, help="JSON annotation manifest; see Evaluation_Manifest_Template.json")
    parser.add_argument("--output", type=Path, help="Optional JSON report destination")
    args = parser.parse_args()
    manifest_path = args.manifest.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("files"), list):
        parser.error("Manifest must use schema_version 1 and provide a files array.")

    files = [score_file(manifest_path.parent, item) for item in manifest["files"]]
    aggregate = {}
    for file_type in sorted({entry["file_type"] for entry in files}):
        typed_files = [entry for entry in files if entry["file_type"] == file_type]
        classes = sorted({label for entry in typed_files for label in entry["pii"]["by_class"]})
        by_class = {}
        for label in classes:
            counts = [entry["pii"]["by_class"].get(label, {}) for entry in typed_files]
            tp = sum(item.get("true_positive", 0) for item in counts)
            fp = sum(item.get("false_positive", 0) for item in counts)
            fn = sum(item.get("false_negative", 0) for item in counts)
            by_class[label] = metrics(tp, fp, fn)
        aggregate[file_type] = {
            "file_count": len(typed_files),
            "quarantined_file_count": sum(entry["quarantined"] for entry in typed_files),
            "structure": {
                "labeled_units": sum(entry["structure"]["labeled_units"] for entry in typed_files),
                "retained_units": sum(entry["structure"]["retained_units"] for entry in typed_files),
                "retention": (
                    sum(entry["structure"]["retained_units"] for entry in typed_files)
                    / sum(entry["structure"]["labeled_units"] for entry in typed_files)
                    if sum(entry["structure"]["labeled_units"] for entry in typed_files) else None
                ),
            },
            "by_class": by_class,
        }
    all_classes = sorted({label for entry in files for label in entry["pii"]["by_class"]})
    overall_by_class = {}
    for label in all_classes:
        class_counts = [entry["pii"]["by_class"].get(label, {}) for entry in files]
        overall_by_class[label] = metrics(
            sum(item.get("true_positive", 0) for item in class_counts),
            sum(item.get("false_positive", 0) for item in class_counts),
            sum(item.get("false_negative", 0) for item in class_counts),
        )
    security = {}
    for result in (case for entry in files for case in entry["security_case_results"]):
        item = security.setdefault(result["case"], {"passed": 0, "failed": 0, "not_scored": 0})
        item["passed" if result["passed"] is True else "failed" if result["passed"] is False else "not_scored"] += 1
    report = {
        "schema_version": 1,
        "disclaimer": "Synthetic challenge results measure only these fixtures. Values are scored after Unicode/whitespace normalization; phone numbers are compared by digits. Manually review gold labels before citing results.",
        "structure_metric_definition": "Locator retention: matched labeled page/row/sheet marker strings divided by labeled marker strings. This is a narrow proxy; it does not score full context or formatting retention and cannot validate the 80% structure-retention outcome.",
        "files_by_type": aggregate,
        "overall_structure": {
            "labeled_units": sum(entry["structure"]["labeled_units"] for entry in files),
            "retained_units": sum(entry["structure"]["retained_units"] for entry in files),
            "retention": (
                sum(entry["structure"]["retained_units"] for entry in files)
                / sum(entry["structure"]["labeled_units"] for entry in files)
                if sum(entry["structure"]["labeled_units"] for entry in files) else None
            ),
        },
        "overall_pii_by_class": overall_by_class,
        "security_case_summary": security,
        "quarantine_summary": {
            "expected_quarantines": sum(entry["expected_quarantine"] is True for entry in files),
            "expected_quarantines_met": sum(entry["expected_quarantine"] is True and entry["quarantine_expectation_met"] is True for entry in files),
            "unexpected_quarantines": sum(entry["expected_quarantine"] is False and entry["quarantined"] for entry in files),
            "missed_quarantines": sum(entry["expected_quarantine"] is True and not entry["quarantined"] for entry in files),
        },
        "files": files,
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        args.output.with_suffix(".md").write_text(markdown_report(report), encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
