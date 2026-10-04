"""Tests our detection on an open dataset we did not write: false positives, and foreign formats.

    python3 eval_false_positives.py

Dataset: ai4privacy/pii-masking-200k on Hugging Face: synthetic English text full of
Western-format personal data, with every sensitive value labelled. We use the first 1,000 rows.

Two questions:

1. False positives. With every labelled value taken out, nothing sensitive is left in the
   text. How often does our layer still block it or redact something?
2. Formats we never wrote a pattern for. The dataset has account numbers, card numbers, US
   social security numbers, IBANs and so on. None is in our database. How many does the
   catch-all remove anyway?

The rows are kept in a local cache that is not committed: the dataset's licence is not
declared in its metadata, so we evaluate on it and do not redistribute it.
No Guard or LLM calls are made.
"""
import json
import urllib.request
from collections import Counter
from pathlib import Path

import pipeline

CACHE = Path(__file__).with_name("pii_masking_sample.json")
API = "https://datasets-server.huggingface.co/rows?dataset=ai4privacy/pii-masking-200k&config=default&split=train"
ROWS = 1000
HARMLESS = ["AMOUNT", "DATE", "TIME", "AGE", "HEIGHT", "ZIPCODE", "BUILDINGNUMBER"]
ID_LABELS = ["ACCOUNTNUMBER", "CREDITCARDNUMBER", "SSN", "IBAN", "PHONEIMEI", "VEHICLEVIN", "MASKEDNUMBER", "PHONENUMBER"]


def load():
    if CACHE.exists():
        return json.loads(CACHE.read_text())
    rows = []
    for offset in range(0, ROWS, 100):
        with urllib.request.urlopen(f"{API}&offset={offset}&length=100", timeout=60) as r:
            rows += [{"text": p["row"]["source_text"], "spans": p["row"]["privacy_mask"]} for p in json.load(r)["rows"]]
    CACHE.write_text(json.dumps(rows))
    return rows


if __name__ == "__main__":
    rows = load()

    blocked = redacted = 0
    for row in rows:
        text = row["text"]
        for span in sorted(row["spans"], key=lambda s: -s["start"]):
            text = text[:span["start"]] + "X" + text[span["end"]:]
        out, notes = pipeline.hook(text, "input")
        blocked += out is None
        redacted += out is not None and bool(notes)
    print(f"1a. On {len(rows)} texts with every labelled value taken out:")
    print(f"    wrongly blocked as an injection: {blocked} ({blocked / len(rows):.1%})")
    print(f"    wrongly redacted: {redacted} ({redacted / len(rows):.1%})")

    # Harmless numbers left in place: amounts, dates, times, ages, heights, postcodes, building numbers.
    gone, seen = Counter(), Counter()
    for row in rows:
        out, _ = pipeline.hook(row["text"], "input")
        for span in row["spans"]:
            if span["label"] in HARMLESS and out is not None and any(ch.isdigit() for ch in span["value"]):
                seen[span["label"]] += 1
                gone[span["label"]] += span["value"] not in out
    print(f"1b. Harmless numbers wrongly removed: {sum(gone.values())} of {sum(seen.values())} "
          f"({sum(gone.values()) / sum(seen.values()):.1%}) " + str({k: f"{gone[k]}/{seen[k]}" for k in HARMLESS}))

    removed, total = Counter(), Counter()
    for row in rows:
        out, _ = pipeline.hook(row["text"], "input")
        for span in row["spans"]:
            if span["label"] in ID_LABELS and out is not None:
                total[span["label"]] += 1
                removed[span["label"]] += pipeline.compact(span["value"]) not in pipeline.compact(out)
    print("\n2. Formats we never wrote a pattern for:\n")
    print("| Label in the dataset | Removed | Recall |\n|---|---|---|")
    for label in ID_LABELS:
        print(f"| {label} | {removed[label]} of {total[label]} | {removed[label] / total[label]:.0%} |")
    print(f"| All of the above | {sum(removed.values())} of {sum(total.values())} | {sum(removed.values()) / sum(total.values()):.0%} |")
