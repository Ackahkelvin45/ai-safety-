"""Tests our detection on an open dataset we did not write: false positives, and foreign formats.

    python3 eval_false_positives.py          the development split (rows 0 to 999)
    python3 eval_false_positives.py --test   the frozen test split (rows 1,000 to 1,999)
    python3 eval_false_positives.py --fresh  a third slice (rows 2,000 to 2,999), used once to score strict mode
    add --strict to any of them to switch strict mode on (pipeline.OPTIONS)

Dataset: ai4privacy/pii-masking-200k on Hugging Face: synthetic English text full of
Western-format personal data, with every sensitive value labelled.

Two questions:

1. False positives. How often does our layer block or redact text with nothing sensitive in
   it, and how often does it remove a harmless number (an amount, a date, a postcode)?
2. Formats from outside our database. The dataset has account numbers, card numbers, US
   social security numbers, IBANs and so on. How many does our layer remove?

How the two splits were used. We read the misses on the development split and improved the
detector against them, so its numbers flatter us. The test split was downloaded and scored
only after the detector was frozen, and we did not look at its misses. It is the number to quote.

The rows are kept in local caches that are not committed: the dataset's licence is not
declared in its metadata, so we evaluate on it and do not redistribute it.
No Guard or LLM calls are made.
"""
import json
import urllib.request
from collections import Counter
from pathlib import Path

import pipeline

import sys
import time

TEST = "--test" in sys.argv
FRESH = "--fresh" in sys.argv
pipeline.OPTIONS["strict"] = "--strict" in sys.argv
START = 2000 if FRESH else 1000 if TEST else 0
CACHE = Path(__file__).with_name("pii_masking_fresh.json" if FRESH else "pii_masking_test.json" if TEST else "pii_masking_sample.json")
API = "https://datasets-server.huggingface.co/rows?dataset=ai4privacy/pii-masking-200k&config=default&split=train"
ROWS = 1000
HARMLESS = ["AMOUNT", "DATE", "TIME", "AGE", "HEIGHT", "ZIPCODE", "BUILDINGNUMBER"]
ID_LABELS = ["ACCOUNTNUMBER", "CREDITCARDNUMBER", "SSN", "IBAN", "PHONEIMEI", "VEHICLEVIN", "MASKEDNUMBER", "PHONENUMBER"]


def load():
    if CACHE.exists():
        return json.loads(CACHE.read_text())
    rows = []
    for offset in range(START, START + ROWS, 100):
        for attempt in range(8):   # the dataset server sometimes needs a moment
            try:
                with urllib.request.urlopen(f"{API}&offset={offset}&length=100", timeout=60) as r:
                    page = json.load(r)
                break
            except OSError:
                time.sleep(3 + 3 * attempt)
        else:
            sys.exit("Could not download the dataset.")
        rows += [{"text": p["row"]["source_text"], "spans": p["row"]["privacy_mask"]} for p in page["rows"]]
    CACHE.write_text(json.dumps(rows))
    return rows


if __name__ == "__main__":
    rows = load()
    print(("Fresh slice, rows 2,000 to 2,999." if FRESH else "Frozen test split, rows 1,000 to 1,999." if TEST
           else "Development split, rows 0 to 999.") + (" Strict mode ON.\n" if pipeline.OPTIONS["strict"] else "\n"))

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
    print("\n2. Identifiers in formats from outside our database:\n")
    print("| Label in the dataset | Removed | Recall |\n|---|---|---|")
    for label in ID_LABELS:
        print(f"| {label} | {removed[label]} of {total[label]} | {removed[label] / total[label]:.0%} |")
    print(f"| All of the above | {sum(removed.values())} of {sum(total.values())} | {sum(removed.values()) / sum(total.values()):.0%} |")
