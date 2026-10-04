"""Measures how often our hook fires on text that holds none of our identifiers.

    python3 eval_false_positives.py

Dataset: ai4privacy/pii-masking-200k on Hugging Face: synthetic English, French, German and
Italian text full of Western-format personal data (names, IBANs, US-style phone numbers, IMEIs,
and so on). None of it is a Ghanaian, Nigerian, Kenyan or South African identifier, so every
time our hook redacts or blocks one of these texts it is a false positive.

The first 1,000 rows are downloaded and kept in a local cache that is not committed: the
dataset's licence is not declared in its metadata, so we evaluate on it and do not redistribute
it. No Guard or LLM calls are made.
"""
import json
import re
import urllib.request
from collections import Counter
from pathlib import Path

import pipeline

CACHE = Path(__file__).with_name("pii_masking_sample.json")
API = "https://datasets-server.huggingface.co/rows?dataset=ai4privacy/pii-masking-200k&config=default&split=train"
ROWS = 1000


def load():
    if CACHE.exists():
        return json.loads(CACHE.read_text())
    texts = []
    for offset in range(0, ROWS, 100):
        with urllib.request.urlopen(f"{API}&offset={offset}&length=100", timeout=30) as r:
            texts += [p["row"]["source_text"] for p in json.load(r)["rows"]]
    CACHE.write_text(json.dumps(texts))
    return texts


if __name__ == "__main__":
    texts = load()
    blocked, redacted, by_pattern = 0, 0, Counter()
    for text in texts:
        out, _ = pipeline.hook(text, "input")
        if out is None:
            blocked += 1
            continue
        placeholders = set(re.findall(r"\[([A-Z_]+)\]", out)) - set(re.findall(r"\[([A-Z_]+)\]", text))
        redacted += bool(placeholders)
        by_pattern.update(placeholders)
    print(f"{len(texts)} texts with no African identifiers in them")
    print(f"wrongly blocked as an injection: {blocked} ({blocked / len(texts):.1%})")
    print(f"wrongly redacted: {redacted} ({redacted / len(texts):.1%}), by pattern: {dict(by_pattern.most_common()) or 'none'}")
