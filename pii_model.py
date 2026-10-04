"""A learned detector for identifier-like numbers, to catch what the patterns have no row for.

    python3 pii_model.py            how it scores on data it was not trained on
    python3 pii_model.py --train    retrain from nemotron_sample.json and rewrite pii_model.json

The hand-written catch-all in pipeline.py only fires next to a short list of identity words.
This replaces that list with something learned: for every token that carries four or more
digits, a classifier decides from the token's shape and the words around it whether it is an
identifier (account, card, licence, phone, customer number and so on) or something harmless
(a date, a time, an amount, a postcode, a house number).

Training data: nvidia/Nemotron-PII on Hugging Face (CC-BY-4.0), 4,000 documents from its train
split. The documents are not included here; the trained weights in pii_model.json are, with
this attribution. The classifier is an averaged perceptron. Standard library only.
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent
WEIGHTS = HERE / "pii_model.json"
SAMPLE = HERE / "nemotron_sample.json"

# Labels in the training data that mean "an identifier, contact number or credential".
SENSITIVE = {"phone_number", "fax_number", "customer_id", "employee_id", "certificate_license_number",
             "account_number", "credit_debit_card", "bank_routing_number", "pin", "ssn", "medical_record_number",
             "health_plan_beneficiary_number", "tax_id", "unique_id", "license_plate", "vehicle_identifier",
             "device_identifier", "biometric_identifier", "password", "api_key", "swift_bic"}
# Labels left out of training altogether: digit-bearing, but neither an identifier nor harmless.
IGNORED = {"ipv4", "ipv6", "mac_address", "url", "email", "coordinate", "http_cookie", "user_name", "date_of_birth"}

TOKEN = re.compile(r"[^\s\[\](){}<>\"',;]+")
EDGE = ".:!?*`"


def tokens(text):
    """(start, end, token) for every run of non-space characters, with edge punctuation trimmed."""
    out = []
    for m in TOKEN.finditer(text):
        token = m.group().strip(EDGE)
        if token:
            start = m.start() + m.group().index(token)
            out.append((start, start + len(token), token))
    return out


def candidate(token):
    return sum(ch.isdigit() for ch in token) >= 4


def shape(token):
    """'GHA-123456789-0' -> 'A-9-9': letters, digits and punctuation, with repeats collapsed."""
    out = []
    for ch in token:
        kind = "9" if ch.isdigit() else "A" if ch.isupper() else "a" if ch.islower() else ch
        if not out or out[-1] != kind:
            out.append(kind)
    return "".join(out)


def word(token):
    return token.lower() if token.isalpha() else shape(token)


def features(toks, i):
    token = toks[i][2]
    digits = sum(ch.isdigit() for ch in token)
    feats = ["bias", "shape=" + shape(token), f"len={min(len(token), 20)}", f"digits={min(digits, 20)}",
             f"letters={min(sum(ch.isalpha() for ch in token), 6)}", f"separators={min(len(token) - sum(ch.isalnum() for ch in token), 5)}"]
    for offset in (-4, -3, -2, -1, 1, 2):
        j = i + offset
        w = word(toks[j][2]) if 0 <= j < len(toks) else "<edge>"
        feats.append(f"w{offset}={w}")
        if offset < 0:
            feats.append("before=" + w)      # the same word anywhere in the four before
    if i >= 2:
        feats.append("pair=" + word(toks[i - 2][2]) + " " + word(toks[i - 1][2]))
    return feats


def examples(rows):
    """(features, is an identifier) for every digit-bearing token whose label we can trust."""
    for row in rows:
        toks = tokens(row["text"])
        for i, (start, end, token) in enumerate(toks):
            if not candidate(token):
                continue
            labels = {s["label"] for s in row["spans"] if s["start"] < end and start < s["end"]}
            if labels & IGNORED:
                continue
            yield features(toks, i), bool(labels & SENSITIVE)


def train(rows, epochs=5):
    data = list(examples(rows))
    weights, totals, stamps = defaultdict(float), defaultdict(float), defaultdict(int)
    step = 0
    for epoch in range(epochs):
        for k in range(len(data)):               # a fixed shuffle: every third, then the rest, and so on
            feats, label = data[(k * 7919 + epoch * 104729) % len(data)]
            step += 1
            if (sum(weights[f] for f in feats) > 0) != label:
                for f in feats:
                    totals[f] += (step - stamps[f]) * weights[f]
                    stamps[f] = step
                    weights[f] += 1 if label else -1
    for f in weights:
        totals[f] += (step - stamps[f]) * weights[f]
    averaged = {f: round(total / step, 4) for f, total in totals.items() if abs(total / step) >= 0.01}
    return averaged, len(data)


MODEL = json.loads(WEIGHTS.read_text()) if WEIGHTS.exists() else {}


def spans(text):
    """(start, end) of every token the model judges to be an identifier."""
    toks = tokens(text)
    return [(start, end) for i, (start, end, token) in enumerate(toks)
            if candidate(token) and sum(MODEL.get(f, 0.0) for f in features(toks, i)) > 0]


if __name__ == "__main__":
    sample = json.loads(SAMPLE.read_text()) if SAMPLE.exists() else sys.exit(
        "nemotron_sample.json is not here (it is not committed). The trained weights in pii_model.json still work.")
    if "--train" in sys.argv:
        MODEL, n = train(sample["train"])
        WEIGHTS.write_text(json.dumps(MODEL))
        print(f"trained on {n} digit-bearing tokens from {len(sample['train'])} documents; kept {len(MODEL)} weights")
    hit = miss = false_alarm = quiet = 0
    for feats, label in examples(sample["test"]):
        guess = sum(MODEL.get(f, 0.0) for f in feats) > 0
        hit += guess and label
        miss += label and not guess
        false_alarm += guess and not label
        quiet += not guess and not label
    print(f"Held-out documents from the same dataset ({len(sample['test'])}):")
    print(f"  identifiers found: {hit} of {hit + miss} ({hit / (hit + miss):.1%})")
    print(f"  harmless numbers wrongly flagged: {false_alarm} of {false_alarm + quiet} ({false_alarm / (false_alarm + quiet):.1%})")
