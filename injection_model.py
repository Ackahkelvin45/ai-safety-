"""A small prompt-injection detector learned from an open dataset.

    python3 injection_model.py      print how it scores on data it was not trained on

Dataset: deepset/prompt-injections on Hugging Face (Apache-2.0), labelled 1 = injection,
0 = benign. It ships as a train split (546 prompts) and a test split (116). The detector is
a Naive Bayes classifier over words and word pairs, trained on the train split only. The
blocking threshold is set by five-fold cross-validation on the train split, at the level
where about 1% of benign prompts would be stopped. The test split is used only to report.

Standard library only. Training takes a few milliseconds and happens at import.
"""
import json
import math
import re
import urllib.request
from collections import Counter
from pathlib import Path

CACHE = Path(__file__).with_name("prompt_injections.json")
API = "https://datasets-server.huggingface.co/rows?dataset=deepset/prompt-injections&config=default"
TRAIN_SIZE = 546  # rows are cached in order: the train split, then the test split


def load():
    if CACHE.exists():
        return json.loads(CACHE.read_text())
    rows = []
    for split in ("train", "test"):
        offset = 0
        while True:
            with urllib.request.urlopen(f"{API}&split={split}&offset={offset}&length=100", timeout=30) as r:
                page = json.load(r)
            rows += [p["row"] for p in page["rows"]]
            offset += 100
            if offset >= page["num_rows_total"]:
                break
    CACHE.write_text(json.dumps(rows))
    return rows


def tokens(text):
    words = re.findall(r"[^\W\d_]+", text.lower())
    return words + [f"{a} {b}" for a, b in zip(words, words[1:])]


def train(rows):
    counts = {0: Counter(), 1: Counter()}
    docs = Counter()
    for r in rows:
        counts[r["label"]].update(tokens(r["text"]))
        docs[r["label"]] += 1
    vocab = len(set(counts[0]) | set(counts[1]))
    totals = {k: sum(c.values()) + vocab for k, c in counts.items()}
    return counts, totals, math.log(docs[1] / docs[0])


def score(model, text):
    """Log-odds that text is an injection. Higher means more likely."""
    counts, totals, prior = model
    return prior + sum(math.log((counts[1][t] + 1) / totals[1]) - math.log((counts[0][t] + 1) / totals[0])
                       for t in tokens(text))


def pick_threshold(rows, folds=5, benign_stopped=0.01):
    """The score above which about 1% of unseen benign prompts would be stopped."""
    benign = []
    for k in range(folds):
        model = train([r for i, r in enumerate(rows) if i % folds != k])
        benign += [score(model, r["text"]) for i, r in enumerate(rows) if i % folds == k and r["label"] == 0]
    benign.sort()
    return benign[min(len(benign) - 1, int(len(benign) * (1 - benign_stopped)))]


ROWS = load()
MODEL = train(ROWS[:TRAIN_SIZE])
THRESHOLD = pick_threshold(ROWS[:TRAIN_SIZE])


def is_injection(text):
    return score(MODEL, text) > THRESHOLD


if __name__ == "__main__":
    test = ROWS[TRAIN_SIZE:]
    attacks = [r["text"] for r in test if r["label"] == 1]
    benign = [r["text"] for r in test if r["label"] == 0]
    caught, wrong = sum(map(is_injection, attacks)), sum(map(is_injection, benign))
    print(f"threshold {THRESHOLD:.2f}, chosen on the train split")
    print(f"test split: {caught} of {len(attacks)} injections stopped ({caught / len(attacks):.0%}), "
          f"{wrong} of {len(benign)} benign prompts wrongly stopped ({wrong / len(benign):.0%})")
