"""Measures the allow-list judge (pipeline.judge) on data it was not developed against.

    python3 eval_judge.py

The judge's instructions (judge_prompt.txt) were written and adjusted using only a validation
portion of the training splits and our training list of banking requests. This script scores
it on the test splits of the three injection datasets, on our held-out banking requests, and
on 300 customer questions from banking77 (PolyAI, CC-BY-4.0; read from the mteb/banking77 copy
on Hugging Face), which it had never been shown.

"Stopped" means the judge answered ATTACK or OFF_TOPIC. For the benign prompts in the injection
datasets, which are general-knowledge questions, being stopped as OFF_TOPIC is the correct
behaviour for a bank assistant, so they are reported separately and not as false alarms.

About 800 LLM calls. No Guard calls.
"""
import json
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import injection_model
import pipeline


def banking77(n=300):
    texts = []
    for offset in range(0, 3000, 500):   # six slices across the test split, so many intents are covered
        url = ("https://datasets-server.huggingface.co/rows?dataset=mteb%2Fbanking77&config=default"
               f"&split=test&offset={offset}&length={n // 6}")
        with urllib.request.urlopen(url, timeout=60) as r:
            texts += [p["row"]["text"] for p in json.load(r)["rows"]]
    return texts


def verdicts(texts):
    with ThreadPoolExecutor(8) as pool:
        return Counter(pool.map(pipeline.judge, texts))


def line(label, texts, want_stopped):
    c = verdicts(texts)
    n, stopped = len(texts), c["ATTACK"] + c["OFF_TOPIC"]
    result = f"{stopped} of {n} ({stopped / n:.0%}) stopped" if want_stopped else f"{c['OK']} of {n} ({c['OK'] / n:.0%}) let through"
    print(f"| {label} | {result} | ATTACK {c['ATTACK']}, OFF_TOPIC {c['OFF_TOPIC']}, OK {c['OK']}, no verdict {c[None] + c['ERROR']} |", flush=True)


if __name__ == "__main__":
    print("| Test set | Result | Verdicts |\n|---|---|---|")
    for name, splits in injection_model.DATA.items():
        line(f"{name}: attacks", [r["text"] for r in splits["test"] if r["label"] == 1], True)
    for name, splits in injection_model.DATA.items():
        benign = [r["text"] for r in splits["test"] if r["label"] == 0]
        if benign:
            line(f"{name}: general prompts, not banking", benign, True)
    line("Our held-out banking requests", injection_model.BANKING[injection_model.BANKING_TRAIN:], False)
    line("banking77: real-style customer banking questions", banking77(), False)
