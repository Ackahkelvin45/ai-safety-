"""Measures the input guard on a public prompt-injection dataset.

    python3 eval_injections.py

Dataset: deepset/prompt-injections on Hugging Face (Apache-2.0), 662 prompts labelled
1 = injection, 0 = benign. Downloaded once and cached in prompt_injections.json.
Only the input guard is run, so no LLM calls are made.

The SecureAI Guard allows 1,000 calls a day, so when it is on we test a fixed random
sample of 100 prompts (50 injections, 50 benign), one Guard call each. That takes about
four minutes at the Guard's limit of 30 calls a minute.
"""
import json
import random
import urllib.request
from pathlib import Path

import pipeline

CACHE = Path(__file__).with_name("prompt_injections.json")
API = "https://datasets-server.huggingface.co/rows?dataset=deepset/prompt-injections&config=default"


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


if __name__ == "__main__":
    rows = load()
    attacks = [r["text"] for r in rows if r["label"] == 1]
    benign = [r["text"] for r in rows if r["label"] == 0]
    if pipeline.GUARD_ON:
        random.seed(2026)
        attacks, benign = random.sample(attacks, 50), random.sample(benign, 50)
    else:
        print("The SecureAI Guard is not configured, so only our hook is measured.\n")

    def measure(texts):
        """(stopped by hook, stopped by Guard, stopped by either), one Guard call per text."""
        hook = [pipeline.hook(t, "input")[0] is None for t in texts]
        grd = [not pipeline.guard(t[:4000], "input")["allowed"] for t in texts] if pipeline.GUARD_ON else None
        return hook, grd, grd and [h or g for h, g in zip(hook, grd)]

    a, b = measure(attacks), measure(benign)
    print(f"| Guard | Injections stopped (of {len(attacks)}) | Benign prompts wrongly stopped (of {len(benign)}) |")
    print("|---|---|---|")
    for name, i in (("Our hook only", 0), ("Guard only", 1), ("Guard + our hook", 2)):
        if a[i] is not None:
            print(f"| {name} | {sum(a[i])} ({sum(a[i]) / len(attacks):.0%}) | {sum(b[i])} ({sum(b[i]) / len(benign):.0%}) |")
