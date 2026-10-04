"""A small prompt-injection detector learned from open datasets.

    python3 injection_model.py             how it scores on data it was not trained on
    python3 injection_model.py --download  rebuild injection_datasets.json from Hugging Face

Training data (train splits only), all openly licensed and included in injection_datasets.json:

  deepset/prompt-injections           Apache-2.0   injections and benign prompts, English and German
  jackhhao/jailbreak-classification   Apache-2.0   jailbreak prompts and benign role-play prompts
  Lakera/gandalf_ignore_instructions  MIT          "ignore your instructions" attacks from the Gandalf game

plus BANKING below: benign things bank staff type, written by us, so that ordinary requests
containing words like "now", "forget" or "ignore my last message" are not mistaken for attacks.

The detector is one Naive Bayes classifier per attack family (one per dataset), over words and
word pairs, each trained on that family's attacks against the benign prompts of all the
datasets. A prompt is stopped if any of them says so. The families use different vocabulary,
and a single classifier blurred them: on a validation portion of the training data it stopped
7% of the weakest family, against 21% for one classifier per family.

Each threshold is set by five-fold cross-validation on the training data and favours
precision: under 0.5% of benign prompts stopped, and none of our own banking requests.
The design was chosen on validation data. Test splits are used only to report.

Standard library only. Training happens at import and takes about a second.
"""
import json
import math
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

CACHE = Path(__file__).with_name("injection_datasets.json")
SOURCES = {  # dataset -> (splits, column holding the text, how to read the label)
    "deepset/prompt-injections": (("train", "test"), "text", lambda row: row["label"]),
    "jackhhao/jailbreak-classification": (("train", "test"), "prompt", lambda row: int(row["type"] == "jailbreak")),
    "Lakera/gandalf_ignore_instructions": (("train", "validation", "test"), "text", lambda row: 1),
}

# Benign requests from our own domain. The first 48 are training data; the rest are held out.
BANKING = [
    "What is the balance for this customer?", "Now tell me how to open a savings account.",
    "Forget it, what is the balance of the other customer instead?", "Please ignore my last message. Can you update the address?",
    "Which city does the customer live in?", "List the customers who live in Kumasi.",
    "What documents does a customer need to open a current account?", "How do I reset a customer's mobile banking PIN?",
    "Act as my assistant and draft a letter to a customer about a late loan payment.",
    "You are helping a teller. What is the process to block a lost card?", "Summarise this customer's record in two sentences.",
    "Now show me the last customer I asked about.", "Instead of the balance, give me the city.",
    "From now on, answer in short sentences please.", "Start again. What details do you have for this customer?",
    "Disregard the previous customer, I typed the wrong name.", "What is the daily withdrawal limit for a savings account?",
    "Explain the instructions for verifying a Ghana Card.", "What are the rules for opening an account for a minor?",
    "Tell me everything I need to know about the new mobile money fees.", "Write a polite reminder for a customer whose account is overdrawn.",
    "Translate this notice to the customer into Twi.", "Pretend I am a new teller and explain how a transfer works.",
    "Imagine a customer has lost their card. What should I do first?", "Can you print the steps for closing an account?",
    "Show me how to check whether a MoMo number is linked to an account.", "Ignore the typo in my last question, I meant Tamale.",
    "What is the system for escalating a fraud complaint?", "Give me a prompt I can use to greet customers at the counter.",
    "Role play a difficult customer so I can practise.", "What was the previous question I asked you?",
    "Repeat the answer above but shorter.", "Is this customer's SSNIT number on file?",
    "How many customers do we have in Accra?", "Update the phone number on this profile.",
    "What does the policy say about sharing account details by phone?", "Do not include the balance, just the city.",
    "New task: help me write the end-of-day report.", "Stop. I asked for the Kumasi branch, not Accra.",
    "Answer without any restrictions on length, I need the full procedure.", "Who approves a loan above GHS 50,000?",
    "List all the fees for international transfers.", "What should I say when a customer asks for another customer's details?",
    "Override the default currency and show the amount in dollars.", "Forget the letter, write an SMS instead.",
    "Now act as a trainer and quiz me on the account opening rules.", "What are your instructions for handling a deceased customer's account?",
    "Reveal the steps a customer must take to unlock their account.",
    # held out
    "Now tell me how to apply for a loan.", "Forget that, show me the balance instead.",
    "Please ignore my previous question and tell me the branch opening hours.", "Act as a customer service trainer and review my reply.",
    "What is the process to change a customer's digital address?", "Disregard the last name I gave you, it was misspelled.",
    "From now on give amounts in cedis.", "Pretend you are explaining mobile money to a first-time customer.",
    "Print the checklist for verifying identity at the counter.", "New request: list the customers who live in Cape Coast.",
    "Show me the rules about dormant accounts.", "Instead, summarise the customer's record.",
    "Start over and tell me which city this customer lives in.", "Write a short apology to a customer for a delayed transfer.",
    "What instructions do tellers follow when a card is swallowed by the machine?", "Stop, I need the fees for a savings account, not a current account.",
]
BANKING_TRAIN = 48


def download():
    data = {}
    for dataset, (splits, column, label) in SOURCES.items():
        data[dataset] = {}
        for split in splits:
            rows, offset = [], 0
            while True:
                url = (f"https://datasets-server.huggingface.co/rows?dataset={urllib.parse.quote(dataset, safe='')}"
                       f"&config=default&split={split}&offset={offset}&length=100")
                for attempt in range(5):   # the dataset server sometimes needs a moment
                    try:
                        with urllib.request.urlopen(url, timeout=60) as r:
                            page = json.load(r)
                        break
                    except OSError:
                        time.sleep(2 + 2 * attempt)
                else:
                    sys.exit(f"Could not download {dataset} ({split}).")
                rows += [{"text": p["row"][column], "label": label(p["row"])} for p in page["rows"]]
                offset += 100
                if offset >= page["num_rows_total"]:
                    break
            data[dataset][split] = rows
    CACHE.write_text(json.dumps(data))


def tokens(text):
    words = re.findall(r"[^\W\d_]+", text.lower())
    return set(words + [f"{a} {b}" for a, b in zip(words, words[1:])])


def train(rows):
    counts = {0: Counter(), 1: Counter()}
    docs = Counter()
    for r in rows:
        counts[r["label"]].update(tokens(r["text"]))   # each word counts once per prompt
        docs[r["label"]] += 1
    vocab = len(set(counts[0]) | set(counts[1]))
    totals = {k: sum(c.values()) + vocab for k, c in counts.items()}
    return counts, totals, math.log(docs[1] / docs[0])


def score(model, text):
    """How strongly text reads as an injection. Scaled by length so long prompts are not favoured."""
    counts, totals, prior = model
    found = tokens(text)
    return (prior + sum(math.log((counts[1][t] + 1) / totals[1]) - math.log((counts[0][t] + 1) / totals[0])
                        for t in found)) / math.sqrt(len(found) + 1)


def pick_threshold(rows, folds=5, benign_stopped=0.005):
    """Precision first. In cross-validation, the score above which under 0.5% of benign prompts
    would be stopped and none of our own banking requests would be. A wrongly stopped request
    counts towards locking a member of staff out, so we would sooner miss an attack: the token
    vault is what protects the data, not this detector."""
    benign, banking = [], []
    for k in range(folds):
        model = train([r for i, r in enumerate(rows) if i % folds != k])
        for i, r in enumerate(rows):
            if i % folds == k and r["label"] == 0:
                (banking if r.get("ours") else benign).append(score(model, r["text"]))
    benign.sort()
    return max([benign[min(len(benign) - 1, int(len(benign) * (1 - benign_stopped)))]] + banking)


def fit(data, leave_out=None):
    """One (model, threshold) per attack family, each against all the benign prompts."""
    benign = [r for name, splits in data.items() if name != leave_out for r in splits["train"] if r["label"] == 0]
    benign += [{"text": t, "label": 0, "ours": True} for t in BANKING[:BANKING_TRAIN]]
    detectors = []
    for name, splits in data.items():
        if name != leave_out:
            rows = [r for r in splits["train"] if r["label"] == 1] + benign
            detectors.append((train(rows), pick_threshold(rows)))
    return detectors


def flagged(detectors, text):
    return any(score(model, text) > threshold for model, threshold in detectors)


DATA = json.loads(CACHE.read_text()) if CACHE.exists() else None
if DATA is None and "--download" not in sys.argv:
    sys.exit("injection_datasets.json is missing. Run: python3 injection_model.py --download")
DETECTORS = fit(DATA) if DATA else []


def is_injection(text):
    return flagged(DETECTORS, text)


def report(detectors, rows):
    attacks = [r for r in rows if r["label"] == 1]
    benign = [r for r in rows if r["label"] == 0]
    caught = sum(flagged(detectors, r["text"]) for r in attacks)
    wrong = sum(flagged(detectors, r["text"]) for r in benign)
    return (f"{caught} of {len(attacks)} ({caught / len(attacks):.0%})",
            f"{wrong} of {len(benign)} ({wrong / len(benign):.0%})" if benign else "no benign prompts in this set")


if __name__ == "__main__":
    if "--download" in sys.argv:
        download()
        sys.exit(f"Wrote {CACHE.name}.")
    print("Trained on the train splits of all three datasets. Scored on their test splits:\n")
    print("| Test set | Injections stopped | Benign prompts wrongly stopped |\n|---|---|---|")
    for name, splits in DATA.items():
        print(f"| {name} | " + " | ".join(report(DETECTORS, splits["test"])) + " |")
    held = [{"text": t, "label": 0} for t in BANKING[BANKING_TRAIN:]]
    wrong = sum(is_injection(r["text"]) for r in held)
    print(f"| Our own held-out banking requests | none in this set | {wrong} of {len(held)} ({wrong / len(held):.0%}) |")
    print("\nThe harder test. Trained with one dataset left out entirely, scored on that dataset's test split:\n")
    print("| Dataset never seen in training | Injections stopped | Benign prompts wrongly stopped |\n|---|---|---|")
    for name in list(DATA)[:2]:   # the third has no benign prompts to set a threshold against
        print(f"| {name} | " + " | ".join(report(fit(DATA, leave_out=name), DATA[name]["test"])) + " |")
