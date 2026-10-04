"""Measures the input guard on prompt injections it has not seen.

    python3 eval_injections.py

Uses the test split of deepset/prompt-injections (116 prompts: 60 injections, 56 benign).
Our injection detector was trained on the train split only (see injection_model.py), so
this is a fair test of it. Only the input guard is run, so no LLM calls are made.

With the SecureAI Guard on, this makes 116 Guard calls (the daily limit is 1,000) and takes
about five minutes at the Guard's limit of 30 calls a minute.
"""
import injection_model
import pipeline

if __name__ == "__main__":
    test = injection_model.DATA["deepset/prompt-injections"]["test"]
    attacks = [r["text"] for r in test if r["label"] == 1]
    benign = [r["text"] for r in test if r["label"] == 0]
    if not pipeline.GUARD_ON:
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
