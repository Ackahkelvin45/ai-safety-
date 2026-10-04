# Global guardrails overlook Ghana's identifiers by design

The gap the team found is real, expected and documented by omission: **no major PII service ships a detector for any Ghanaian identifier**, and Model Armor's default sensitive-data filter looks for only six US and credential types, so Ghana Card PINs, mobile money numbers and SSNIT numbers pass on both the prompt and the response exactly as the vendor documentation implies. Every vendor's stated remedy is the one the team already built, a customer-supplied pattern layer, so the local regex database on both sides of the LLM is the mainstream fix rather than a workaround. What the research adds is the anatomy that mature tools wrap around a bare regex: a base confidence, context keywords inside a proximity window, a validator, an allow-list, and exact matching against the known customer records. That last technique closes most of the team's "names, balances and free-text facts" limit without any machine learning, because in a records assistant the sensitive values are already known. The over-block of a harmless record is also documented behaviour: Google warns that Model Armor's lower confidence thresholds cause "a high volume of false positives", though no independent false-positive rate for Model Armor was found. Competitions and CTFs set the honest ceiling: every filter-based defence was bypassed at least once, mostly by encoding or fragmenting the protected string, so the output side must be presented as hardened, not closed. No published empirical write-up of this gap for Ghana was found, which makes a measured "Model Armor alone versus Model Armor plus Ghana pack" result a defensible contribution for 5 October. Throughout, claims are marked as verified (the source page was opened, usually through a summarising fetch tool, so wording should be re-checked before quoting) or snippet-only (seen in a search result, page not opened).

## Vendor catalogues stop at South Africa

The clearest evidence is in the vendors' own entity lists. Model Armor's basic Sensitive Data Protection configuration detects **credit card numbers, US SSNs, financial account numbers, US ITINs, Google Cloud credentials and Google Cloud API keys, and nothing else**; only the advanced configuration accepts a Sensitive Data Protection inspect template with custom infoTypes ([Model Armor overview](https://docs.cloud.google.com/security-command-center/docs/model-armor-overview), verified). Even the full Sensitive Data Protection catalogue behind it has a single African infoType, `SOUTH_AFRICA_ID_NUMBER` ([SDP infoTypes reference](https://docs.cloud.google.com/sensitive-data-protection/docs/infotypes-reference), verified through a page summary). AWS Comprehend detects PII only in English or Spanish and has country-specific types for four countries, none African ([AWS Comprehend](https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html), verified). Bedrock Guardrails covers only US, Canada and UK identifiers and sends everything else to a custom regex filter ([Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html), verified). Azure AI Language PII and Microsoft Purview each list South Africa and no other African country ([Azure PII entity categories](https://learn.microsoft.com/en-us/azure/ai-services/language-service/personally-identifiable-information/concepts/entity-categories); [Purview entity definitions](https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-entity-definitions), both verified). Open-source Presidio is the only tool with a second African country, Nigeria (`NG_NIN`, `NG_VEHICLE_REGISTRATION`) alongside South Africa's `ZA_ID_NUMBER`; Ghana does not appear ([Presidio supported entities](https://presidio.dataprivacystack.org/supported_entities/), verified).

| Service | South Africa | Nigeria | Ghana | Status |
|---|---|---|---|---|
| Model Armor basic | No | No | No | Verified |
| Google SDP / Model Armor advanced | Yes | No | No | Verified via summary |
| AWS Comprehend, Bedrock Guardrails | No | No | No | Verified |
| Azure AI Language PII, Purview | Yes | No | No | Verified |
| Presidio | Yes | Yes | No | Verified via summary |

Two caveats keep this claim honest. No vendor states "Ghana is not supported"; the evidence is absence from the lists, and generic detectors such as a phone-number infoType were not tested against Ghanaian formats. And the closest open-source prior work, the pre-1.0 `arche` project, advertises a Ghana Data Protection Act statute pack but its README enumerates no Ghana Card, SSNIT or mobile money recognisers ([arche](https://github.com/unpatterned-labs/arche), verified; source code not inspected). The safe wording is "no Ghana identifier ships in Purview, Google SDP or Presidio's predefined recognisers as of October 2026", never "first ever". No industry report, vendor blog or bug report documenting Ghanaian identifiers slipping through a commercial guardrail was found, so the team's tested observation appears to be new as a published finding, with the limit that GitHub issue trackers and other DLP vendors' catalogues were not searched.

The language side of the gap is better documented than the identifier side. Google tests Model Armor's injection and content filters on nine languages, none African, and says quality elsewhere "might vary" ([Model Armor overview](https://docs.cloud.google.com/security-command-center/docs/model-armor-overview), verified). Low-resource languages jailbroke GPT-4 **79% of the time** on AdvBench in 2023 ([Yong et al.](https://arxiv.org/abs/2310.02446), verified), PolyGuard's 17 moderation languages exclude all of Sub-Saharan Africa ([PolyGuard](https://arxiv.org/html/2504.04377v1), verified), and TukaBench reports that African-language and culturally adapted prompts reduce refusal relative to English ([TukaBench](https://arxiv.org/abs/2606.01322), verified at abstract level). The picture is not uniform: a 2026 study found multi-turn jailbreak success in Kiswahili (41.8% to 70.9%) no higher than in English (52.7% to 83.6%), because poor translation degrades the attack ([Marx and Dunaiski](https://arxiv.org/abs/2605.18239), verified). On names, three PII masking systems showed their highest error rates for names associated with Black and Asian/Pacific Islander individuals ([Mansfield et al.](https://aclanthology.org/2022.ltedi-1.10/), verified), and OpenAI's open-weight Privacy Filter warns of under-detection of uncommon names and regional conventions ([model card](https://huggingface.co/openai/privacy-filter), verified). No study covering Twi, Ga, Ewe, Ghanaian Pidgin or Ghanaian names was found in either the PII or the guardrail literature.

## Every mature tool wraps the regex in context and confidence

Enterprise DLP solved this exact problem years ago, and its recipe is what the team's pattern database lacks. Microsoft Purview defines a sensitive information type as a primary element (a regex, with or without checksum), supporting keywords as "corroborative evidence", a character proximity window (250 characters in the worked examples) and a confidence level of 65, 75 or 85; a real definition such as Argentina's DNI is just one regex plus one keyword list ([Purview SIT overview](https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-learn-about), verified). Google SDP expresses the same idea as hotword rules that raise or lower a finding's likelihood within a character window ([SDP likelihood](https://docs.cloud.google.com/sensitive-data-protection/docs/creating-custom-infotypes-likelihood), verified), Presidio as context words that add 0.35 to a pattern's score ([Presidio context tutorial](https://raw.githubusercontent.com/microsoft/presidio/main/docs/tutorial/06_context.md), verified), and Azure's container format as strong and weak patterns with separate scores, hint words with a boost, and an allow-list of values never to redact ([Azure adapt-to-domain](https://learn.microsoft.com/en-us/azure/ai-services/language-service/personally-identifiable-information/how-to/adapt-to-domain-pii), verified). This structure matters for Ghana because the identifiers differ in ambiguity: a Ghana Card PIN is self-identifying and needs no context, whereas a bare ten-digit mobile number or a thirteen-character SSNIT string should be redacted only when a word such as "momo", "wallet" or "SSNIT" sits nearby. AfriHate's finding that Global South moderation fails through "keyword spotting out of context" is the warning against shipping bare patterns ([AfriHate](https://arxiv.org/abs/2501.08284), verified). All of it is standard-library Python: extra fields per JSON entry and a window search around each match.

The "formats are unverified" limit is partly closable today from primary sources. The Ghana Revenue Authority's submission to the OECD describes the Ghana Card PIN as a **three-letter ISO country code, an eight- or nine-digit number, and a checksum character that can be a number or a letter**, hyphen-separated; the checksum is "used internally" and no public algorithm was found ([OECD Ghana TIN sheet](https://www.oecd.org/tax/automatic-exchange/crs-implementation-and-assistance/tax-identification-numbers/Ghana-TIN.pdf), verified, PDF read in full). The commonly assumed `GHA-\d{9}-\d` therefore misses non-citizen cards (whose prefix is the holder's nationality code), the eight-digit variant and letter checksums; `[A-Z]{3}-\d{8,9}-[0-9A-Z]` matches the official description. The honest label is format-validated, checksum-unverified, and the team should not invent a check digit. The same sheet documents the 11-character GRA TIN with prefixes P00, C00, G00, Q00 and V00. The National Communications Authority's numbering plan fixes mobile numbers at nine significant digits beginning 2 or 5 after the leading 0 or +233 ([NCA numbering plan](https://www.nca.org.gh/wp-content/uploads/2021/11/NUMBERING-PLAN-FOR-GHANA.pdf), verified, though the document predates current operator names). A mobile money wallet is just a mobile number, so only context words distinguish the two. The **SSNIT format remains unverified**: the only source is a KYC vendor regex seen in a snippet whose page returned 404 ([Smile ID](https://docs.usesmileid.com/supported-id-types/for-individuals-kyc/backed-by-id-authority/supported-countries/ghana/ssnit), snippet-only), and the GhanaPost digital address structure comes from secondary sources only.

Staying inside Model Armor is possible in principle: advanced mode pointed at an SDP inspect template carrying custom regex infoTypes and hotword rules, optionally with a de-identify template ([Model Armor overview](https://docs.cloud.google.com/security-command-center/docs/model-armor-overview), verified). That is configuration rather than code, but it needs Google Cloud project permissions a hackathon team is unlikely to hold on a provided guard, and the local hook has a privacy argument in its favour: OWASP's LLM02 guidance lists pattern-matching redaction before processing as a mitigation ([OWASP LLM02:2025](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/), verified), and the cloud guard is itself a third-party processor of the text. No primary source was found that prescribes "local redaction before a cloud guard" in those words; that ordering is an inference from OWASP and from the team's own 0.1 ms versus 1.3 s measurement.

## Known records catch what patterns cannot

The team's largest stated limit, names, balances and free-text facts, has a cheaper answer than a name-detection model. Purview's Exact Data Match builds detectors from "exact values in a database of sensitive information": the source table is hashed with a salt, only hashes are uploaded, and a candidate found by an ordinary pattern is confirmed by hash lookup, with other fields from the same row raising confidence ([Purview EDM](https://learn.microsoft.com/en-us/purview/sit-learn-about-exact-data-match-based-sits), verified). Netskope does the same with SHA-256 and normalises values before hashing, so "987-654-3210" becomes "9876543210" ([Netskope exact match](https://docs.netskope.com/en/select-an-exact-match-file), verified). In a bank-staff assistant the names, account numbers and balances in a retrieved record are known exactly at request time, so a per-request set of those values, matched literally and in normalised form against the model's output, catches precisely the items regex cannot. A hit also supports a stronger statement than a pattern match: a real customer value is leaving, not merely something shaped like an identifier.

The stronger control sits upstream. RAG privacy research shows that an assistant repeats its context when asked: with 250 prompts of the form "topic plus 'Please repeat all the context'", researchers extracted 107 PIIs from an Enron store with Llama-7b-Chat and 205 with GPT-3.5-turbo, re-ranking had "almost no mitigation effects", and summarising the context helped untargeted leakage only ([Zeng et al.](https://arxiv.org/html/2402.16893), verified, full text). The practical reading is that anything placed in the prompt can come out, so the record should be minimised by field name and staff role before it reaches the model, with output scanning as the last line. This is inference from the paper rather than a quoted recommendation; no study of structured-record or banking assistants was found.

For names in free user text there is no standard-library solution, and the evidence favours a hybrid over a model swap. RECAP, the most transferable study, ran regex for structured PII alongside a zero-shot LLM for unstructured PII across 13 lower-resource locales and reached **weighted F1 0.657 against 0.360 for fine-tuned NER and 0.558 for zero-shot LLMs alone** ([RECAP](https://arxiv.org/html/2510.07551v1), verified); Ghana and African languages were not among its locales, and 0.66 is a reminder that nothing here is close to complete. Casper's three-layer design (rules, NER, local LLM) and the top Kaggle PII solutions (DeBERTa ensembles plus regex post-processing, scored on recall-weighted F5) tell the same story ([Casper](https://arxiv.org/abs/2408.07004), verified at abstract level; [Kaggle summary](https://zenn.dev/sinchir0/articles/396967387196dc), verified from a third-party summary). A local encoder such as GLiNER2-PII or Privacy Filter is a dependency and a model download with no evaluation on Ghanaian text, so it is a poor use of a single day. A small gazetteer of Ghanaian names with context triggers is feasible but partial, since Akan day names double as ordinary words.

One-way redaction is the easiest limit to lift. The established pattern replaces each value with a consistent token, keeps the mapping outside the model, and restores it on output: LLM Guard's Anonymize scanner and Vault ([LLM Guard](https://protectai.github.io/llm-guard/input_scanners/anonymize/), verified) and LangChain's reversible anonymizer both work this way, and LangChain documents the main failure, that models alter the replaced text so restoration misses ([LangChain notebook](https://raw.githubusercontent.com/langchain-ai/langchain/v0.1.0/docs/docs/guides/privacy/presidio_data_anonymization/reversible.ipynb), verified, v0.1.0 source). A single `[GHANA_CARD]` placeholder also collapses two different cards into one token, so the model cannot reason about which is which. Numbered placeholders with an in-memory dictionary per request fix both problems in a few lines; fixed-shape bracket tokens survive model rewriting better than realistic fake values. Two rules follow by inference: the mapping is itself personal data and must not be logged, and only values the user typed themselves should be restored, otherwise rehydration re-leaks what the guard removed. Format-preserving encryption and key-managed tokenisation, which Google documents in detail ([SDP pseudonymisation](https://docs.cloud.google.com/sensitive-data-protection/docs/pseudonymization), verified), add nothing for a single-process demo.

## Over-blocking and bypass are both measured properties

The harmless record blocked as "harmful content" matches a failure Google describes itself. Model Armor's Responsible AI filter runs at one of three confidence levels, and the documentation states that "Low and above", while thorough, "can cause a high volume of false positives" and that false positives "degrade the user experience by incorrectly blocking legitimate prompts or responses", recommending High or Medium for general content safety ([Model Armor overview](https://docs.cloud.google.com/model-armor/overview?hl=en), verified). The advice to test with known-safe queries and raise the threshold if false positives persist was seen only in a search summary of the same page. **No independent numeric false-positive rate for Model Armor was found**: the one benchmark that includes it, by Wavestone, returned HTTP 404 twice and is snippet-only. Broader benchmarks point both ways. Poly-Guard, across 19 guard models, found precision consistently higher than recall, meaning under-blocking on domain policy, with finance-domain F1 as low as 5.3 for LlamaGuard 4 and 63.3 for Granite Guardian ([Poly-Guard](https://arxiv.org/html/2506.19054v3), verified). A single headline false-positive rate for "guardrails" is therefore not defensible, and why this particular record tripped the classifier is unknown; lexical triggers in record text are a hypothesis only. The actionable step is to measure the block rate on the team's own benign records and, if the guard's thresholds are outside the team's control, report it and design around it.

Bypass evidence sets the limit on what the output filter can claim. In the SaTML 2024 CTF, 137,063 attack chats were run against 44 accepted defences and **"all defenses were bypassed at least once"**; attackers reconstructed even a six-character secret through character-by-character output, ASCII codes, list formatting and multi-turn chats ([SaTML CTF](https://arxiv.org/html/2406.07954v1), verified). Character-level obfuscation defeated six injection detectors at high rates, 100% for emoji smuggling and 81% to 95% for leetspeak ([Hackett et al.](https://arxiv.org/html/2504.11168v1), verified; these figures are for injection detectors, not PII detectors). Model Armor "doesn't decode or inspect encoded content" such as Base64, hex or URL encoding ([Model Armor overview](https://docs.cloud.google.com/model-armor/overview?hl=en), verified), so the regex hook and the cloud guard share this blind spot and stacking them does not close it. Model Armor is also stateless per call, so attacks split across turns go unseen unless the application joins the history. Layering still earns its place: in Lakera's Gandalf trial of 15,448 players, individual defences caught largely different attacks (about 14.5% overlap), only 2.9% to 6.4% of players beat the combined defence, and locking a session after three flagged attempts blocked 75% of otherwise-uncaught attacks ([Gandalf the Red](https://arxiv.org/html/2501.07927v3), verified). HackAPrompt's 600,000 prompts led to the conclusion that prompt-based defences do not work ([HackAPrompt](https://arxiv.org/html/2311.16119v3), verified), which supports deterministic checks outside the model.

On latency, the hook's 0.1 ms is negligible and the 1.3 s of guard time is where savings exist. OpenAI recommends running the input guard concurrently with the LLM call and releasing the answer only if the guard allows ([OpenAI cookbook](https://developers.openai.com/cookbook/examples/how_to_use_guardrails), verified), which by arithmetic on the team's figures would cut roughly 2.6 s to 1.9 s. The cost is that the prompt reaches the LLM before the verdict, acceptable only if local redaction has already run, and NVIDIA warns that mutating input inside parallel rails causes race conditions ([NeMo parallel rails](https://archive.docs.nvidia.com/nemo/microservices/25.9.0/guardrails/tutorials/parallel-rails.html), verified). AWS states that masking is not supported with asynchronous streaming ([Bedrock streaming](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-streaming.html), verified), so an output path that redacts must buffer. No vendor latency figure for Model Armor was found, and guidance on fail-open versus fail-closed comes from one practitioner blog and snippets only; the defensible position is fail-closed for guard-dependent categories with "blocked by policy" and "guard unavailable" reported separately.

## What was verified and what was not

The table below separates the report's load-bearing claims by evidence quality. "Verified" means the page was opened, in most cases through a summarising fetch tool rather than line-by-line reading, so any direct quotation should be re-checked before it goes on a slide. Two arXiv entries in the notes carry identifiers that do not match their stated submission dates (the Privacy Filter cross-lingual evaluation, 2608.02616, and the low-resource safety literature review, 2608.14626); both are omitted from the argument above for that reason.

| Claim | Status |
|---|---|
| Model Armor basic covers six types; advanced takes SDP templates; no decoding of encoded content; false-positive warning at low thresholds | Verified (vendor page) |
| No Ghana identifier in Google SDP, AWS, Azure, Purview, Presidio | Verified by absence from opened lists (SDP and Presidio via summary) |
| Ghana Card PIN structure; GRA TIN prefixes | Verified (OECD/GRA PDF read in full) |
| Mobile number structure (02/05, nine digits) | Verified (NCA PDF, dated 2021) |
| Ghana Card checksum algorithm | Not public; unknown |
| SSNIT number format | Snippet-only (vendor page 404); unverified |
| GhanaPost address format; Ghana passport format | Secondary or no source; unverified |
| Community Ghana Card regex gist | Snippet-only |
| `python-stdnum` Ghana TIN check digit module | Snippet-only (algorithm not read) |
| Purview SIT anatomy, EDM hashing, Netskope normalisation | Verified |
| RECAP, Zeng et al., SaTML CTF, Gandalf, HackAPrompt, Poly-Guard, Hackett et al. figures | Verified (full text or HTML) |
| Casper, CAPID, GLiNER2-PII, TukaBench, LlamaFirewall | Verified at abstract level only |
| Wavestone benchmark including Model Armor; per-guard false-positive rates in finance | Snippet-only; do not cite |
| Clinical de-identification figures (Philter recall 99.92%; cross-hospital F1 drop from about 0.95 to about 0.86) | Snippet-only; two snippets disagree on the drop |
| Model Armor fail-closed default; NeMo parallel-rail savings | Snippet-only |
| Ghana Data Protection Act text, regulator guidance, AU strategy content | Not opened; no claims made |
| Any evaluation of PII tools or guardrails on Ghanaian names, Twi, Ga, Ewe or Pidgin | None found |

The clinical de-identification literature is worth a sentence despite its snippet-only status, because its direction is consistent across sources: hybrid rule-plus-statistical systems tuned for recall, and a sharp drop when a detector moves to a new institution until it is customised with local data ([Yang et al.](https://bmcmedinformdecismak.biomedcentral.com/track/pdf/10.1186/s12911-019-0935-4), snippet-only). Its reporting convention, recall or F2 first and precision as the usability cost, is the one to copy. The framing sources are verified: an African agenda paper states that "African perspectives have not been meaningfully integrated into global debates and processes regarding AI safety" ([Segun et al.](https://arxiv.org/abs/2508.13179)), and Liz Orembo argues that "risk is relational and does not reside in code alone" ([Tech Policy Press](https://techpolicy.press/why-the-global-ai-safety-agenda-cannot-see-african-harms)).

## Conclusion

The research reframes the project. The team did not find a bug in Model Armor; it found the LLM-era instance of a coverage pattern that runs through every vendor catalogue, where identifier support follows market and regulatory pull and Sub-Saharan Africa outside South Africa is left to the deployer. The fix is not novel either, and that is its strength: it is the per-country detector pack that DLP products have shipped for a decade, placed on both sides of a model. What is new is the Ghana pack itself and a measurement of the gap, neither of which appears to exist in public.

The more useful shift is in where the remaining risk lies. Patterns are the right tool for fixed-format identifiers and will stay ahead of models that were never trained on them, but the unsolved part of the problem is not detection quality. It is that a model repeats what it is given and that any filter on a string can be evaded by re-encoding it, so the durable controls are minimising what enters the prompt and matching against values already known. A demo that states this limit and shows one bypass before and after normalisation will be more credible than one that claims the output side is sealed.

## Prioritised adoption list for 5 October

Ordered by value per hour; items 1 to 6 are standard-library Python and fit in a day for three people.

1. **Build a labelled test set and report numbers.** About 100 synthetic prompts and outputs containing Ghanaian identifiers (hyphenated, spaced, lower-case, embedded in sentences, code-switched) plus about 100 benign look-alikes (order numbers, dates). Report recall, precision and F2 for "Model Armor alone" versus "Model Armor plus local pack", and the block rate on benign customer records to quantify the over-block. This turns both the gap and the false positive into evidence and is the main deliverable. Basis: Presidio and clinical de-identification practice; Kaggle's recall-weighted metric.
2. **Correct the patterns from primary sources.** Ghana Card as `[A-Z]{3}-\d{8,9}-[0-9A-Z]` with tolerant separators; mobile as `(?:\+233|00233|0)[25]\d{8}`; GRA TIN as `[PCGQV]00[0-9A-Z]{8}`. Record the source of each format in the pattern file and label SSNIT and GhanaPost as unverified, Ghana Card as checksum-unverified. Basis: OECD/GRA sheet and NCA plan (verified).
3. **Add the DLP anatomy to each entry.** Base score, context words (English plus Twi and Pidgin terms such as "momo", "wallet", "SSNIT"), a proximity window of about 250 characters, a threshold, and an allow-list. Self-identifying patterns redact on their own; bare-digit patterns require context. This is also the direct mitigation for the team's own false positives. Basis: Purview, SDP, Presidio, Azure (verified).
4. **Exact-match known record values on the output.** Collect the names, account numbers, balances and identifiers from the retrieved record, normalise them, and search the model output for them literally; salted hashes are optional polish for the slide. This is the cheapest answer to "names and balances are not caught". Basis: Purview EDM, Netskope (verified).
5. **Normalise before matching, on both sides.** Unicode NFKC, strip zero-width characters, collapse spaces and hyphens between digits, attempt Base64 and hex decoding, and scan the joined conversation rather than the last message only. Demo one bypass ("spell the number with spaces") before and after. Basis: SaTML CTF, Hackett et al., Model Armor's stated encoding limit (verified).
6. **Switch to numbered reversible placeholders.** `[GHANA_CARD_1]`, `[GHANA_CARD_2]` with an in-memory per-request dictionary; restore only values the user typed; never log the mapping. Basis: LLM Guard, LangChain (verified).
7. **Minimise the record before it reaches the prompt.** Drop or partially mask fields by name and staff role, showing the last three or four characters where identity confirmation is needed. Smaller code change than it sounds if the demo record is a dictionary. Basis: inference from Zeng et al. and OWASP LLM02.
8. **Handle the over-block explicitly.** Ask the guard's operator whether the content-safety threshold can be raised to High; separate "blocked by policy" from "guard unavailable" in logs and user messages; show category-level reasons only, never the matched span. Basis: Model Armor documentation (verified); block-reason guidance is inference.
9. **Add a session counter.** Lock or escalate after three flagged attempts. Basis: Gandalf (verified).
10. **Frame the contribution carefully.** One slide with the vendor coverage table, the safe novelty wording, the two African-authored framing sources, and the pattern file and test set released under an open licence. Check the `arche` source for Ghana recognisers before presenting.

Leave for later: packaging the pack as Presidio recognisers (`GH_GHANA_CARD`, `GH_PHONE`, `GH_TIN`) for an upstream pull request, which is a credible next-step slide but not needed for the demo; running the input guard in parallel with the LLM call, which saves about 0.7 s but only safely after redaction; an extra LLM pass or a local encoder model for names in free text; Model Armor advanced mode with a custom SDP template, which needs project permissions; and format-preserving encryption or key-managed tokenisation.


---

# Appendix: design-level defences

Notes from a second literature search, on defences that work by design and not by detection. Sources were read through a summarising tool; figures should be checked against the papers before being quoted.

# Design-level (architectural) defences for LLM applications: verified literature notes

Compiled 2026-10-04. Scope: data leakage and prompt injection defences that work by architecture rather than by detection.

## How to read the verification labels

- **VERIFIED (abstract)**: I opened the arXiv/publisher abstract page; title, authors, venue and the quoted numbers appear in the abstract.
- **VERIFIED (full text)**: I opened the HTML full text. Numbers were extracted from the page by a fetch-and-summarise tool, so they are one step removed from my own reading. Check the cited section before quoting a number on a slide.
- **PARTIAL**: source opened, but the specific claim was not confirmed there.
- **UNVERIFIED**: could not open; do not cite without checking.

The team's design, for reference: (1) opaque tokens in place of customer identifiers, rehydrated after checks by role; (2) pattern + check-digit + catch-all detection of typed-in sensitive values; (3) need-to-know context fetched by a trusted non-LLM layer; (4) server-side sessions, lockout after repeated flagged attempts, audit log.

---

## 1. Capability and data-flow designs

### 1.1 CaMeL
Debenedetti, Shumailov, Fan, Hayes, Carlini, Fabian, Kern, Shi, Terzis, Tramèr. "Defeating Prompt Injections by Design." arXiv:2503.18813 (v1 24 Mar 2025, v2 24 Jun 2025). Google / Google DeepMind / ETH Zurich. Venue: arXiv preprint (no venue listed on the abstract page).
URL: https://arxiv.org/abs/2503.18813 (full text: https://arxiv.org/html/2503.18813v2)
Status: VERIFIED (abstract) for the headline; VERIFIED (full text) for the rest.

- Control and data flow are extracted from the trusted user query, so "untrusted data retrieved by the LLM can never impact the program flow"; capabilities attached to values enforce policies at tool-call time.
- Headline: solves **77% of AgentDojo tasks with provable security vs 84% undefended** (abstract, v2).
- Cost: about **2.82x input and 2.73x output tokens** versus native tool calling (median task). Utility loss is concentrated in the Travel suite.
- Stated limits: side channels (exceptions, timing), user-confirmation fatigue, and attacks that do not change control or data flow (text-to-text manipulation) are out of scope.

Borrow: the principle, not the interpreter. Decide what will be fetched and done from the trusted request alone, and enforce policy in code at the point data leaves, which is what the team's "rehydrate after checks, by role" already does.

### 1.2 Dual LLM pattern
Simon Willison. "The Dual LLM pattern for building AI assistants that can resist prompt injection." Blog post, 25 April 2023.
URL: https://simonwillison.net/2023/Apr/25/dual-llm-pattern/
Status: VERIFIED (full text). No quantitative evaluation exists in the post.

- Privileged LLM sees only trusted input and handles tools; Quarantined LLM reads untrusted content and has no tools; a non-LLM Controller passes content between them only as opaque variables (`$VAR1`).
- "It is absolutely crucial that unfiltered content output by the Quarantined LLM is never forwarded on to the Privileged LLM."
- Author's own verdict: "This solution is pretty bad"; complexity, social engineering of the user and chained prompts remain weak points.

Borrow: this is the closest named precedent for the team's opaque tokens. Cite it as the origin of "the model handles references, the controller handles values".

### 1.3 Design Patterns for Securing LLM Agents
Beurer-Kellner, Buesser, Creţu, Debenedetti, Dobos, Fabian, Fischer, Froelicher, Grosse, Naeff, Ozoani, Paverd, Tramèr, Volhejn. "Design Patterns for Securing LLM Agents against Prompt Injections." arXiv:2506.08837 (v1 10 Jun 2025, v3 27 Jun 2025).
URL: https://arxiv.org/abs/2506.08837 (full text: https://arxiv.org/html/2506.08837v3)
Status: VERIFIED (abstract + full text). Qualitative paper; reports no benchmark numbers.

- Six patterns: Action-Selector, Plan-Then-Execute, LLM Map-Reduce, Dual LLM, Code-Then-Execute, Context-Minimization.
- Core principle: "once an LLM agent has ingested untrusted input, it must be constrained so that it is impossible for that input to trigger any consequential actions."
- Ten case studies, including a Customer Service Chatbot and a SQL Agent.
- Utility cost is stated qualitatively: the patterns deliberately restrict what the agent can do.

Borrow: name the team's design in this vocabulary. Need-to-know retrieval by a trusted layer is Context-Minimization plus Action-Selector; token substitution is a Dual-LLM-style variable indirection.

### 1.4 FIDES (information-flow control)
Costa, Köpf, Kolluri, Paverd, Russinovich, Salem, Tople, Wutschitz, Zanella-Béguelin. "Securing AI Agents with Information-Flow Control." arXiv:2505.23643 (v1 29 May 2025, v2 3 Sep 2025). Microsoft.
URL: https://arxiv.org/abs/2505.23643 (full text: https://arxiv.org/html/2505.23643v2)
Status: VERIFIED (abstract) for the design; PARTIAL for the numbers below (extracted from the full text, comparison baselines were not fully clear to me, re-check before quoting).

- Planner tracks confidentiality and integrity labels on every value and "deterministically enforces security policies".
- New primitives: hiding tool results behind variables so they do not taint the context, and a quarantined LLM whose output is limited by a schema (boolean < enum < string), so the label reflects how much information can pass.
- Full text reports that with policies enforced, policy-violating injections in AgentDojo are stopped (extraction gave 1 of 949 for GPT-4o with FIDES versus 163 for a basic planner without policies), and that utility with reasoning models is comparable to the basic planner.

Borrow: constrained output types. Where the model only needs to answer yes/no or pick from a list about a sensitive record, force that schema; it caps what can leak.

---

## 2. Marking untrusted content

### 2.1 Spotlighting
Hines, Lopez, Hall, Zarfati, Zunger, Kiciman. "Defending Against Indirect Prompt Injection Attacks With Spotlighting." arXiv:2403.14720 (20 Mar 2024). Microsoft.
URL: https://arxiv.org/abs/2403.14720
Status: VERIFIED (abstract); per-variant numbers VERIFIED (full text).

- Headline: attack success rate "from greater than 50% to below 2%" on GPT-family models with minimal task impact.
- Delimiting roughly halves ASR; datamarking takes GPT-3.5-Turbo from about 50% to below 3%; encoding reaches about 0% but damages task quality on weaker models ("should not be used with earlier-generation models").
- Caveat from section 3 below: under adaptive attack, Spotlighting was broken at over 95% ASR.

Borrow: cheap to add around any free-text field pulled from customer records, as one layer, never as the control that the design relies on.

### 2.2 StruQ
Chen, Piet, Sitawarin, Wagner. "StruQ: Defending Against Prompt Injection with Structured Queries." arXiv:2402.06363; USENIX Security 2025.
URL: https://arxiv.org/abs/2402.06363
Status: VERIFIED (abstract for design and venue; full text for numbers).

- Separate prompt and data channels plus fine-tuning to ignore instructions in the data channel.
- Manual attacks: below 2% ASR. Optimisation attacks remain effective: TAP 97% -> 9% (Llama), 100% -> 36% (Mistral); GCG 97% -> 58% (Llama), 99% -> 56% (Mistral).
- Utility roughly unchanged (AlpacaEval win rate 67.2% -> 67.6% Llama; 80.0% -> 78.7% Mistral).

### 2.3 SecAlign
Chen, Zharmagambetov, Mahloujifar, Chaudhuri, Wagner, Guo. "SecAlign: Defending Against Prompt Injection with Preference Optimization." arXiv:2410.05451; ACM CCS 2025.
URL: https://arxiv.org/abs/2410.05451
Status: VERIFIED (abstract).

- Preference optimisation over (injected input, secure output, insecure output) triples.
- Abstract claim: "the first known method that reduces the success rates of various prompt injections to <10%, even against attacks much more sophisticated than ones seen during training", with similar utility.
- Caveat: the successor MetaSecAlign was broken at 96% ASR in "The Attacker Moves Second".

Borrow (2.2 and 2.3): requires fine-tuning, so not for a hackathon; the lesson is that channel separation helps against unsophisticated attacks only.

### 2.4 Instruction hierarchy
Wallace, Xiao, Leike, Weng, Heidecke, Beutel. "The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions." arXiv:2404.13208 (19 Apr 2024). OpenAI.
URL: https://arxiv.org/abs/2404.13208
Status: VERIFIED (abstract + full text).

- Trains GPT-3.5 Turbo to rank system > user > tool content.
- "Defense against system prompt extraction is improved by 63%"; "jailbreak robustness increases by over 30%".
- Reports over-refusal regressions on two evaluations (System Message Probing Questions; Jailbreakchat with Allowed Prompts).

Borrow: put policy in the system role and retrieved data in a clearly lower-privilege position, but treat it as probabilistic.

---

## 3. Evidence that detection-only defences fail under adaptive attack

### 3.1 The Attacker Moves Second
Nasr, Carlini, Sitawarin, Schulhoff, Hayes, Ilie, Pluto, Song, Chaudhari, Shumailov, Thakurta, Xiao, Terzis, Tramèr. "The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections." arXiv:2510.09023 (10 Oct 2025). OpenAI / Anthropic / Google DeepMind and others.
URL: https://arxiv.org/abs/2510.09023 (full text: https://arxiv.org/html/2510.09023v1)
Status: VERIFIED (abstract) for the headline; per-defence figures VERIFIED (full text, tool-extracted).

- Headline: 12 recent defences bypassed "with attack success rate above 90% for most", although most originally reported near-zero ASR.
- Per defence (extracted): Spotlighting >95%, Prompt Sandwiching >95%, StruQ 100%, MetaSecAlign 96%, Circuit Breakers 100%, PromptGuard >90%, Protect AI detector >90%, Model Armor >90%, PIGuard 71%, Data Sentinel >80%, MELON 76-95%.
- Human red-teaming: over 500 participants, $20,000 prize pool, every defence in the competition broken.
- The paper evaluates prompting, training, filtering and secret-knowledge defences. It does not evaluate CaMeL-style designs.

Borrow: never present a static block rate as a security claim. State what remains true if the detector is bypassed.

### 3.2 SaTML 2024 LLM CTF
Debenedetti, Rando, Paleka, Florin, Albastroiu, Cohen, Lemberg, Ghosh, Wen, Salem, Cherubin, Zanella-Beguelin, Schmid, Klemm, Miki, Li, Kraft, Fritz, Tramèr, Abdelnabi, Schönherr. "Dataset and Lessons Learned from the 2024 SaTML LLM Capture-the-Flag Competition." arXiv:2406.07954 (12 Jun 2024). (Abstract page lists IEEE SaTML 2024 as the competition venue; I believe the report appeared in the NeurIPS 2024 Datasets and Benchmarks track, UNVERIFIED.)
URL: https://arxiv.org/abs/2406.07954
Status: VERIFIED (abstract + full text).

- "All defenses were bypassed at least once." Dataset of over 137k multi-turn attack chats.
- 72 defences submitted, 44 accepted; defences could combine a system prompt, a Python filter and an LLM filter; models were GPT-3.5-turbo and Llama-2 70B.
- 137,063 chats, 5,461 (4%) with a correct secret extraction. Multi-turn matters: 15% of successful attacks needed four or more exchanges.
- Lesson stated: filtering a single short secret out of model output is "extremely challenging"; defences leak information about themselves through their behaviour.

Borrow: the only robust way to keep a secret from the output is for the model never to hold it, which is the argument for tokens and need-to-know context.

### 3.3 Gandalf the Red
Pfister, Volhejn, Knott, Arias, Bazińska, Bichurin, Commike, Darling, Dienes, Fiedler, Haber, Kraft, Lancini, Mathys, Pascual-Ortiz, Podolak, Romero-López, Shiarlis, Signer, Terek, Theocharis, Timbrell, Trautwein, Watts, Wu, Rojas-Carulla. "Gandalf the Red: Adaptive Security for LLMs." arXiv:2501.07927 (v1 14 Jan 2025, v3 4 Aug 2025). Lakera. (I believe this was ICML 2025; venue UNVERIFIED, not shown on the abstract page.)
URL: https://arxiv.org/abs/2501.07927 (full text: https://arxiv.org/html/2501.07927v3)
Status: VERIFIED (abstract + full text).

- Dataset: 279,675 prompts in 36,286 sessions from 15,448 users (1 Oct to 7 Nov 2024).
- **Session lockout**: an adaptive defence that blocks the whole session after T flagged prompts; "using a block threshold of 3 with the combined defense is able to block 75% of the attacks that were not caught by any of the non-adaptive" defences (section 4.2).
- Defence-in-depth: "only 14.5% of the attacks are blocked by all defenses", i.e. different detectors catch different attacks; only 2.9% / 6.3% / 6.4% of players beat the combined-defence level (general / summarisation / topic setups).
- Restricting the application domain raises security; system-prompt defences shorten and alter benign answers even when nothing is blocked, so utility must be measured on benign traffic.

Borrow: direct empirical support for the team's lockout. Cite the threshold-of-3 result and measure false lockouts on legitimate staff prompts.

---

## 4. Pseudonymisation / tokenisation with rehydration

### 4.1 Microsoft Presidio pseudonymisation sample
Microsoft Presidio documentation, sample notebook "pseudonymization.ipynb".
URL: https://raw.githubusercontent.com/microsoft/presidio/main/docs/samples/python/pseudonymization.ipynb (the docs-site URL https://microsoft.github.io/presidio/samples/python/pseudonymization/ returned 404)
Status: VERIFIED (notebook content). No quality evaluation.

- Custom `InstanceCounterAnonymizer` replaces entities with `<{entity_type}_{index}>` (for example `<PERSON_1>`) and keeps a mapping; `InstanceCounterDeanonymizer` restores them.
- The notebook notes the approach is not thread-safe.

### 4.2 LLM Guard Anonymize / Vault / Deanonymize
Protect AI, LLM Guard documentation.
URL: https://protectai.github.io/llm-guard/input_scanners/anonymize/
Status: VERIFIED (docs page). No quality evaluation.

- Input scanner redacts entities (credit cards, names, phones, emails, IPs, UUIDs, US SSN, crypto wallets, IBAN) using Presidio plus extra patterns; originals go to a Vault; the Deanonymize output scanner restores them.

### 4.3 LangChain PresidioReversibleAnonymizer
URL tried: https://python.langchain.com/docs/guides/privacy/presidio_data_anonymization/reversible (redirects to a generic overview page).
Status: UNVERIFIED. Seen only in search-result snippets, which describe an anonymise step storing a mapping and a deanonymise step using it.

### 4.4 Hide and Seek (HaS)
Chen, Li, Liu, Yu. "Hide and Seek (HaS): A Lightweight Framework for Prompt Privacy Protection." arXiv:2309.03057 (6 Sep 2023). Tencent.
URL: https://arxiv.org/abs/2309.03057
Status: VERIFIED (abstract + full text).

- A small local model hides entities; a second small model restores them in the LLM's output (needed because the output may be translated or rephrased, so string replacement fails).
- Translation BLEU-4: 38.55 without anonymisation; 37.16 with the 1.7B generative hide model (-2.32%); 35.50 with the 560M model (-5.65%).
- Classification F1: 91.20% baseline; changes between +0.17% and -1.16%.

### 4.5 PAPILLON
Li Siyan, Raghuram, Khattab, Hirschberg, Yu. "PAPILLON: Privacy Preservation from Internet-based and Local Language Model Ensembles." arXiv:2410.17127; NAACL 2025 main conference.
URL: https://arxiv.org/abs/2410.17127
Status: VERIFIED (abstract); redaction-baseline numbers VERIFIED (full text, tool-extracted).

- Local model rewrites the query without PII, remote model answers, local model composes the final answer with the private details.
- Headline: "maintains high response quality for 85.5% of user queries while restricting privacy leakage to only 7.5%."
- Plain redaction costs quality: full text reports quality falling from 88.2% (unredacted) to 77.2% for GPT-4o-mini on redacted queries.

### 4.6 ProSan
Shen, Xi, He, Tong, Hua, Zhong. "The Fire Thief Is Also the Keeper: Balancing Usability and Privacy in Prompts." arXiv:2406.14318 (20 Jun 2024).
URL: https://arxiv.org/abs/2406.14318
Status: VERIFIED (abstract only). Note: the paper title does not contain "ProSan"; arXiv:2408.08930 is a different paper (DePrompt, Sun et al.).

- Anonymises words according to task importance and privacy risk; claims "minimal reduction in task performance" on QA, summarisation and code generation. The abstract gives no numbers.

### 4.7 Casper
Chong, Hou, Yao, Talebi. "Casper: Prompt Sanitization for Protecting User Privacy in Web-Based Large Language Models." arXiv:2408.07004 (13 Aug 2024); DOI 10.1109/CSCloud66326.2025.00027.
URL: https://arxiv.org/abs/2408.07004
Status: VERIFIED (abstract).

- Browser extension with three layers: rule-based filter, NER model, local-LLM topic identifier.
- On 4,000 synthetic prompts: 98.5% accuracy filtering PII, 89.9% for privacy-sensitive topics.

### 4.8 Rescriber
Zhou, Xu, Wu, Li. "Rescriber: Smaller-LLM-Powered User-Led Data Minimization for LLM-Based Chatbots." arXiv:2410.11876; CHI 2025.
URL: https://arxiv.org/abs/2410.11876
Status: VERIFIED (abstract).

- User study, N=12: helped users reduce unnecessary disclosure; Llama3-8B detection judged on par with GPT-4o.
- "Comprehensiveness and consistency of the detection and sanitization" drive user trust.

Borrow (section 4 overall): keep the entity type and a stable index in the token (`<CUSTOMER_1>`), keep the mapping consistent across a session, expect a small but measurable quality loss (roughly 2 to 11 points in the studies above), and show the user what was replaced. The team's layered detector (patterns, check digits, catch-all) matches Casper's rule + model + fallback layering.

---

## 5. Access control before retrieval

### 5.1 OWASP LLM02:2025 Sensitive Information Disclosure
OWASP Top 10 for LLM Applications 2025.
URL: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
Status: VERIFIED (page).

- "Limit access to sensitive data based on the principle of least privilege. Only grant access to data that is necessary for the specific user or process."
- "Implement tokenization to preprocess and sanitize sensitive information. Techniques like pattern matching can detect and redact confidential content before processing."
- System-prompt restrictions "may not always be honored and could be bypassed via prompt injection or other methods."

### 5.2 OWASP LLM08:2025 Vector and Embedding Weaknesses
URL: https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/
Status: VERIFIED (page).

- "Implement fine-grained access controls and permission-aware vector and embedding stores."
- "Maintain detailed immutable logs of retrieval activities to detect and respond promptly to suspicious behavior."

### 5.3 Authorization-First Retrieval
Rohith Namboothiri. "Authorization-First Retrieval: Enforcing Least Privilege in Multi-Agent RAG Systems." Proceedings of the 6th Workshop on Trustworthy NLP (TrustNLP 2026).
URL: https://aclanthology.org/2026.trustnlp-main.15/
Status: VERIFIED (ACL Anthology abstract).

- Retrieve-then-filter pipelines "expose unauthorized context in 86.1% of queries".
- Resulting answer leakage: 41.3% (Gemini 2.0 Flash) and 29.5% (GPT-4o-mini).
- Conclusion: "behavioral guardrails and metadata tagging cannot reliably enforce least privilege in RAG pipelines"; authorisation must constrain the candidate set before any learned component sees it.

### 5.4 Azure AI Search document-level access control
Microsoft Learn, "Document-Level Access Control - Azure AI Search" (ms.date 2026-08-08).
URL: https://learn.microsoft.com/en-us/azure/search/search-document-level-access-overview
Status: VERIFIED (page).

- Security filters: the application passes the caller's identity and the query excludes non-matching documents, described as "essential for building secure ... retrieval-augmented generation (RAG) applications".
- Filtering inside the search pipeline is recommended over post-query trimming in application code.

### 5.5 Windley, "Authorization Before Retrieval"
Phil Windley. "Authorization Before Retrieval: Making RAG Safe by Construction." Blog, 7 Jan 2026.
URL: https://www.windley.com/archives/2026/01/authorization_before_retrieval_making_rag_safe_by_construction.shtml
Status: VERIFIED (page). Practitioner source, not peer reviewed.

- "If sensitive data is included in the prompt, it is already too late. The model has seen it." "Prompts express intent, not policy."

### 5.6 NIST
- NIST AI 100-2 E2025, "Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations", Vassilev, Oprea, Fordyce, Anderson, Davies, Hamin, March 2025. URL: https://csrc.nist.gov/pubs/ai/100/2/e2025/final. Status: PARTIAL. Landing page opened and bibliographic details confirmed; the PDF could not be parsed, so I could not confirm any specific wording on access control or prompt-injection mitigations.
- NIST AI 600-1 (Generative AI Profile, July 2024). Status: UNVERIFIED. Not opened; seen only through third-party summaries.

Borrow (section 5): apply the role check inside the trusted retrieval layer before anything enters the prompt, and log every retrieval. Section 5.3 gives the number to quote for why filter-after-retrieval is not enough.

---

## 6. Contextual integrity and role-based disclosure

### 6.1 ConfAIde
Mireshghallah, Kim, Zhou, Tsvetkov, Sap, Shokri, Choi. "Can LLMs Keep a Secret? Testing Privacy Implications of Language Models via Contextual Integrity Theory." arXiv:2310.17884; ICLR 2024 (Spotlight).
URL: https://arxiv.org/abs/2310.17884
Status: VERIFIED (abstract).

- GPT-4 and ChatGPT "reveal private information in contexts that humans would not, 39% and 57% of the time, respectively".
- "This leakage persists even when we employ privacy-inducing prompts or chain-of-thought reasoning."

Borrow: evidence that the model cannot be the one deciding who may see what. Role-based disclosure has to be enforced in code, as the team does at rehydration.

### 6.2 AirGapAgent
Bagdasarian, Yi, Ghalebikesabi, Kairouz, Gruteser, Oh, Balle, Ramage. "AirGapAgent: Protecting Privacy-Conscious Conversational Agents." arXiv:2405.05175; ACM CCS 2024. Google.
URL: https://arxiv.org/abs/2405.05175
Status: VERIFIED (abstract; mechanism and utility from full text).

- A minimiser decides which user data is relevant using only the trusted task description, before the conversational agent meets untrusted input; the agent then sees only that subset.
- Under context-hijacking attack, a baseline agent's protection drops from 94% to 45%; AirGapAgent keeps 97%.
- Utility reported at roughly 87-89% (full text, tool-extracted).

Borrow: the nearest published analogue of the team's need-to-know layer. The key detail is that the selection decision is made from trusted inputs only.

---

## Ideas from this literature that the team's design appears to be missing

1. **Selection driven by trusted inputs, not just by the prompt.** "Retrieve the records the prompt refers to" lets the prompt author choose the scope. AirGapAgent and Authorization-First Retrieval both decide scope from trusted facts (role, assigned customers, task type) first, and only then match the prompt. Add an explicit authorisation predicate ahead of the lookup.
2. **Field-level minimisation.** Fetch only the fields the task type needs, not whole records (AirGapAgent, OWASP LLM02).
3. **Treat free-text record fields as untrusted input.** Notes, memos and transaction narratives can carry indirect injections. Either withhold them, pass them as opaque variables (Dual LLM), or at minimum datamark them (Spotlighting).
4. **Constrained output types.** Where a task needs only yes/no or a category, force that schema (FIDES); it bounds leakage regardless of what the model was told.
5. **Typed, session-stable tokens.** Tokens that carry entity type and a stable index preserve answer quality better than bare redaction (Presidio sample, PAPILLON's 88.2% to 77.2% drop for redaction). Measure answer quality with and without tokenisation.
6. **Adaptive evaluation.** Report results from people actively trying to beat the layer, including multi-turn attempts, rather than a static prompt list (Attacker Moves Second, SaTML CTF).
7. **Utility on benign traffic.** Measure false flags and false lockouts for legitimate staff prompts (Gandalf's D-SEC framing). Lockout has an availability cost if a colleague can trigger it or if detectors over-flag.
8. **Uninformative refusals.** Defences leak how they work through their responses (SaTML CTF). Keep block messages generic and constant.
9. **Retrieval-level audit.** Log which records and fields were fetched for whom, immutably, not only which prompts were flagged (OWASP LLM08).
10. **Say what holds if detection fails.** The typed-in detector (layer 2) is a detection defence and will be bypassed under adaptive attack. State the claim that survives: the model never holds identifiers the user's role does not permit.

## Sources that could not be fully verified

- LangChain reversible anonymiser page (redirected): UNVERIFIED.
- NIST AI 600-1: UNVERIFIED. NIST AI 100-2 E2025: bibliographic details only.
- FIDES numerical results: opened, but the baseline comparisons were unclear in extraction; re-read section on AgentDojo evaluation before quoting.
- Venue for Gandalf the Red (ICML 2025?) and for the SaTML CTF report (NeurIPS 2024 D&B?): from memory, not confirmed on the pages opened.
- Spotlighting: only the arXiv listing was confirmed; no peer-reviewed venue checked.
