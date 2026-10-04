# Day 3: AI Safety Challenge — notes

Our notes on the organisers' challenge brief, the SecureAI Guard participant guide and the mentor session. The brief itself (`Challenge Brief.pdf`) is not committed because it contains the LLM API key.

## The challenge

- Each team gets the SecureAI Guard API (a screening proxy) and an LLM API.
- Build a simple system that adds a layer of protection on top of the Guard, addressing a weakness we found in it.
- The prototype must do three things: show a weakness in the Guard, show our system addressing it, and run as a working demo with the Guard and the LLM.
- Judged on Demo Day for innovation and creativity. There is no automated scoring.

## Dates and submission

- **4 October 2026:** submit a Git repository to nanidesmond01@gmail.com. The README must explain what we built, how to run it, and which system we chose to protect. **The token must not be in the repository.**
- **5 October 2026:** presentations. The organisers set up from our submission beforehand.

## The SecureAI Guard API

| Method and path | Use |
|---|---|
| `POST /v1/check/prompt` | Text a user typed, before it goes to a model |
| `POST /v1/check/response` | Text a model produced, before a user sees it |
| `GET /v1/usage` | How much of the team's quota is used today |
| `GET /health` | Is the service up (no token needed) |

Send `{"text": "..."}` with the header `Authorization: Bearer <token>`. Check one message at a time.

The reply has `allowed`, `flags`, `status` (`complete` or `partial`), a `checks` entry per category, a `request_id` and `latency_ms`. Categories: `injection`, `harmful_content`, `sensitive_data` ("card and account numbers, passwords, credentials"), `unsafe_links`, `prohibited_content`, `other`.

Errors: `400 text_required`, `401 unauthorized`, `413 text_too_long` (over 4,000 characters), `429 rate_limited` (wait for `Retry-After`), `429 daily_quota_exceeded` (resets 00:00 UTC), `502 guard_unavailable`, `503 service_busy`.

Limits: 30 requests a minute and 1,000 a day per team.

Ground rules: keep the token private and in an environment variable; never send real personal data; do not hammer the service.

## What the presentation needs (organiser message)

1. **Show the weakness, logically and visually.** A real prompt injection, jailbreak attempt or data-leak scenario, demonstrated live.
2. **Explain the system built around it.** How the Guard checks fit in, and what was added on top.
3. **Present one comprehensive solution.** One complete working pipeline, shown start to finish.
4. **Show the impact.** Who is protected, what harm is avoided, and why anyone outside the room should care.

## Mentor guidance

- Attacking the guard directly will not work; it is a strong system. Look for what it does not know, such as the Ghana Card, and use a custom database.
- Judging points: use case as problem and solution, architecture, latency with the guardrail, quality of the information returned, scalability, demonstration, presentation.
- Session notes: transparent communication middleware; errors from the guard; gaps the guard does not capture.
