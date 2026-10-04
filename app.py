"""Demo web app: one prompt, run side by side with the Guard only and with our layer.

    python3 app.py        then open http://127.0.0.1:8000

Who you are decides what you see, so the role is never taken from the request. It comes from
a signed session cookie set at sign-in. Demo accounts are in users.json (passwords stored as
PBKDF2 hashes): teller / teller-demo-2026 and compliance / compliance-demo-2026. Anyone not
signed in is a guest.

Also here: a lockout after repeated flagged requests, and an audit log (audit.log, one JSON
line per request, never containing a sensitive value).

The page is the React app in web/, served from its built copy in web/dist. After changing
anything under web/src, rebuild it:  cd web && npm install && npm run build

The server itself is standard library only and listens on this machine only.
Each comparison uses four Guard calls.
"""
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pipeline

HERE = Path(__file__).parent
DIST = (HERE / "web" / "dist").resolve()
USERS = json.loads((HERE / "users.json").read_text())
AUDIT = HERE / "audit.log"

SECRET = os.urandom(32)   # signs session cookies; new on every start, so a restart signs everyone out
SESSIONS = {}             # session id -> {"user", "role", "flags": [times], "failed": [times], "locked_until"}
ACCOUNTS = {}             # username -> {"misses": [times], "locked_until"}: follows the person, not the cookie
LOCK = threading.Lock()

FLAG_LIMIT, FLAG_WINDOW, LOCK_SECONDS = 3, 600, 300   # 3 flagged requests in 10 minutes lock the session for 5
MISS_LIMIT = 10                                        # typed identifiers that match no customer, same window
LOGIN_LIMIT = 5                                        # failed sign-ins in the same window before the same lock


# What the settings screen can change: who may see which field of a customer's record, and which
# data types are detected in typed text. A guest's row is not editable: a guest gets nothing.
MODES = ("full", "partial", "hidden")
EDITABLE_ROLES = ("teller", "compliance")
FIELDS = [(pipeline.PROTECTED[f], pipeline.TITLES[f]) for f in pipeline.PROTECTED]
TYPES = list({e["name"]: {"name": e["name"], "label": e["label"], "country": e["country"]}
              for e in pipeline.DB if e["action"] == "redact"}.values())
TYPES.append({"name": "UNVERIFIED_ID", "label": "anything else shaped like an identifier (catch-all and learned detector)", "country": "any"})


def settings(session):
    return {"can_edit": session["role"] == "compliance",
            "fields": FIELDS,
            "policy": {role: {name: pipeline.POLICY[role].get(name, "hidden") for name, _ in FIELDS} for role in EDITABLE_ROLES},
            "types": [dict(t, on=t["name"] not in pipeline.DISABLED) for t in TYPES],
            "strict": pipeline.OPTIONS["strict"]}


def sign(session_id):
    return hmac.new(SECRET, session_id.encode(), hashlib.sha256).hexdigest()


def new_session(role="guest", user=None):
    session_id = secrets.token_urlsafe(24)
    SESSIONS[session_id] = {"user": user, "role": role, "flags": [], "failed": [], "locked_until": 0}
    return session_id


def recent(times):
    cutoff = time.time() - FLAG_WINDOW
    times[:] = [t for t in times if t > cutoff]
    return len(times)


def audit(session, **event):
    with LOCK, AUDIT.open("a") as f:
        f.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "user": session["user"] or "guest",
                            "role": session["role"], **event}) + "\n")


def found(text, released=(), lookup=True):
    """Plain-language labels of the sensitive values present in text, apart from those the
    policy released to this user on purpose. With lookup=False the text is not compared with
    the customer file, so the labels cannot reveal whether a value is a customer's."""
    if not text:
        return []
    for shown in released:
        text = text.replace(shown, " ")
    notes = []
    pipeline.detect(pipeline.canonical(text), "", notes, lookup=lookup)
    return sorted({label for label in pipeline.LABELS.values() if any(label in note for note in notes)})


class Handler(BaseHTTPRequestHandler):
    session_id = None

    def session(self):
        """The caller's session, from a cookie we signed. Anything else gets a fresh guest session."""
        cookie = SimpleCookie(self.headers.get("Cookie", "")).get("session")
        session_id, _, signature = (cookie.value if cookie else "").partition(".")
        with LOCK:
            if session_id in SESSIONS and hmac.compare_digest(signature, sign(session_id)):
                self.session_id = session_id
            else:
                self.session_id = new_session()
            return SESSIONS[self.session_id]

    def reply(self, code, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if self.session_id:
            self.send_header("Set-Cookie", f"session={self.session_id}.{sign(self.session_id)}; "
                                           "HttpOnly; SameSite=Strict; Path=/")
        self.end_headers()
        self.wfile.write(data)

    def status(self, session):
        user = USERS.get(session["user"] or "", {})
        return {"guard": pipeline.GUARD_ON, "llm": bool(pipeline.OPENAI_KEY), "role": session["role"],
                "name": user.get("name"), "locked_for": max(0, round(session["locked_until"] - time.time()))}

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/status":
            return self.reply(200, self.status(self.session()))
        if path == "/settings":
            return self.reply(200, settings(self.session()))
        file = (DIST / (path.lstrip("/") or "index.html")).resolve()
        if DIST in file.parents and file.is_file():  # only files inside the built app
            self.reply(200, file.read_bytes(), mimetypes.guess_type(file.name)[0] or "application/octet-stream")
        elif not DIST.is_dir():
            self.reply(503, b"The page is not built yet. Run: cd web && npm install && npm run build", "text/plain")
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        session = self.session()
        account = ACCOUNTS.setdefault(session["user"], {"misses": [], "locked_until": 0}) if session["user"] else None
        locked_until = max(session["locked_until"], account["locked_until"] if account else 0)
        if locked_until > time.time():
            wait = round(locked_until - time.time())
            return self.reply(429, {"error": f"This session is locked for {wait} more seconds after repeated flagged requests."})
        try:
            handler = {"/login": self.login, "/logout": self.logout, "/run": self.run_prompt, "/settings": self.change_settings}[self.path]
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 20000)) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, KeyError):
            return self.reply(400, {"error": "Bad request."})
        handler(session, body)

    def login(self, session, body):
        username, password = str(body.get("username", "")), str(body.get("password", ""))
        user = USERS.get(username)
        # hash even for an unknown user, so the reply takes the same time either way
        salt = bytes.fromhex(user["salt"]) if user else b"\0" * 16
        attempt = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()
        if user and ACCOUNTS.get(username, {}).get("locked_until", 0) > time.time():
            audit(session, event="sign-in refused: account locked")
            return self.reply(429, {"error": "This account is locked after too many identifiers that match no customer."})
        if not user or not hmac.compare_digest(attempt, user["hash"]):
            with LOCK:
                session["failed"].append(time.time())
                if recent(session["failed"]) >= LOGIN_LIMIT:
                    session["locked_until"] = time.time() + LOCK_SECONDS
            audit(session, event="sign-in failed")
            return self.reply(401, {"error": "Wrong username or password."})
        with LOCK:   # a new session id on sign-in, so a cookie planted beforehand is worthless
            del SESSIONS[self.session_id]
            self.session_id = new_session(user["role"], username)
            session = SESSIONS[self.session_id]
        audit(session, event="signed in")
        self.reply(200, self.status(session))

    def logout(self, session, body):
        audit(session, event="signed out")
        with LOCK:
            del SESSIONS[self.session_id]
            self.session_id = new_session()
        self.reply(200, self.status(SESSIONS[self.session_id]))

    def change_settings(self, session, body):
        """Only a compliance officer may change the settings, and every value is checked against a
        fixed list before anything is applied. The change is for everyone and lasts until restart."""
        if session["role"] != "compliance":
            return self.reply(403, {"error": "Only a compliance officer can change the settings."})
        policy, disabled, strict = body.get("policy", {}), body.get("disabled"), body.get("strict")
        names = {name for name, _ in FIELDS}
        valid = (isinstance(policy, dict) and all(
                     role in EDITABLE_ROLES and isinstance(cells, dict)
                     and all(name in names and mode in MODES for name, mode in cells.items())
                     for role, cells in policy.items())
                 and (disabled is None or (isinstance(disabled, list) and set(map(str, disabled)) <= {t["name"] for t in TYPES}))
                 and strict in (None, True, False))
        if not valid:
            return self.reply(400, {"error": "Bad request."})
        with LOCK:
            for role, cells in policy.items():
                for name, mode in cells.items():
                    if mode == "hidden":
                        pipeline.POLICY[role].pop(name, None)
                    else:
                        pipeline.POLICY[role][name] = mode
            if disabled is not None:
                pipeline.DISABLED.clear()
                pipeline.DISABLED.update(disabled)
            if strict is not None:
                pipeline.OPTIONS["strict"] = strict
        audit(session, event="settings changed", policy=policy, disabled=sorted(pipeline.DISABLED), strict=pipeline.OPTIONS["strict"])
        self.reply(200, settings(session))

    def run_prompt(self, session, body):
        prompt, use_hook = body.get("prompt"), bool(body.get("hook"))
        if not isinstance(prompt, str) or not 0 < len(prompt.strip()) <= 4000:  # the Guard's own limit
            return self.reply(400, {"error": "The prompt must be between 1 and 4,000 characters."})
        try:
            result = pipeline.run(prompt.strip(), use_hook=use_hook, role=session["role"], session=self.session_id)
        except Exception as e:  # the LLM call failed; the Guard's failures are handled inside run()
            print(f"LLM error: {e!r}")
            return self.reply(502, {"error": "The language model could not be reached. Try again."})
        # On the protected side, a result is never compared with the customer file, for any role.
        lookup = not use_hook
        # Identifiers that found no customer are counted against the ACCOUNT, so signing in again
        # does not reset them. The request that crosses the limit is not answered.
        if session["user"] and result.get("lookup_misses"):
            with LOCK:
                account = ACCOUNTS.setdefault(session["user"], {"misses": [], "locked_until": 0})
                account["misses"].extend([time.time()] * result["lookup_misses"])
                over = recent(account["misses"]) > MISS_LIMIT
                if over:
                    account["locked_until"] = time.time() + LOCK_SECONDS
            if over:
                audit(session, event="account locked", lookup_misses=result["lookup_misses"])
                return self.reply(429, {"error": f"This account is locked for {LOCK_SECONDS // 60} minutes: too many "
                                                 "identifiers were entered that match no customer."})
        result["leaked_to_user"] = found(result["response"], result["released"], lookup)
        result["leaked_to_model"] = found(result["llm_input"], lookup=lookup)
        if result["response"] is None:
            result["model_answer"] = None   # a stopped answer is not shown, on either side
        # A request stopped as an attack counts against the session. Three and it is locked:
        # an attacker gets a handful of tries, not thousands.
        stopped = result["stopped_by"] or ""
        if use_hook and "off topic" not in stopped and ("our layer, input" in stopped or "injection" in stopped):
            with LOCK:
                session["flags"].append(time.time())
                if recent(session["flags"]) >= FLAG_LIMIT:
                    session["locked_until"] = time.time() + LOCK_SECONDS
                    result["notes"].append(f"This session is now locked for {LOCK_SECONDS // 60} minutes after "
                                           f"{FLAG_LIMIT} flagged requests.")
        audit(session, event="request", layer=use_hook, stopped_by=result["stopped_by"],
              records_given=result["records_given"], released=len(result["released"]),
              lookup_misses=result.get("lookup_misses", 0), stepped_down=result.get("stepped_down"), notes=result["notes"])
        self.reply(200, result)

    def log_message(self, *args):   # the audit log is the record; keep the console quiet
        pass


if __name__ == "__main__":
    print("Demo running at http://127.0.0.1:8000  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
