"""Demo web app: one prompt, run side by side with the Guard only and with our layer.

    python3 app.py        then open http://127.0.0.1:8000

The page is the React app in web/, served from its built copy in web/dist. After changing
anything under web/src, rebuild it:  cd web && npm install && npm run build

The server itself is standard library only and listens on this machine only.
Each comparison uses four Guard calls.
"""
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pipeline

DIST = (Path(__file__).parent / "web" / "dist").resolve()


def found(text):
    """Plain-language labels of the sensitive values present in text."""
    if not text:
        return []
    labels = {e["label"] for e in pipeline.DB if e["action"] == "redact" and e["regex"].search(text)}
    squashed = pipeline.compact(text)
    labels |= {pipeline.LABELS[name] for value, name, _ in pipeline.KNOWN if value in squashed}
    return sorted(labels)


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/status":
            return self.reply(200, {"guard": pipeline.GUARD_ON, "llm": bool(pipeline.OPENAI_KEY)})
        path = self.path.split("?")[0].lstrip("/") or "index.html"
        file = (DIST / path).resolve()
        if DIST in file.parents and file.is_file():  # only files inside the built app
            self.reply(200, file.read_bytes(), mimetypes.guess_type(file.name)[0] or "application/octet-stream")
        elif not DIST.is_dir():
            self.reply(503, b"The page is not built yet. Run: cd web && npm install && npm run build", "text/plain")
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/run":
            return self.reply(404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 20000)))
            prompt, use_hook = body["prompt"].strip(), bool(body.get("hook"))
        except (ValueError, KeyError, AttributeError, TypeError):
            return self.reply(400, {"error": "Send JSON with a text prompt."})
        if not 0 < len(prompt) <= 4000:  # the Guard's own limit
            return self.reply(400, {"error": "The prompt must be between 1 and 4,000 characters."})
        try:
            result = pipeline.run(prompt, use_hook=use_hook)
        except Exception as e:  # the LLM call failed; the Guard's failures are handled inside run()
            print(f"LLM error: {e!r}")
            return self.reply(502, {"error": "The language model could not be reached. Try again."})
        result["leaked_to_user"] = found(result["response"])
        result["leaked_to_model"] = found(result["llm_input"])
        self.reply(200, result)


if __name__ == "__main__":
    print("Demo running at http://127.0.0.1:8000  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
