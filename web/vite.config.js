import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies the two API routes to app.py; `npm run build` writes dist/, which app.py serves.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/run": "http://127.0.0.1:8000", "/status": "http://127.0.0.1:8000" } },
});
