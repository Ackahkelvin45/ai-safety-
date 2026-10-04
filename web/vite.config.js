import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies the API routes to app.py; `npm run build` writes dist/, which app.py serves.
export default defineConfig({
  plugins: [react()],
  server: { proxy: Object.fromEntries(["/run", "/status", "/login", "/logout", "/settings"].map((path) => [path, "http://127.0.0.1:8000"])) },
});
