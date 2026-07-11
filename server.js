/* Halo Trade — standalone landing page server.
   Zero dependencies: serves the static landing page from /public.
   Runs on Railway (or anywhere Node runs). Nothing here touches the main app. */
import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, "public");
const PORT = process.env.PORT || 3000;

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".webp": "image/webp",
  ".json": "application/json; charset=utf-8",
  ".woff2": "font/woff2",
};

const server = http.createServer((req, res) => {
  // strip query string, prevent path traversal
  let urlPath = decodeURIComponent((req.url || "/").split("?")[0]);
  if (urlPath === "/") urlPath = "/index.html";
  const safePath = path.normalize(path.join(PUBLIC, urlPath)).replace(/^(\.\.[/\\])+/, "");

  // must stay inside PUBLIC
  if (!safePath.startsWith(PUBLIC)) {
    res.writeHead(403); res.end("Forbidden"); return;
  }

  fs.readFile(safePath, (err, data) => {
    if (err) {
      // anything not found falls back to the landing page (single-page site)
      fs.readFile(path.join(PUBLIC, "index.html"), (e2, home) => {
        if (e2) { res.writeHead(404); res.end("Not found"); return; }
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(home);
      });
      return;
    }
    const ext = path.extname(safePath).toLowerCase();
    res.writeHead(200, {
      "Content-Type": TYPES[ext] || "application/octet-stream",
      "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600",
    });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`Halo landing page live on :${PORT}`);
});
