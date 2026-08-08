import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import path from "node:path";

const MAX_CHUNK_BYTES = 48 * 1024;
const MAX_QUERY_TERMS = 24;

function stateRoot() {
  const configured = process.env.CONTEXT_MODE_DIR;
  if (typeof configured !== "string" || configured.length === 0 || !path.isAbsolute(configured)) {
    throw new Error("CONTEXT_MODE_DIR must be an absolute run-local directory");
  }
  mkdirSync(configured, { recursive: true, mode: 0o700 });
  chmodSync(configured, 0o700);
  return path.resolve(configured);
}

function utf8Prefix(text, byteLimit) {
  const raw = Buffer.from(text, "utf8");
  if (raw.length <= byteLimit) return text;
  let end = byteLimit;
  let value = raw.subarray(0, end).toString("utf8");
  while (Buffer.byteLength(value, "utf8") > byteLimit) {
    end -= 1;
    value = raw.subarray(0, end).toString("utf8");
  }
  return value;
}

function splitContent(content) {
  const normalized = content.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
  const sections = normalized.split(/(?=^#{1,6}\s+)/m);
  const chunks = [];
  for (const section of sections) {
    if (!section) continue;
    let remaining = section;
    while (Buffer.byteLength(remaining, "utf8") > MAX_CHUNK_BYTES) {
      let candidate = utf8Prefix(remaining, MAX_CHUNK_BYTES);
      const boundary = Math.max(candidate.lastIndexOf("\n\n"), candidate.lastIndexOf("\n"));
      if (boundary > MAX_CHUNK_BYTES / 3) candidate = candidate.slice(0, boundary + 1);
      chunks.push(candidate);
      remaining = remaining.slice(candidate.length);
    }
    if (remaining) chunks.push(remaining);
  }
  return chunks.length === 0 ? [""] : chunks;
}

function titleFor(chunk, index) {
  const heading = chunk.match(/^#{1,6}\s+(.+)$/m)?.[1]?.trim();
  return heading ? utf8Prefix(heading, 240) : `section ${index + 1}`;
}

function terms(value) {
  return [...new Set(value.normalize("NFKC").toLowerCase().match(/[\p{L}\p{N}_-]{2,}/gu) ?? [])]
    .slice(0, MAX_QUERY_TERMS);
}

function ftsExpression(value) {
  const words = terms(value).map((word) => `"${word.replaceAll('"', '""')}"`);
  return words.join(" OR ");
}

function trigramExpression(value) {
  const word = terms(value).find((candidate) => [...candidate].length >= 3);
  return word ? `"${word.replaceAll('"', '""')}"` : "";
}

export class LocalStore {
  constructor() {
    this.root = stateRoot();
    this.databasePath = path.join(this.root, "context.sqlite3");
    this.db = new Database(this.databasePath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.pragma("foreign_keys = ON");
    this.db.pragma("trusted_schema = OFF");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY,
        source TEXT NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL
      );
      CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
        source UNINDEXED,
        title,
        body,
        tokenize='porter unicode61'
      );
      CREATE VIRTUAL TABLE IF NOT EXISTS documents_tri USING fts5(
        source UNINDEXED,
        title,
        body,
        tokenize='trigram'
      );
      CREATE TABLE IF NOT EXISTS counters (
        name TEXT PRIMARY KEY,
        value INTEGER NOT NULL CHECK(value >= 0)
      );
    `);
    this.insertDocument = this.db.prepare(
      "INSERT INTO documents(source,title,body,content_sha256,created_at_ms) VALUES(?,?,?,?,?)",
    );
    this.insertPorter = this.db.prepare(
      "INSERT INTO documents_fts(rowid,source,title,body) VALUES(?,?,?,?)",
    );
    this.insertTrigram = this.db.prepare(
      "INSERT INTO documents_tri(rowid,source,title,body) VALUES(?,?,?,?)",
    );
    this.bumpCounter = this.db.prepare(`
      INSERT INTO counters(name,value) VALUES(?,?)
      ON CONFLICT(name) DO UPDATE SET value=value+excluded.value
    `);
    this.insertAll = this.db.transaction((content, source, createdAt) => {
      const chunks = splitContent(content);
      for (const [index, body] of chunks.entries()) {
        const title = titleFor(body, index);
        const digest = createHash("sha256").update(body).digest("hex");
        const result = this.insertDocument.run(source, title, body, digest, createdAt);
        this.insertPorter.run(result.lastInsertRowid, source, title, body);
        this.insertTrigram.run(result.lastInsertRowid, source, title, body);
      }
      this.bumpCounter.run("indexed_bytes", Buffer.byteLength(content, "utf8"));
      this.bumpCounter.run("indexed_documents", 1);
      return chunks.length;
    });
  }

  index(content, source) {
    if (typeof content !== "string") throw new Error("index content must be text");
    if (typeof source !== "string" || source.length === 0 || Buffer.byteLength(source) > 512) {
      throw new Error("index source must be a bounded non-empty label");
    }
    const indexedBytes = Buffer.byteLength(content, "utf8");
    const chunks = this.insertAll(content, source, Date.now());
    return { chunks, indexedBytes, source };
  }

  searchOne(query, { limit = 3, source } = {}) {
    const expression = ftsExpression(query);
    if (!expression) return [];
    const boundedLimit = Math.max(1, Math.min(10, Number(limit) || 3));
    const sourceClause = source ? " AND source LIKE ?" : "";
    const sql = `
      SELECT rowid AS id, source, title,
             snippet(documents_fts, 2, '[', ']', ' … ', 28) AS snippet,
             bm25(documents_fts, 0.0, 5.0, 1.0) AS rank
      FROM documents_fts
      WHERE documents_fts MATCH ?${sourceClause}
      ORDER BY rank
      LIMIT ?
    `;
    const args = source
      ? [expression, `%${source}%`, boundedLimit]
      : [expression, boundedLimit];
    const porterRows = this.db.prepare(sql).all(...args);
    const merged = new Map(porterRows.map((row, index) => [row.id, { ...row, score: 1 / (60 + index) }]));
    const tri = trigramExpression(query);
    if (tri) {
      const triSql = `
        SELECT rowid AS id, source, title,
               snippet(documents_tri, 2, '[', ']', ' … ', 28) AS snippet,
               bm25(documents_tri, 0.0, 5.0, 1.0) AS rank
        FROM documents_tri
        WHERE documents_tri MATCH ?${sourceClause}
        ORDER BY rank
        LIMIT ?
      `;
      const triArgs = source ? [tri, `%${source}%`, boundedLimit] : [tri, boundedLimit];
      for (const [index, row] of this.db.prepare(triSql).all(...triArgs).entries()) {
        const previous = merged.get(row.id);
        merged.set(row.id, {
          ...(previous ?? row),
          score: (previous?.score ?? 0) + 1 / (60 + index),
        });
      }
    }
    return [...merged.values()]
      .sort((left, right) => right.score - left.score || left.id - right.id)
      .slice(0, boundedLimit);
  }

  stats() {
    const document = this.db.prepare("SELECT COUNT(*) AS count, COALESCE(SUM(length(CAST(body AS BLOB))),0) AS bytes FROM documents").get();
    const counters = Object.fromEntries(
      this.db.prepare("SELECT name,value FROM counters ORDER BY name").all().map((row) => [row.name, row.value]),
    );
    return {
      chunks: Number(document.count),
      storedBytes: Number(document.bytes),
      counters,
      sqliteVersion: this.db.prepare("SELECT sqlite_version() AS version").get().version,
    };
  }

  recent(limit = 12, sourcePrefix = "memory:") {
    const boundedLimit = Math.max(1, Math.min(64, Number(limit) || 12));
    return this.db.prepare(`
      SELECT source,title,body,created_at_ms AS createdAtMs
      FROM documents
      WHERE source LIKE ?
      ORDER BY id DESC
      LIMIT ?
    `).all(`${sourcePrefix}%`, boundedLimit);
  }

  purge() {
    const before = this.stats();
    this.db.transaction(() => {
      this.db.exec("DELETE FROM documents; DELETE FROM documents_fts; DELETE FROM documents_tri; DELETE FROM counters;");
    })();
    return before;
  }

  close() {
    if (this.db.open) this.db.close();
  }
}

let singleton;

export function getStore() {
  singleton ??= new LocalStore();
  return singleton;
}

export function closeStore() {
  singleton?.close();
  singleton = undefined;
}
