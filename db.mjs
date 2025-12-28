import Database from "better-sqlite3";
import fs from "fs";
import path from "path";

// Render kalici disk kullaniyorsan: /var/data tavsiye.
// Yoksa bu proje klasorune yazar (restart/deploy'da silinebilir).
const DB_PATH = process.env.DB_PATH || path.join(process.cwd(), "data", "spotimaker.db");

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  spotify_id TEXT PRIMARY KEY,
  display_name TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  playlists_created INTEGER NOT NULL DEFAULT 0,
  playlists_saved INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  spotify_id TEXT,
  type TEXT NOT NULL,
  meta TEXT,
  ts INTEGER NOT NULL
);
`);

const upsertUserStmt = db.prepare(`
INSERT INTO users (spotify_id, display_name, first_seen, last_seen)
VALUES (@spotify_id, @display_name, @ts, @ts)
ON CONFLICT(spotify_id) DO UPDATE SET
  display_name = excluded.display_name,
  last_seen = excluded.last_seen
`);

const incCreatedStmt = db.prepare(`
UPDATE users SET playlists_created = playlists_created + 1, last_seen = @ts
WHERE spotify_id = @spotify_id
`);

const incSavedStmt = db.prepare(`
UPDATE users SET playlists_saved = playlists_saved + 1, last_seen = @ts
WHERE spotify_id = @spotify_id
`);

const insertEventStmt = db.prepare(`
INSERT INTO events (spotify_id, type, meta, ts)
VALUES (@spotify_id, @type, @meta, @ts)
`);

export function upsertUser({ spotify_id, display_name }) {
  const ts = Date.now();
  upsertUserStmt.run({ spotify_id, display_name: display_name || "", ts });
  insertEventStmt.run({ spotify_id, type: "login", meta: "", ts });
}

export function markPlaylistCreated(spotify_id, meta = "") {
  const ts = Date.now();
  incCreatedStmt.run({ spotify_id, ts });
  insertEventStmt.run({ spotify_id, type: "playlist_created", meta, ts });
}

export function markPlaylistSaved(spotify_id, meta = "") {
  const ts = Date.now();
  incSavedStmt.run({ spotify_id, ts });
  insertEventStmt.run({ spotify_id, type: "playlist_saved", meta, ts });
}

export function getUsers(limit = 200) {
  return db.prepare(`
    SELECT spotify_id, display_name, first_seen, last_seen, playlists_created, playlists_saved
    FROM users
    ORDER BY last_seen DESC
    LIMIT ?
  `).all(limit);
}

export function getStats() {
  const totalUsers = db.prepare(`SELECT COUNT(*) as c FROM users`).get().c;
  const totalEvents = db.prepare(`SELECT COUNT(*) as c FROM events`).get().c;
  const active24h = db.prepare(`SELECT COUNT(*) as c FROM users WHERE last_seen >= ?`).get(Date.now() - 24*60*60*1000).c;
  return { totalUsers, totalEvents, active24h };
}
