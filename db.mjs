import fs from "fs";
import path from "path";

const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), "data");
const USERS_PATH = path.join(DATA_DIR, "users.json");
const EVENTS_PATH = path.join(DATA_DIR, "events.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

function readJson(p, fallback) {
    try {
        return JSON.parse(fs.readFileSync(p, "utf-8"));
    } catch (e) {
        console.error("readJson failed:", p, e?.message || e);
        return fallback;
    }
}

function writeJson(p, obj) {
    const tmp = p + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), "utf-8");
    fs.renameSync(tmp, p);
}

export function upsertUser({ spotify_id, display_name }) {
    const users = readJson(USERS_PATH, {});
    const ts = Date.now();
    const prev = users[spotify_id];

    users[spotify_id] = {
        spotify_id,
        display_name: display_name || "",
        first_seen: prev?.first_seen || ts,
        last_seen: ts,
        playlists_created: prev?.playlists_created || 0,
        playlists_saved: prev?.playlists_saved || 0,
        logins: (prev?.logins || 0) + 1
    };

    writeJson(USERS_PATH, users);

    const events = readJson(EVENTS_PATH, []);
    events.push({ spotify_id, type: "login", meta: "", ts });
    writeJson(EVENTS_PATH, events);
}

export function markPlaylistCreated(spotify_id, meta = "") {
    const users = readJson(USERS_PATH, {});
    const ts = Date.now();
    if (users[spotify_id]) {
        users[spotify_id].playlists_created = (users[spotify_id].playlists_created || 0) + 1;
        users[spotify_id].last_seen = ts;
        writeJson(USERS_PATH, users);
    }
    const events = readJson(EVENTS_PATH, []);
    events.push({ spotify_id, type: "playlist_created", meta, ts });
    writeJson(EVENTS_PATH, events);
}

export function markPlaylistSaved(spotify_id, meta = "") {
    const users = readJson(USERS_PATH, {});
    const ts = Date.now();
    if (users[spotify_id]) {
        users[spotify_id].playlists_saved = (users[spotify_id].playlists_saved || 0) + 1;
        users[spotify_id].last_seen = ts;
        writeJson(USERS_PATH, users);
    }
    const events = readJson(EVENTS_PATH, []);
    events.push({ spotify_id, type: "playlist_saved", meta, ts });
    writeJson(EVENTS_PATH, events);
}

export function getUsers(limit = 200) {
    const usersObj = readJson(USERS_PATH, {});
    const arr = Object.values(usersObj);
    arr.sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));
    return arr.slice(0, limit);
}

export function getStats() {
    const usersObj = readJson(USERS_PATH, {});
    const totalUsers = Object.keys(usersObj).length;

    const events = readJson(EVENTS_PATH, []);
    const totalEvents = events.length;

    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    const active24h = Object.values(usersObj).filter(u => (u.last_seen || 0) >= cutoff).length;

    return { totalUsers, totalEvents, active24h };
}
