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
        logins: (prev?.logins || 0) + 1,
        premium_until: prev?.premium_until || 0

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
    export function setPremiumUntil(spotify_id, premium_until_ts) {
        const users = readJson(USERS_PATH, {});
        if (!users[spotify_id]) return false;
        users[spotify_id].premium_until = Number(premium_until_ts) || 0;
        writeJson(USERS_PATH, users);
        return true;
    }

    export function isPremium(spotify_id) {
        const users = readJson(USERS_PATH, {});
        const u = users[spotify_id];
        if (!u) return false;
        return Number(u.premium_until || 0) > Date.now();
    }

    export function countSavedToday(spotify_id, timeZone = "Europe/Istanbul") {
        const events = readJson(EVENTS_PATH, []);
        const today = new Date().toLocaleDateString("en-CA", { timeZone }); // YYYY-MM-DD

        let c = 0;
        for (const e of events) {
            if (e.spotify_id !== spotify_id) continue;
            if (e.type !== "playlist_saved") continue;
            const d = new Date(Number(e.ts || 0)).toLocaleDateString("en-CA", { timeZone });
            if (d === today) c++;
        }
        return c;
    }


