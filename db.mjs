// db.mjs (Postgres)
// Bu dosya: upsertUser, markPlaylistCreated, markPlaylistSaved, getUsers, getStats,
// isPremium, countSavedToday, createRedeemCode, redeemCode fonksiyonlarýný export eder.

import pg from "pg";
const { Pool } = pg;

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
    throw new Error("DATABASE_URL env missing");
}

export const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
});

function now() {
    return Date.now();
}

// --- DB init (shell yoksa bile tablo kurulsun) ---
export async function initDb() {
    const sql = `
  create table if not exists users (
    spotify_id text primary key,
    display_name text not null default '',
    first_seen bigint not null,
    last_seen bigint not null,
    playlists_created int not null default 0,
    playlists_saved int not null default 0,
    logins int not null default 0,
    premium_until bigint not null default 0
  );

  create table if not exists events (
    id bigserial primary key,
    spotify_id text not null references users(spotify_id) on delete cascade,
    type text not null,
    ts bigint not null,
    meta jsonb not null default '{}'::jsonb
  );

  create index if not exists idx_events_user_type_ts
  on events (spotify_id, type, ts desc);

  create table if not exists redeem_codes (
    code text primary key,
    created_ts bigint not null,
    expires_ts bigint not null,
    days int not null,
    max_uses int not null,
    used_count int not null default 0,
    note text not null default ''
  );
  `;
    await pool.query(sql);
}

// --- USERS ---
export async function upsertUser({ spotify_id, display_name }) {
    const ts = now();
    const name = String(display_name || "");

    const q = `
    insert into users (spotify_id, display_name, first_seen, last_seen, logins)
    values ($1, $2, $3, $3, 1)
    on conflict (spotify_id) do update
      set display_name = excluded.display_name,
          last_seen = excluded.last_seen,
          logins = users.logins + 1
    returning *;
  `;
    const r = await pool.query(q, [String(spotify_id), name, ts]);
    return r.rows[0];
}

async function getPremiumUntil(spotify_id) {
    const r = await pool.query(
        `select premium_until from users where spotify_id=$1`,
        [String(spotify_id)]
    );
    return Number(r.rows?.[0]?.premium_until || 0);
}

async function setPremiumUntil(spotify_id, premium_until) {
    const r = await pool.query(
        `update users set premium_until=$2 where spotify_id=$1`,
        [String(spotify_id), Number(premium_until || 0)]
    );
    return r.rowCount > 0;
}

export async function isPremium(spotify_id) {
    const until = await getPremiumUntil(spotify_id);
    return until > now();
}

// --- EVENTS / STATS ---
export async function markPlaylistCreated(spotify_id, meta = "") {
    const ts = now();

    await pool.query(
        `update users
     set playlists_created = playlists_created + 1,
         last_seen = $2
     where spotify_id = $1`,
        [String(spotify_id), ts]
    );

    await pool.query(
        `insert into events (spotify_id, type, ts, meta)
     values ($1, 'playlist_created', $2, $3)`,
        [String(spotify_id), ts, { meta }]
    );
}

export async function markPlaylistSaved(spotify_id, meta = "") {
    const ts = now();

    await pool.query(
        `update users
     set playlists_saved = playlists_saved + 1,
         last_seen = $2
     where spotify_id = $1`,
        [String(spotify_id), ts]
    );

    await pool.query(
        `insert into events (spotify_id, type, ts, meta)
     values ($1, 'playlist_saved', $2, $3)`,
        [String(spotify_id), ts, { meta }]
    );
}

export async function getUsers(limit = 200) {
    const lim = Math.max(1, Math.min(1000, Number(limit) || 200));
    const r = await pool.query(
        `select * from users order by last_seen desc limit $1`,
        [lim]
    );
    return r.rows;
}

export async function getStats() {
    const [u, e] = await Promise.all([
        pool.query(`select count(*)::int as n from users`),
        pool.query(`select count(*)::int as n from events`)
    ]);

    const totalUsers = u.rows[0]?.n || 0;
    const totalEvents = e.rows[0]?.n || 0;

    const since24h = now() - 24 * 60 * 60 * 1000;
    const a = await pool.query(
        `select count(*)::int as n from users where last_seen >= $1`,
        [since24h]
    );

    return {
        totalUsers,
        totalEvents,
        active24h: a.rows[0]?.n || 0
    };
}

// MVP: son 3 günü çekip JS'te sayýyoruz (küçük kullanýmda yeterli, stabil)
export async function countSavedToday(spotify_id, timeZone = "Europe/Istanbul") {
    const since = now() - 3 * 24 * 60 * 60 * 1000;
    const r = await pool.query(
        `select ts from events
     where spotify_id=$1 and type='playlist_saved' and ts >= $2
     order by ts desc`,
        [String(spotify_id), since]
    );

    const today = new Date().toLocaleDateString("en-CA", { timeZone });
    let c = 0;
    for (const row of r.rows) {
        const d = new Date(Number(row.ts || 0)).toLocaleDateString("en-CA", { timeZone });
        if (d === today) c++;
    }
    return c;
}

// --- REDEEM CODES ---
function normalizeCode(s) {
    return String(s || "").trim().toUpperCase();
}
function cryptoRandomDigits() {
    return String(Math.floor(100000 + Math.random() * 900000));
}
function cryptoRandomCode() {
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let out = "";
    for (let i = 0; i < 6; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
    return out;
}

export async function createRedeemCode({ days = 30, max_uses = 1, expires_in_days = 365, note = "" } = {}) {
    const code = cryptoRandomCode() + "-" + cryptoRandomDigits();
    const created_ts = now();
    const expires_ts = created_ts + Number(expires_in_days) * 24 * 60 * 60 * 1000;

    const obj = {
        code,
        created_ts,
        expires_ts,
        days: Number(days) || 30,
        max_uses: Number(max_uses) || 1,
        used_count: 0,
        note: String(note || "")
    };

    await pool.query(
        `insert into redeem_codes (code, created_ts, expires_ts, days, max_uses, used_count, note)
     values ($1,$2,$3,$4,$5,0,$6)`,
        [obj.code, obj.created_ts, obj.expires_ts, obj.days, obj.max_uses, obj.note]
    );

    return obj;
}

export async function redeemCode(codeRaw, spotify_id) {
    const code = normalizeCode(codeRaw);
    const ts = now();

    const client = await pool.connect();
    try {
        await client.query("begin");

        const c = await client.query(
            `select * from redeem_codes where code=$1 for update`,
            [code]
        );
        const item = c.rows[0];
        if (!item) {
            await client.query("rollback");
            return { ok: false, error: "Kod bulunamadi" };
        }
        if (Number(item.expires_ts) < ts) {
            await client.query("rollback");
            return { ok: false, error: "Kod suresi dolmus" };
        }
        if (Number(item.used_count) >= Number(item.max_uses)) {
            await client.query("rollback");
            return { ok: false, error: "Kod kullanim limiti dolmus" };
        }

        const u = await client.query(
            `select premium_until from users where spotify_id=$1 for update`,
            [String(spotify_id)]
        );
        if (!u.rows[0]) {
            await client.query("rollback");
            return { ok: false, error: "Kullanici bulunamadi (once Spotify ile giris yap)." };
        }

        const current = Number(u.rows[0].premium_until || 0);
        const base = Math.max(ts, current);
        const addMs = (Number(item.days) || 30) * 24 * 60 * 60 * 1000;
        const newUntil = base + addMs;

        await client.query(
            `update users set premium_until=$2 where spotify_id=$1`,
            [String(spotify_id), newUntil]
        );
        await client.query(
            `update redeem_codes set used_count = used_count + 1 where code=$1`,
            [code]
        );

        await client.query("commit");
        return { ok: true, premium_until: newUntil, days_added: Number(item.days) || 30 };
    } catch (e) {
        await client.query("rollback");
        throw e;
    } finally {
        client.release();
    }
}
