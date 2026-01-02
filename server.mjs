// server.mjs (fixed)

// --- core ---
import express from "express";
import OpenAI from "openai";
import path from "path";
import { fileURLToPath } from "url";
import querystring from "querystring";
import crypto from "crypto";

// --- db (single source of truth) ---
import {
    pool,
    initDb,
    upsertUser,
    markPlaylistCreated,
    markPlaylistSaved,
    getUsers,
    getStats,
    isPremium,
    countSavedToday,
    createRedeemCode,
    redeemCode
} from "./db.mjs";

// --- paths ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- express ---
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- OpenAI client ---
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---- simple in-memory cache for Spotify profile (MVP) ----
const spotifyProfileCache = new Map(); // key: access_token -> { text, ts }
const SPOTIFY_PROFILE_TTL = 15 * 60 * 1000; // 15 min

/* -----------------------------
   Cookie helpers (HttpOnly)
------------------------------ */
function getCookie(req, name) {
    const header = req.headers.cookie || "";
    const parts = header.split(";").map(v => v.trim());
    const found = parts.find(p => p.startsWith(name + "="));
    if (!found) return "";
    return decodeURIComponent(found.split("=").slice(1).join("="));
}

function setCookie(res, name, value, maxAgeMs) {
    const isProd = process.env.NODE_ENV === "production";
    const cookie = [
        `${name}=${encodeURIComponent(value)}`,
        `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        isProd ? "Secure" : ""
    ].filter(Boolean).join("; ");

    const prev = res.getHeader("Set-Cookie");
    if (!prev) res.setHeader("Set-Cookie", cookie);
    else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie]);
    else res.setHeader("Set-Cookie", [prev, cookie]);
}

function clearCookie(res, req, name) {
    const isProd = process.env.NODE_ENV === "production";
    const cookie = [
        `${name}=`,
        "Max-Age=0",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        isProd ? "Secure" : ""
    ].filter(Boolean).join("; ");

    const prev = res.getHeader("Set-Cookie");
    if (!prev) res.setHeader("Set-Cookie", cookie);
    else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie]);
    else res.setHeader("Set-Cookie", [prev, cookie]);
}

/* -----------------------------
   Admin helpers
------------------------------ */
function requireAdmin(req, res) {
    const token = String(req.query.token || req.headers["x-admin-token"] || "");
    if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
        res.status(401).send("Unauthorized");
        return false;
    }
    return true;
}
function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
}

/* -----------------------------
   Utility
------------------------------ */
function normalizeStr(s) {
    return String(s || "")
        .replace(/\s+/g, " ")
        .trim();
}

function buildEnergyCurve(n) {
    const arr = [];
    if (!Number.isFinite(n) || n <= 0) return arr;

    for (let i = 0; i < n; i++) {
        const x = i / Math.max(1, n - 1);
        let v;

        if (x < 0.25) v = 3 + Math.round(3 * (x / 0.25));
        else if (x < 0.70) v = 6 + Math.round(3 * ((x - 0.25) / 0.45));
        else v = 9 - Math.round(4 * ((x - 0.70) / 0.30));

        arr.push(Math.max(1, Math.min(10, v)));
    }
    return arr;
}

/* -----------------------------
   Schemas
------------------------------ */
const playlistSchema = {
    name: "spotimaker_playlist",
    schema: {
        type: "object",
        additionalProperties: false,
        properties: {
            language: { type: "string", enum: ["tr", "en"] },
            title: { type: "string", minLength: 2, maxLength: 60 },
            description: { type: "string", minLength: 5, maxLength: 240 },
            vibe_tags: {
                type: "array",
                minItems: 3,
                maxItems: 3,
                items: { type: "string", minLength: 2, maxLength: 24 }
            },
            tracks: {
                type: "array",
                minItems: 20,
                maxItems: 200,
                items: {
                    type: "object",
                    additionalProperties: false,
                    properties: {
                        artist: { type: "string", minLength: 1, maxLength: 80 },
                        song: { type: "string", minLength: 1, maxLength: 120 }
                    },
                    required: ["artist", "song"]
                }
            }
        },
        required: ["language", "title", "description", "vibe_tags", "tracks"]
    }
};

/* -----------------------------
   Spotify token flow (with refresh)
------------------------------ */
async function refreshSpotifyAccessToken(req, res) {
    const refreshToken = getCookie(req, "spotify_refresh_token");
    if (!refreshToken) return null;

    const clientId = String(process.env.SPOTIFY_CLIENT_ID || "").trim();
    const clientSecret = String(process.env.SPOTIFY_CLIENT_SECRET || "").trim();
    if (!clientId || !clientSecret) return null;

    const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
    const body = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken });

    const r = await fetch("https://accounts.spotify.com/api/token", {
        method: "POST",
        headers: {
            Authorization: `Basic ${basic}`,
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body
    });

    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.access_token) {
        console.error("refresh token failed:", j);
        clearCookie(res, req, "spotify_access_token");
        clearCookie(res, req, "spotify_refresh_token");
        clearCookie(res, req, "spotify_expires_at");
        return null;
    }

    const expiresIn = Number(j.expires_in || 3600);
    const expiresAt = Date.now() + expiresIn * 1000;

    setCookie(res, "spotify_access_token", j.access_token, expiresIn * 1000);
    if (j.refresh_token) {
        setCookie(res, "spotify_refresh_token", j.refresh_token, 365 * 24 * 60 * 60 * 1000);
    }
    setCookie(res, "spotify_expires_at", String(expiresAt), expiresIn * 1000);

    return j.access_token;
}

async function getValidSpotifyToken(req, res) {
    const token = getCookie(req, "spotify_access_token");
    const exp = Number(getCookie(req, "spotify_expires_at") || 0);
    if (token && exp && (exp - Date.now() > 60_000)) return token;
    return await refreshSpotifyAccessToken(req, res);
}

async function requireSpotifyToken(req, res) {
    const token = await getValidSpotifyToken(req, res);
    if (!token) {
        res.status(401).json({ error: "Spotify oturumu yok veya süresi doldu. /login" });
        return null;
    }
    return token;
}

/* -----------------------------
   spotifyFetch wrapper (auto-retry on 401)
------------------------------ */
async function spotifyFetch(req, res, url, options = {}) {
    let token = await getValidSpotifyToken(req, res);
    if (!token) return { ok: false, status: 401, json: { error: "no_token" }, text: null };

    const doReq = async (tk) => {
        const r = await fetch(url, {
            ...options,
            headers: {
                ...(options.headers || {}),
                Authorization: `Bearer ${tk}`,
            }
        });

        const ct = r.headers.get("content-type") || "";
        let data = null;
        if (ct.includes("application/json")) data = await r.json().catch(() => ({}));
        else data = await r.text().catch(() => "");

        return { r, data };
    };

    let { r, data } = await doReq(token);

    if (r.status === 401) {
        const refreshed = await refreshSpotifyAccessToken(req, res);
        if (!refreshed) return { ok: false, status: 401, json: { error: "expired_and_refresh_failed" }, text: null };
        token = refreshed;
        ({ r, data } = await doReq(token));
    }

    return {
        ok: r.ok,
        status: r.status,
        json: typeof data === "string" ? null : data,
        text: typeof data === "string" ? data : null
    };
}

/* -----------------------------
   Spotify helpers
------------------------------ */
async function spotifyMe(req, res) {
    const meRes = await spotifyFetch(req, res, "https://api.spotify.com/v1/me");
    if (!meRes.ok) return { ok: false, me: null, status: meRes.status, details: meRes.json || meRes.text };
    return { ok: true, me: meRes.json, status: 200, details: null };
}

async function spotifyCreatePlaylist(req, res, userId, title, description) {
    const body = JSON.stringify({
        name: title,
        description: description || "",
        public: false
    });

    return await spotifyFetch(req, res, `https://api.spotify.com/v1/users/${encodeURIComponent(userId)}/playlists`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });
}

async function spotifySearchTrack(req, res, q) {
    const url = "https://api.spotify.com/v1/search?" + new URLSearchParams({
        q,
        type: "track",
        limit: "1"
    }).toString();

    const r = await spotifyFetch(req, res, url);
    if (!r.ok) return null;

    const item = r.json?.tracks?.items?.[0];
    if (!item?.uri) return null;
    return { uri: item.uri, id: item.id, name: item.name, artist: item.artists?.[0]?.name || "" };
}

async function spotifyAddTracks(req, res, playlistId, uris) {
    const chunks = [];
    for (let i = 0; i < uris.length; i += 100) chunks.push(uris.slice(i, i + 100));

    for (const chunk of chunks) {
        const r = await spotifyFetch(req, res, `https://api.spotify.com/v1/playlists/${encodeURIComponent(playlistId)}/tracks`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ uris: chunk })
        });
        if (!r.ok) return r;
    }
    return { ok: true, status: 200, json: { ok: true } };
}

async function getSpotifyMeId(req, res) {
    const { ok, me } = await spotifyMe(req, res);
    if (!ok || !me?.id) return "";
    return String(me.id);
}

/* -----------------------------
   ROUTES
------------------------------ */

// Home
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Health/db sanity (admin)
app.get("/api/admin/db-check", async (req, res) => {
    try {
        if (!requireAdmin(req, res)) return;

        await initDb();
        const stats = await getStats();
        const db = await pool.query("select current_database() as db, now() as now");
        res.json({ ok: true, stats, db: db.rows[0] });
    } catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

// Spotify OAuth start
app.get("/login", (req, res) => {
    try {
        const state = crypto.randomBytes(12).toString("hex");
        setCookie(res, "spotify_state", state, 10 * 60 * 1000);

        const scope = [
            "user-read-private",
            "user-read-email",
            "user-top-read",
            "playlist-modify-public",
            "playlist-modify-private"
        ].join(" ");

        const redirectUri = String(process.env.SPOTIFY_REDIRECT_URI || "").trim();
        const clientId = String(process.env.SPOTIFY_CLIENT_ID || "").trim();

        if (!clientId || !redirectUri) {
            console.error("Spotify ENV eksik:", {
                SPOTIFY_CLIENT_ID: !!clientId,
                SPOTIFY_REDIRECT_URI: !!redirectUri
            });
            return res.status(500).send("Sunucu ayarı eksik: CLIENT_ID / REDIRECT_URI yok.");
        }

        const force = String(req.query.force || "") === "1";

        const params = querystring.stringify({
            show_dialog: force ? "true" : "false",
            response_type: "code",
            client_id: clientId,
            scope,
            redirect_uri: redirectUri,
            state
        });

        return res.redirect(`https://accounts.spotify.com/authorize?${params}`);
    } catch (e) {
        console.error("/login crashed:", e);
        return res.status(500).send("Spotify giriş başlatılırken hata: " + (e?.message || String(e)));
    }
});

// Spotify OAuth callback
app.get("/callback", async (req, res) => {
    try {
        const code = String(req.query.code || "");
        const state = String(req.query.state || "");
        const savedState = getCookie(req, "spotify_state");

        if (!code) return res.status(400).send("No code");
        if (!state || !savedState || state !== savedState) return res.status(400).send("Invalid state");

        const redirectUri = String(process.env.SPOTIFY_REDIRECT_URI || "").trim();

        const body = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri
        });

        const auth = Buffer.from(
            process.env.SPOTIFY_CLIENT_ID + ":" + process.env.SPOTIFY_CLIENT_SECRET
        ).toString("base64");

        const tokenRes = await fetch("https://accounts.spotify.com/api/token", {
            method: "POST",
            headers: {
                Authorization: `Basic ${auth}`,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body
        });

        const data = await tokenRes.json();
        if (!tokenRes.ok) {
            console.error("Spotify token error:", data);
            return res.status(500).send("Token exchange failed");
        }

        // user upsert (IMPORTANT: await)
        try {
            const meRes = await fetch("https://api.spotify.com/v1/me", {
                headers: { Authorization: `Bearer ${data.access_token}` }
            });
            const me = await meRes.json();
            if (me?.id) {
                await upsertUser({ spotify_id: me.id, display_name: me.display_name });
                console.log("LOGIN_EVENT", { spotify_id: me.id, display_name: me.display_name || null, time: new Date().toISOString() });
            }
        } catch (e) {
            console.error("upsertUser failed:", e);
        }

        clearCookie(res, req, "spotify_state");

        const expiresIn = Number(data.expires_in || 3600);
        const expiresAt = Date.now() + expiresIn * 1000;

        setCookie(res, "spotify_access_token", data.access_token, expiresIn * 1000);
        if (data.refresh_token) setCookie(res, "spotify_refresh_token", data.refresh_token, 365 * 24 * 60 * 60 * 1000);
        setCookie(res, "spotify_expires_at", String(expiresAt), expiresIn * 1000);

        return res.redirect("/");
    } catch (err) {
        console.error(err);
        return res.status(500).send("Callback failed");
    }
});

// Logout
app.get("/logout", (req, res) => {
    try {
        clearCookie(res, req, "spotify_access_token");
        clearCookie(res, req, "spotify_refresh_token");
        clearCookie(res, req, "spotify_expires_at");
        clearCookie(res, req, "spotify_state");
        return res.redirect(302, "/");
    } catch (e) {
        console.error("logout failed:", e);
        return res.redirect(302, "/");
    }
});

// Switch account (force dialog)
app.get("/switch-account", (req, res) => {
    try {
        clearCookie(res, req, "spotify_access_token");
        clearCookie(res, req, "spotify_refresh_token");
        clearCookie(res, req, "spotify_expires_at");
        clearCookie(res, req, "spotify_state");
        return res.redirect(302, "/login?force=1");
    } catch (e) {
        console.error("switch-account failed:", e);
        return res.redirect(302, "/login?force=1");
    }
});

// Debug cookies
app.get("/debug/cookies", (req, res) => {
    res.json({
        hostname: req.hostname,
        cookieHeader: req.headers.cookie || "",
        accessTokenPresent: Boolean(getCookie(req, "spotify_access_token")),
        refreshTokenPresent: Boolean(getCookie(req, "spotify_refresh_token")),
        expiresAt: Number(getCookie(req, "spotify_expires_at") || 0),
        statePresent: Boolean(getCookie(req, "spotify_state"))
    });
});

// Spotify status (single source of truth)
app.get("/api/spotify/status", async (req, res) => {
    try {
        const token = await getValidSpotifyToken(req, res);
        if (!token) return res.json({ connected: false, reason: "no_token" });

        const r = await fetch("https://api.spotify.com/v1/me", {
            headers: { Authorization: `Bearer ${token}` }
        });

        if (r.status === 401) return res.json({ connected: false, reason: "expired_token" });
        if (r.status === 403) return res.json({ connected: false, reason: "insufficient_scope" });
        if (!r.ok) return res.json({ connected: false, reason: "spotify_error", status: r.status });

        const me = await r.json();
        return res.json({
            connected: true,
            user: { id: me.id, name: me.display_name },
            premium: await isPremium(me.id)
        });
    } catch (e) {
        return res.json({ connected: false, reason: "exception", message: String(e?.message || e) });
    }
});

// /api/me
app.get("/api/me", async (req, res) => {
    try {
        let token = await getValidSpotifyToken(req, res);
        if (!token) return res.status(200).json({ ok: false, reason: "no_token" });

        let r = await fetch("https://api.spotify.com/v1/me", {
            headers: { Authorization: `Bearer ${token}` }
        });

        let data = await r.json().catch(() => ({}));

        if (r.status === 401) {
            const refreshed = await refreshSpotifyAccessToken(req, res);
            if (refreshed) {
                token = refreshed;
                r = await fetch("https://api.spotify.com/v1/me", {
                    headers: { Authorization: `Bearer ${token}` }
                });
                data = await r.json().catch(() => ({}));
            }
        }

        if (!r.ok) {
            return res.status(200).json({ ok: false, status: r.status, spotify_error: data });
        }

        const premium = await isPremium(data.id);

        return res.status(200).json({
            ok: true,
            me: { id: data.id, display_name: data.display_name },
            premium
        });
    } catch (e) {
        return res.status(200).json({ ok: false, reason: "exception", message: String(e?.message || e) });
    }
});

// Spotify top helper endpoint
app.get("/spotify/top", async (req, res) => {
    try {
        const token = await requireSpotifyToken(req, res);
        if (!token) return;

        const timeRange = String(req.query.time_range || "short_term");

        const [tracksRes, artistsRes] = await Promise.all([
            fetch(`https://api.spotify.com/v1/me/top/tracks?limit=10&time_range=${timeRange}`, {
                headers: { Authorization: `Bearer ${token}` }
            }),
            fetch(`https://api.spotify.com/v1/me/top/artists?limit=10&time_range=${timeRange}`, {
                headers: { Authorization: `Bearer ${token}` }
            })
        ]);

        const tracksJson = await tracksRes.json();
        const artistsJson = await artistsRes.json();

        if (!tracksRes.ok) return res.status(500).json({ error: "Top tracks failed", details: tracksJson });
        if (!artistsRes.ok) return res.status(500).json({ error: "Top artists failed", details: artistsJson });

        const topTracks = (tracksJson.items || []).map(t => `${t.name} - ${t.artists?.[0]?.name || ""}`.trim());
        const topArtists = (artistsJson.items || []).map(a => a.name);

        return res.json({ time_range: timeRange, topTracks, topArtists });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Spotify top fetch failed" });
    }
});

// Debug spotify
app.get("/debug/spotify", async (req, res) => {
    const token = await getValidSpotifyToken(req, res);
    if (!token) return res.status(401).json({ error: "Spotify not connected" });

    try {
        const meRes = await fetch("https://api.spotify.com/v1/me", {
            headers: { Authorization: `Bearer ${token}` }
        });
        const me = await meRes.json();

        const tracksRes = await fetch("https://api.spotify.com/v1/me/top/tracks?limit=3&time_range=short_term", {
            headers: { Authorization: `Bearer ${token}` }
        });
        const tracks = await tracksRes.json();

        return res.json({
            ok: true,
            me: { id: me.id, display_name: me.display_name },
            premium: await isPremium(String(me.id || "")),
            sampleTopTracks: (tracks?.items || []).slice(0, 3).map(
                t => `${t.name} - ${t.artists?.[0]?.name || ""}`.trim()
            )
        });
    } catch (e) {
        console.error(e);
        return res.json({ ok: false, error: String(e) });
    }
});

/* -----------------------------
   AI generate
------------------------------ */
app.post("/api/generate", async (req, res) => {
    const userText = String(req.body?.text ?? "").trim();
    if (!userText) return res.status(400).json({ error: "Missing text" });

    try {
        const spotifyToken = await getValidSpotifyToken(req, res);
        let spotifyProfileText = "";

        // 1) Spotify profile text (optional)
        if (spotifyToken) {
            const cached = spotifyProfileCache.get(spotifyToken);
            const now = Date.now();

            if (cached && (now - cached.ts) < SPOTIFY_PROFILE_TTL) {
                spotifyProfileText = cached.text;
            } else {
                try {
                    const [topTracksRes, topArtistsRes] = await Promise.all([
                        spotifyFetch(req, res, "https://api.spotify.com/v1/me/top/tracks?limit=5&time_range=short_term"),
                        spotifyFetch(req, res, "https://api.spotify.com/v1/me/top/artists?limit=5&time_range=short_term")
                    ]);

                    if (topTracksRes.ok && topArtistsRes.ok) {
                        const tracksJson = topTracksRes.json;
                        const artistsJson = topArtistsRes.json;

                        const topTracksText = (tracksJson.items || [])
                            .map(t => `${t.name} by ${t.artists?.[0]?.name || ""}`)
                            .join(", ");

                        const topArtistsText = (artistsJson.items || [])
                            .map(a => a.name)
                            .join(", ");

                        spotifyProfileText = `
User listening profile:
Top artists: ${topArtistsText}
Top tracks: ${topTracksText}

Use this profile to personalize the playlist.
`.trim();

                        spotifyProfileCache.set(spotifyToken, { text: spotifyProfileText, ts: now });
                    }
                } catch (e) {
                    console.error("Spotify profile fetch failed", e);
                }
            }
        }

        // 2) Count + premium/free limit
        const requestedCountRaw = Number(req.body?.count ?? 20);
        let requestedCount = Math.max(20, Math.min(200, Number.isFinite(requestedCountRaw) ? requestedCountRaw : 20));

        let premium = false;
        try {
            if (spotifyToken) {
                const meRes = await spotifyFetch(req, res, "https://api.spotify.com/v1/me");
                if (meRes.ok && meRes.json?.id) premium = await isPremium(meRes.json.id);
            }
        } catch (e) {
            console.error("premium check failed", e);
        }

        const hardMax = premium ? 200 : 40;
        requestedCount = Math.max(20, Math.min(hardMax, requestedCount));

        // 3) Prompts
        const systemPrompt = `
You are an expert music curator and playlist designer.
You deeply understand mood, emotion, tempo, and how music guides feelings over time.

STRICT RULES:
- You will be given requested_count.
- You MUST return exactly requested_count tracks.
- Follow the user's mood, energy, language, and era strictly.
- If the user provides example songs or artists, include at least one of them in the playlist.
- Match the overall vibe to the examples given.
- Avoid generic or unrelated songs.
- Use plain ASCII characters only.
- Output MUST be valid JSON only, matching the provided schema.
- Do not invent fake songs. Prefer widely available tracks.
- Avoid repeating the same artist more than 2 times.

Language rule:
- If the user writes in Turkish, set language="tr" and write title+description in Turkish.
- If the user writes in English, set language="en" and write title+description in English.
- Do not mix languages in title/description.

Emotional arc rule:
- Tracks 1-5: ease-in / set the mood
- Tracks 6-15: main emotional peak
- Tracks 16-20: resolution based on user input

IMPORTANT:
Use plain ASCII characters only.
Do not use smart quotes, special punctuation, or non-ASCII symbols.
Use simple apostrophes and standard characters only.

${spotifyProfileText}
`.trim();

        const userPrompt = `User request: ${userText}\nrequested_count: ${requestedCount}`;

        // 4) Schema exact count
        const exactSchema = structuredClone(playlistSchema);
        exactSchema.schema.properties.tracks.minItems = requestedCount;
        exactSchema.schema.properties.tracks.maxItems = requestedCount;

        // 5) OpenAI call
        const response = await client.responses.create({
            model: "gpt-5-mini",
            input: [
                { role: "system", content: systemPrompt },
                { role: "user", content: userPrompt }
            ],
            text: {
                format: {
                    type: "json_schema",
                    name: playlistSchema.name,
                    schema: exactSchema.schema,
                    strict: true
                }
            }
        });

        const jsonText = response.output_text;
        const data = JSON.parse(jsonText);

        data.energy_curve = buildEnergyCurve(data.tracks?.length || requestedCount);

        // admin stats: playlist_created (only if Spotify is connected)
        try {
            if (spotifyToken) {
                const meId = await getSpotifyMeId(req, res);
                if (meId) await markPlaylistCreated(meId, `count=${requestedCount}`);
            }
        } catch (e) {
            console.error("markPlaylistCreated failed:", e);
        }

        res.setHeader("Content-Type", "application/json; charset=utf-8");
        return res.json(data);
    } catch (e) {
        console.error("generate crash:", e);
        return res.status(500).json({ error: String(e?.message || e) });
    }
});

/* -----------------------------
   Save playlist to Spotify
------------------------------ */
async function saveSpotifyPlaylist(req, res) {
    try {
        const token = await requireSpotifyToken(req, res);
        if (!token) return;

        const meInfo = await spotifyMe(req, res);
        if (!meInfo.ok) return res.status(401).json({ error: "Spotify /me failed" });
        const me = meInfo.me;

        const premium = await isPremium(String(me.id || ""));

        try {
            if (!premium) {
                const used = await countSavedToday(String(me.id || ""));
                if (used >= 1) console.log("FREE_SAVE_LIMIT_WARNING", { me: me.id, used });
            }
        } catch (e) {
            console.error("countSavedToday failed:", e);
        }

        const body = req.body || {};
        const title = normalizeStr(body.title || body.name || "Spotimaker Playlist");
        const description = normalizeStr(body.description || "");
        const tracks = Array.isArray(body.tracks) ? body.tracks : [];

        if (!tracks.length) return res.status(400).json({ error: "Missing tracks" });

        // Create Spotify playlist
        const created = await spotifyCreatePlaylist(req, res, me.id, title, description);
        if (!created.ok) {
            console.error("create playlist failed:", created.json || created.text);
            return res.status(500).json({ error: "create playlist failed", details: created.json || created.text });
        }

        const playlistId = created.json?.id;
        if (!playlistId) return res.status(500).json({ error: "create playlist returned no id" });

        // Build track URIs
        const uris = [];
        for (const t of tracks) {
            const artist = normalizeStr(t?.artist);
            const song = normalizeStr(t?.song);
            if (!artist || !song) continue;

            const q = `track:${song} artist:${artist}`;
            const hit = await spotifySearchTrack(req, res, q);
            if (hit?.uri) uris.push(hit.uri);
        }

        if (!uris.length) {
            return res.status(400).json({ error: "No Spotify matches found for provided tracks" });
        }

        const addRes = await spotifyAddTracks(req, res, playlistId, uris);
        if (!addRes.ok) {
            console.error("add tracks failed:", addRes.json || addRes.text);
            return res.status(500).json({ error: "add tracks failed", details: addRes.json || addRes.text });
        }

        try {
            await markPlaylistSaved(me.id, `added=${uris.length}`);
        } catch (e) {
            console.error("markPlaylistSaved failed:", e);
        }

        return res.json({
            ok: true,
            playlistId,
            url: created.json?.external_urls?.spotify || null,
            added: uris.length,
            premium
        });
    } catch (e) {
        console.error("saveSpotifyPlaylist crash:", e);
        return res.status(500).json({ error: String(e?.message || e) });
    }
}

app.post("/spotify/save", saveSpotifyPlaylist);
app.post("/api/spotify/save", saveSpotifyPlaylist);

// DB tables sanity
app.get("/api/debug/db", async (req, res) => {
    try {
        const r = await pool.query(`select to_regclass('public.users') as users,
                                       to_regclass('public.events') as events,
                                       to_regclass('public.redeem_codes') as redeem_codes`);
        res.json({ ok: true, tables: r.rows[0] });
    } catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

/* -----------------------------
   Redeem + admin
------------------------------ */

// Admin: hediye kodu üret
app.post("/api/admin/codes/create", async (req, res) => {
    try {
        if (!requireAdmin(req, res)) return;

        const days = Number(req.body?.days ?? 30);
        const max_uses = Number(req.body?.max_uses ?? 1);
        const note = String(req.body?.note ?? "");

        const codeObj = await createRedeemCode({ days, max_uses, note });

        return res.json({
            ok: true,
            code: codeObj?.code || null,
            meta: codeObj || null
        });
    } catch (e) {
        console.error("codes/create failed:", e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

// Kullanıcı redeem
app.post("/api/redeem", async (req, res) => {
    try {
        const spotify_id = await getSpotifyMeId(req, res);
        if (!spotify_id) return res.status(401).json({ ok: false, error: "Once Spotify’a giris yap." });

        const code = String(req.body?.code || "");
        const result = await redeemCode(code, spotify_id);

        if (!result.ok) return res.status(400).json(result);
        return res.json({ ok: true, premium_until: result.premium_until, days_added: result.days_added });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

// Debug users (admin)
app.get("/api/debug/users", async (req, res) => {
    try {
        if (!requireAdmin(req, res)) return;
        const stats = await getStats();
        const users = await getUsers(20);
        return res.json({ stats, users });
    } catch (e) {
        console.error("DEBUG USERS ERROR:", e);
        return res.status(500).json({ error: "debug users crashed" });
    }
});

// Admin panel
app.get("/admin", async (req, res) => {
    try {
        if (!requireAdmin(req, res)) return;

        const stats = await getStats();
        const users = await getUsers(200);

        const row = (u) => `
      <tr>
        <td>${escapeHtml(u.display_name || "")}</td>
        <td>${escapeHtml(u.spotify_id || "")}</td>
        <td>${u.first_seen ? new Date(u.first_seen).toLocaleString() : ""}</td>
        <td>${u.last_seen ? new Date(u.last_seen).toLocaleString() : ""}</td>
        <td style="text-align:right">${Number(u.playlists_created || 0)}</td>
        <td style="text-align:right">${Number(u.playlists_saved || 0)}</td>
        <td style="text-align:right">${Number(u.logins || 0)}</td>
      </tr>
    `;

        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Spotimaker Admin</title>
  <style>
    body{font-family:system-ui,Arial;margin:24px}
    .cards{display:flex;gap:16px;margin:16px 0}
    .card{padding:12px 14px;border:1px solid #ddd;border-radius:10px;min-width:160px}
    table{border-collapse:collapse;width:100%;margin-top:16px}
    th,td{border:1px solid #eee;padding:8px 10px;font-size:14px}
    th{text-align:left;background:#fafafa}
  </style>
</head>
<body>
  <h1>Spotimaker Admin</h1>
  <div class="cards">
    <div class="card"><b>Total users</b><div>${stats.totalUsers ?? 0}</div></div>
    <div class="card"><b>Active 24h</b><div>${stats.active24h ?? 0}</div></div>
    <div class="card"><b>Total events</b><div>${stats.totalEvents ?? 0}</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Name</th><th>Spotify ID</th><th>First seen</th><th>Last seen</th>
        <th>Created</th><th>Saved</th><th>Logins</th>
      </tr>
    </thead>
    <tbody>
      ${(Array.isArray(users) ? users : []).map(row).join("")}
    </tbody>
  </table>
</body>
</html>`);
    } catch (e) {
        console.error("ADMIN ERROR:", e);
        return res.status(500).send("Admin crashed. Check logs.");
    }
});

// Static LAST
app.use(express.static(path.join(__dirname, "public")));

// Boot
const port = process.env.PORT || 8787;
await initDb();

app.listen(port, () => {
    console.log(`Spotimaker running on http://localhost:${port}`);
});
