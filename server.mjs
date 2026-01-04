// server.mjs (RESTORED + FIXED OAuth STATE + CLEAN REDIRECTS)

import express from "express";
import OpenAI from "openai";
import path from "path";
import { fileURLToPath } from "url";
import querystring from "querystring";
import crypto from "crypto";
import dns from "node:dns";

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
    grantPremium,
    countSavedToday,
    createRedeemCode,
    redeemCode,
    saveFeedback,
    getFeedbackMessages,
    dbEnabled,
} from "./db.mjs";

// Render/IPv6 timeout sorunlarına karşı
try {
    dns.setDefaultResultOrder("ipv4first");
} catch (_) { }

// --- paths ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- express ---
const app = express();

// JSON parser (webhook hariç)
const jsonParser = express.json();
const urlEncodedParser = express.urlencoded({ extended: true });
app.use((req, res, next) => {
    if (req.originalUrl.startsWith("/api/billing/webhook")) return next();
    jsonParser(req, res, (err) => {
        if (err) return next(err);
        urlEncodedParser(req, res, next);
    });
});

// Render reverse proxy
app.enable("trust proxy");

/**
 * ✅ Redirect middleware (tek yerde)
 * - HTTPS zorla
 * - İstersen CANONICAL_HOST zorla (PUBLIC_HOST env ile)
 *
 * NOT: PUBLIC_HOST boşsa canonical zorlama yapma.
 * Bu sayede "onrenderder" gibi typo host'a redirect etmez.
 */
const CANONICAL_HOST = String(process.env.PUBLIC_HOST || "").trim();

app.use((req, res, next) => {
    const host = String(req.headers.host || "");
    const xfProto = String(req.headers["x-forwarded-proto"] || "").toLowerCase();
    const isHttps = req.secure || xfProto === "https";

    // Canonical host zorlaması (opsiyonel)
    if (CANONICAL_HOST && host && host !== CANONICAL_HOST) {
        return res.redirect(302, `https://${CANONICAL_HOST}${req.originalUrl}`);
    }

    // Production'da HTTP -> HTTPS
    if (process.env.NODE_ENV === "production" && !isHttps) {
        const h = CANONICAL_HOST || host;
        return res.redirect(302, `https://${h}${req.originalUrl}`);
    }

    next();
});

// --- OpenAI client ---
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---- simple in-memory cache for Spotify profile (MVP) ----
const spotifyProfileCache = new Map(); // key: access_token -> { text, ts }
const SPOTIFY_PROFILE_TTL = 15 * 60 * 1000; // 15 min

// ---- premium intent cache (per user, ephemeral) ----
const intentPlanCache = new Map(); // key: spotify_user_id -> { plan, text, count, ts }
const INTENT_PLAN_TTL = 30 * 60 * 1000; // 30 min
const STRIPE_SECRET_KEY = String(process.env.STRIPE_SECRET_KEY || "").trim();
const STRIPE_PRICE_ID = String(process.env.STRIPE_PRICE_ID || "").trim();
const STRIPE_WEBHOOK_SECRET = String(process.env.STRIPE_WEBHOOK_SECRET || "").trim();

async function getSpotifyProfileText(req, res, spotifyToken) {
    if (!spotifyToken) return "";

    const cached = spotifyProfileCache.get(spotifyToken);
    const now = Date.now();

    if (cached && now - cached.ts < SPOTIFY_PROFILE_TTL) {
        return cached.text;
    }

    try {
        const [topTracksRes, topArtistsRes] = await Promise.all([
            spotifyFetch(req, res, "https://api.spotify.com/v1/me/top/tracks?limit=5&time_range=short_term"),
            spotifyFetch(req, res, "https://api.spotify.com/v1/me/top/artists?limit=5&time_range=short_term"),
        ]);

        if (topTracksRes.ok && topArtistsRes.ok) {
            const tracksJson = topTracksRes.json;
            const artistsJson = topArtistsRes.json;

            const topTracksText = (tracksJson.items || [])
                .map((t) => `${t.name} by ${t.artists?.[0]?.name || ""}`)
                .join(", ");

            const topArtistsText = (artistsJson.items || []).map((a) => a.name).join(", ");

            const spotifyProfileText = `
User listening profile:
Top artists: ${topArtistsText}
Top tracks: ${topTracksText}
`.trim();

            spotifyProfileCache.set(spotifyToken, { text: spotifyProfileText, ts: now });
            return spotifyProfileText;
        }
    } catch (e) {
        console.error("Spotify profile fetch failed", e);
    }

    return "";
}

/* -----------------------------
   Cookie helpers (HttpOnly)
------------------------------ */
function getCookie(req, name) {
    const header = req.headers.cookie || "";
    const parts = header.split(";").map((v) => v.trim());
    const found = parts.find((p) => p.startsWith(name + "="));
    if (!found) return "";
    return decodeURIComponent(found.split("=").slice(1).join("="));
}

/**
 * ✅ OAuth cookie (Spotify state gibi) için:
 * SameSite=None + Secure => modern browser'larda daha az problem.
 * Prod dışı ortamda Secure zorunlu olmasın diye isProd kontrolü var.
 */
function setCookie(res, name, value, maxAgeMs, { sameSite = "Lax" } = {}) {
    const isProd = process.env.NODE_ENV === "production";
    const cookie = [
        `${name}=${encodeURIComponent(value)}`,
        `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
        "Path=/",
        "HttpOnly",
        `SameSite=${sameSite}`,
        isProd ? "Secure" : "",
    ]
        .filter(Boolean)
        .join("; ");

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
        isProd ? "Secure" : "",
    ]
        .filter(Boolean)
        .join("; ");

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
    return String(s).replace(/[&<>"']/g, (c) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
    }[c]));
}

/* -----------------------------
   Utility
------------------------------ */
function normalizeStr(s) {
    return String(s || "").replace(/\s+/g, " ").trim();
}

function getBaseUrl(req) {
    const envBase = String(process.env.PUBLIC_BASE_URL || "").trim();
    if (envBase) return envBase.replace(/\/+$/, "");

    const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0];
    const host = req.headers.host || "localhost";
    return `${proto}://${host}`;
}

function stripeConfigured() {
    return Boolean(STRIPE_SECRET_KEY && STRIPE_PRICE_ID);
}

async function createStripeCheckoutSession({ spotify_id, success_url, cancel_url }) {
    const body = new URLSearchParams();
    body.append("mode", "payment");
    body.append("line_items[0][price]", STRIPE_PRICE_ID);
    body.append("line_items[0][quantity]", "1");
    body.append("client_reference_id", spotify_id);
    body.append("success_url", success_url);
    body.append("cancel_url", cancel_url);
    body.append("metadata[spotify_id]", spotify_id);

    const r = await fetch("https://api.stripe.com/v1/checkout/sessions", {
        method: "POST",
        headers: {
            Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
    });

    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
        const errMsg = data?.error?.message || data?.error?.type || "Stripe session failed";
        throw new Error(errMsg);
    }
    return data;
}

function verifyStripeSignature(rawBody, signatureHeader) {
    if (!signatureHeader || !STRIPE_WEBHOOK_SECRET) return false;
    const parts = String(signatureHeader)
        .split(",")
        .map((s) => s.split("="))
        .reduce((acc, [k, v]) => ({ ...acc, [k]: v }), {});

    const timestamp = parts.t;
    const v1 = parts.v1;
    if (!timestamp || !v1) return false;

    const signedPayload = `${timestamp}.${rawBody}`;
    const expected = crypto.createHmac("sha256", STRIPE_WEBHOOK_SECRET).update(signedPayload).digest("hex");

    const a = Buffer.from(expected, "hex");
    const b = Buffer.from(v1, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

function buildEnergyCurve(n) {
    const arr = [];
    if (!Number.isFinite(n) || n <= 0) return arr;

    for (let i = 0; i < n; i++) {
        const x = i / Math.max(1, n - 1);
        let v;

        if (x < 0.25) v = 3 + Math.round(3 * (x / 0.25));
        else if (x < 0.7) v = 6 + Math.round(3 * ((x - 0.25) / 0.45));
        else v = 9 - Math.round(4 * ((x - 0.7) / 0.3));

        arr.push(Math.max(1, Math.min(10, v)));
    }
    return arr;
}

function smoothEnergyCurve(curve, targetLength) {
    const fallback = buildEnergyCurve(targetLength);
    const out = [];
    const src = Array.isArray(curve) ? curve : [];

    for (let i = 0; i < targetLength; i++) {
        const fallbackVal = fallback[i] ?? 5;
        const raw = Number(src[i]);
        const val = Number.isFinite(raw) ? Math.max(1, Math.min(10, Math.round(raw))) : fallbackVal;

        if (i > 0) {
            const prev = out[i - 1];
            if (Math.abs(val - prev) > 3) {
                const step = val > prev ? 2 : -2;
                out.push(Math.max(1, Math.min(10, prev + step)));
                continue;
            }
        }

        out.push(val);
    }

    return out.length ? out : fallback;
}

async function safeIsPremiumUser(spotifyId) {
    if (!spotifyId) return false;
    try {
        return await isPremium(spotifyId);
    } catch (e) {
        console.error("safeIsPremiumUser failed", e);
        return false;
    }
}

function setIntentPlanForUser(spotifyId, plan, text, count, playlist = null) {
    if (!spotifyId || !plan) return;
    intentPlanCache.set(spotifyId, { plan, text, count, playlist, ts: Date.now() });
}

function getIntentPlanForUser(spotifyId) {
    if (!spotifyId) return null;
    const entry = intentPlanCache.get(spotifyId);
    if (!entry) return null;
    if (Date.now() - entry.ts > INTENT_PLAN_TTL) {
        intentPlanCache.delete(spotifyId);
        return null;
    }
    return entry;
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
                items: { type: "string", minLength: 2, maxLength: 24 },
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
                        song: { type: "string", minLength: 1, maxLength: 120 },
                    },
                    required: ["artist", "song"],
                },
            },
        },
        required: ["language", "title", "description", "vibe_tags", "tracks"],
    },
};

const intentSchema = {
    name: "spotimaker_intent",
    schema: {
        type: "object",
        additionalProperties: false,
        properties: {
            primary_mood: { type: "string", minLength: 2, maxLength: 48 },
            secondary_mood: { type: "string", minLength: 0, maxLength: 48 },
            activity: { type: "string", minLength: 2, maxLength: 120 },
            energy_curve: {
                type: "array",
                minItems: 5,
                maxItems: 200,
                items: { type: "integer", minimum: 1, maximum: 10 },
            },
            energy_curve_segments: {
                type: "array",
                minItems: 3,
                maxItems: 6,
                items: { type: "string", minLength: 2, maxLength: 60 },
            },
            genre_anchors: {
                type: "array",
                minItems: 1,
                maxItems: 8,
                items: { type: "string", minLength: 2, maxLength: 60 },
            },
            language_mix: { type: "string", minLength: 2, maxLength: 60 },
            avoid_repeats_rules: {
                type: "object",
                additionalProperties: false,
                properties: {
                    artist_back_to_back: { type: "boolean" },
                    artist_per_playlist: { type: "integer", minimum: 1, maximum: 5 },
                    decade_repeat_limit: { type: "integer", minimum: 1, maximum: 10 },
                    genre_repeat_limit: { type: "integer", minimum: 1, maximum: 10 },
                },
                required: [
                    "artist_back_to_back",
                    "artist_per_playlist",
                    "decade_repeat_limit",
                    "genre_repeat_limit",
                ],
            },
            tempo_range: { type: "string", minLength: 2, maxLength: 60 },
            familiarity_bias: { type: "string", minLength: 2, maxLength: 120 },
            do_not_include: {
                type: "array",
                minItems: 0,
                maxItems: 10,
                items: { type: "string", minLength: 1, maxLength: 80 },
            },
            vibe_keywords: {
                type: "array",
                minItems: 3,
                maxItems: 12,
                items: { type: "string", minLength: 2, maxLength: 60 },
            },
        },
        required: [
            "primary_mood",
            "secondary_mood",
            "activity",
            "energy_curve",
            "tempo_range",
            "familiarity_bias",
            "do_not_include",
            "vibe_keywords",
            "energy_curve_segments",
            "genre_anchors",
            "language_mix",
            "avoid_repeats_rules",
        ],
    },
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
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body,
    });

    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.access_token) {
        console.error("refresh token failed:", j);

        clearCookie(res, req, "spotify_access_token");
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

    if (token && !exp) return token;
    if (token && exp && exp - Date.now() > 60_000) return token;

    return await refreshSpotifyAccessToken(req, res);
}

async function requireSpotifyToken(req, res) {
    const token = await getValidSpotifyToken(req, res);
    if (!token) {
        res.status(401).json({ error: "Spotify oturumu yok veya süresi doldu. /login?force=1" });
        return null;
    }
    return token;
}

/* -----------------------------
   spotifyFetch wrapper
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
            },
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
        text: typeof data === "string" ? data : null,
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
    const body = JSON.stringify({ name: title, description: description || "", public: false });

    return await spotifyFetch(
        req,
        res,
        `https://api.spotify.com/v1/users/${encodeURIComponent(userId)}/playlists`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body,
        }
    );
}

async function spotifySearchTrack(req, res, q) {
    const url =
        "https://api.spotify.com/v1/search?" +
        new URLSearchParams({ q, type: "track", limit: "1" }).toString();

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
        const r = await spotifyFetch(
            req,
            res,
            `https://api.spotify.com/v1/playlists/${encodeURIComponent(playlistId)}/tracks`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ uris: chunk }),
            }
        );
        if (!r.ok) return r;
    }
    return { ok: true, status: 200, json: { ok: true } };
}

async function getSpotifyMeId(req, res) {
    const { ok, me } = await spotifyMe(req, res);
    if (!ok || !me?.id) return "";
    return String(me.id);
}

async function resolveUserSession(req, res) {
    const spotifyToken = await getValidSpotifyToken(req, res);
    let spotifyId = "";
    let premium = false;
    let displayName = "";

    if (spotifyToken) {
        try {
            const meRes = await spotifyFetch(req, res, "https://api.spotify.com/v1/me");
            if (meRes.ok && meRes.json?.id) {
                spotifyId = String(meRes.json.id);
                displayName = String(meRes.json.display_name || "");
                premium = await safeIsPremiumUser(spotifyId);
            }
        } catch (e) {
            console.error("resolveUserSession /me failed", e);
        }
    }

    const spotifyProfileText = await getSpotifyProfileText(req, res, spotifyToken);

    return { spotifyToken, spotifyId, premium, spotifyProfileText, displayName };
}

/* -----------------------------
   ROUTES
------------------------------ */

// Debug env
app.get("/api/debug/env", (req, res) => {
    res.json({
        NODE_ENV: process.env.NODE_ENV || null,
        PUBLIC_HOST: process.env.PUBLIC_HOST || null,
        SPOTIFY_REDIRECT_URI: process.env.SPOTIFY_REDIRECT_URI || null,
        host: req.headers.host || null,
        x_forwarded_proto: req.headers["x-forwarded-proto"] || null,
        protocol: req.protocol,
        secure: req.secure,
    });
});

// Static (public)
app.use(express.static(path.join(__dirname, "public")));

// Home
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* -----------------------------
   Billing (Stripe Checkout)
------------------------------ */
app.post("/api/billing/checkout", async (req, res) => {
    try {
        if (!stripeConfigured()) {
            return res.status(500).json({ ok: false, error: "STRIPE_NOT_CONFIGURED" });
        }

        const spotify_id = await getSpotifyMeId(req, res);
        if (!spotify_id) return res.status(401).json({ ok: false, error: "Önce Spotify’a giriş yap." });

        const base = getBaseUrl(req);

        const session = await createStripeCheckoutSession({
            spotify_id,
            success_url: `${base}/premium.html?success=1`,
            cancel_url: `${base}/premium.html?canceled=1`,
        });

        return res.json({ url: session?.url || null });
    } catch (e) {
        console.error("checkout failed", e);
        return res.status(500).json({ ok: false, error: "STRIPE_CHECKOUT_FAILED" });
    }
});

app.post(
    "/api/billing/webhook",
    express.raw({ type: "application/json" }),
    async (req, res) => {
        if (!STRIPE_WEBHOOK_SECRET) {
            return res.status(500).send("stripe_not_configured");
        }

        const sig = req.headers["stripe-signature"];
        const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || "");
        if (!verifyStripeSignature(raw.toString("utf8"), sig)) {
            return res.status(400).send("Invalid signature");
        }

        let event = null;
        try {
            event = JSON.parse(raw.toString("utf8"));
        } catch (err) {
            console.error("Webhook JSON parse failed", err?.message || err);
            return res.status(400).send("Invalid payload");
        }

        try {
            if (event?.type === "checkout.session.completed") {
                const data = event.data?.object || {};
                const spotify_id = data?.metadata?.spotify_id || data?.client_reference_id || "";

                if (spotify_id) {
                    await grantPremium(spotify_id, 30, "stripe_checkout");
                } else {
                    console.warn("checkout.session.completed without spotify_id", data?.id);
                }
            }
        } catch (e) {
            console.error("Webhook handler error", e);
        }

        // Respond quickly regardless of downstream issues
        return res.status(200).json({ received: true });
    }
);

// Health/db sanity (admin)
app.get("/api/admin/db-check", async (req, res) => {
    try {
        if (!pool) {
            return res.json({ ok: false, error: "DB_NOT_CONFIGURED" });
        }

        if (!requireAdmin(req, res)) return;
        await initDb();
        const stats = await getStats();
        const db = await pool.query("select current_database() as db, now() as now");
        res.json({ ok: true, stats, db: db.rows[0] });
    } catch (e) {
        res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

/**
 * ✅ Spotify OAuth start
 * - state cookie’ye yazılır (server restart etse de kalır)
 */
app.get("/login", (req, res) => {
    try {
        const state = crypto.randomBytes(16).toString("hex");

        // OAuth state cookie (10 dk)
        setCookie(res, "spotify_state", state, 10 * 60 * 1000, { sameSite: "None" });

        const scope = [
            "user-read-private",
            "user-read-email",
            "user-top-read",
            "user-read-recently-played",
            "playlist-modify-private",
            "playlist-modify-public",
        ].join(" ");

        const redirectUri = String(process.env.SPOTIFY_REDIRECT_URI || "").trim();
        const clientId = String(process.env.SPOTIFY_CLIENT_ID || "").trim();

        if (!clientId || !redirectUri) {
            console.error("Spotify ENV eksik:", { SPOTIFY_CLIENT_ID: !!clientId, SPOTIFY_REDIRECT_URI: !!redirectUri });
            return res.status(500).send("Sunucu ayarı eksik: CLIENT_ID / REDIRECT_URI yok.");
        }

        const force = String(req.query.force || "") === "1";

        const params = querystring.stringify({
            show_dialog: force ? "true" : "false",
            response_type: "code",
            client_id: clientId,
            scope,
            redirect_uri: redirectUri,
            state,
        });

        const url = `https://accounts.spotify.com/authorize?${params}`;
        console.log("SPOTIFY_AUTHORIZE_URL", url);
        return res.redirect(url);
    } catch (e) {
        console.error("/login crashed:", e);
        return res.status(500).send("Spotify giriş başlatılırken hata: " + (e?.message || String(e)));
    }
});

/**
 * ✅ Spotify OAuth callback
 * - query.state ile cookie spotify_state eşleşmek zorunda
 */
app.get("/callback", async (req, res) => {
    try {
        const code = String(req.query.code || "");
        const state = String(req.query.state || "");

        if (!code) return res.status(400).send("No code");

        const cookieState = getCookie(req, "spotify_state");
        if (!state || !cookieState || state !== cookieState) {
            console.error("INVALID_STATE", { state, cookieStatePresent: Boolean(cookieState) });
            return res.status(400).send("Invalid state");
        }

        // state tek kullanımlık: hemen temizle
        clearCookie(res, req, "spotify_state");

        const redirectUri = String(process.env.SPOTIFY_REDIRECT_URI || "").trim();

        const body = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri,
        });

        const clientId = String(process.env.SPOTIFY_CLIENT_ID || "").trim();
        const clientSecret = String(process.env.SPOTIFY_CLIENT_SECRET || "").trim();
        const auth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

        const tokenRes = await fetch("https://accounts.spotify.com/api/token", {
            method: "POST",
            headers: {
                Authorization: `Basic ${auth}`,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body,
        });

        const data = await tokenRes.json().catch(() => ({}));
        if (!tokenRes.ok) {
            console.error("Spotify token error:", data);
            return res.status(500).send("Token exchange failed");
        }

        // eski token cookielerini temizle
        clearCookie(res, req, "spotify_access_token");
        clearCookie(res, req, "spotify_refresh_token");
        clearCookie(res, req, "spotify_expires_at");

        const expiresIn = Number(data.expires_in || 3600);
        const expiresAt = Date.now() + expiresIn * 1000;

        setCookie(res, "spotify_access_token", data.access_token, expiresIn * 1000, { sameSite: "Lax" });

        if (data.refresh_token) {
            setCookie(res, "spotify_refresh_token", data.refresh_token, 365 * 24 * 60 * 60 * 1000, { sameSite: "Lax" });
        } else {
            clearCookie(res, req, "spotify_refresh_token");
        }

        setCookie(res, "spotify_expires_at", String(expiresAt), expiresIn * 1000, { sameSite: "Lax" });

        // user upsert
        try {
            const meRes = await fetch("https://api.spotify.com/v1/me", {
                headers: { Authorization: `Bearer ${data.access_token}` },
            });
            const me = await meRes.json().catch(() => ({}));
            if (me?.id) await upsertUser({ spotify_id: me.id, display_name: me.display_name });
        } catch (e) {
            console.error("upsertUser failed:", e);
        }

        return res.redirect("/");
    } catch (err) {
        console.error("CALLBACK_FAILED", err);
        return res.status(500).send("Callback failed");
    }
});

// Logout
app.get("/logout", (req, res) => {
    clearCookie(res, req, "spotify_access_token");
    clearCookie(res, req, "spotify_refresh_token");
    clearCookie(res, req, "spotify_expires_at");
    clearCookie(res, req, "spotify_state");
    return res.redirect(302, "/");
});

// Switch account (force dialog)
app.get("/switch-account", (req, res) => {
    clearCookie(res, req, "spotify_access_token");
    clearCookie(res, req, "spotify_refresh_token");
    clearCookie(res, req, "spotify_expires_at");
    clearCookie(res, req, "spotify_state");
    return res.redirect(302, "/login?force=1");
});

// Debug cookies
app.get("/debug/cookies", (req, res) => {
    res.json({
        hostname: req.hostname,
        host: req.headers.host || "",
        cookieHeader: req.headers.cookie || "",
        accessTokenPresent: Boolean(getCookie(req, "spotify_access_token")),
        refreshTokenPresent: Boolean(getCookie(req, "spotify_refresh_token")),
        expiresAt: Number(getCookie(req, "spotify_expires_at") || 0),
        statePresent: Boolean(getCookie(req, "spotify_state")),
    });
});

// Spotify status
app.get("/api/spotify/status", async (req, res) => {
    try {
        const token = await getValidSpotifyToken(req, res);
        if (!token) return res.json({ connected: false, reason: "no_token" });

        const r = await fetch("https://api.spotify.com/v1/me", {
            headers: { Authorization: `Bearer ${token}` },
        });

        if (r.status === 401) return res.json({ connected: false, reason: "expired_token" });

        if (r.status === 403) {
            clearCookie(res, req, "spotify_access_token");
            clearCookie(res, req, "spotify_refresh_token");
            clearCookie(res, req, "spotify_expires_at");
            return res.json({ connected: false, reason: "insufficient_scope", login_url: "/login?force=1" });
        }

        if (!r.ok) return res.json({ connected: false, reason: "spotify_error", status: r.status });

        const me = await r.json().catch(() => ({}));

        let premium = false;
        try { premium = await isPremium(me.id); } catch (_) { premium = false; }

        return res.json({
            connected: true,
            user: { id: me.id, name: me.display_name },
            premium,
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
            headers: { Authorization: `Bearer ${token}` },
        });

        let data = await r.json().catch(() => ({}));

        if (r.status === 401) {
            const refreshed = await refreshSpotifyAccessToken(req, res);
            if (refreshed) {
                token = refreshed;
                r = await fetch("https://api.spotify.com/v1/me", {
                    headers: { Authorization: `Bearer ${token}` },
                });
                data = await r.json().catch(() => ({}));
            }
        }

        if (!r.ok) return res.status(200).json({ ok: false, status: r.status, spotify_error: data });

        let premium = false;
        try { premium = await isPremium(String(data.id || "")); } catch (_) { premium = false; }
        return res.status(200).json({
            ok: true,
            me: { id: data.id, display_name: data.display_name },
            premium,
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
                headers: { Authorization: `Bearer ${token}` },
            }),
            fetch(`https://api.spotify.com/v1/me/top/artists?limit=10&time_range=${timeRange}`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        ]);

        const tracksJson = await tracksRes.json().catch(() => ({}));
        const artistsJson = await artistsRes.json().catch(() => ({}));

        if (!tracksRes.ok) return res.status(500).json({ error: "Top tracks failed", details: tracksJson });
        if (!artistsRes.ok) return res.status(500).json({ error: "Top artists failed", details: artistsJson });

        const topTracks = (tracksJson.items || []).map((t) => `${t.name} - ${t.artists?.[0]?.name || ""}`.trim());
        const topArtists = (artistsJson.items || []).map((a) => a.name);

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
            headers: { Authorization: `Bearer ${token}` },
        });
        const me = await meRes.json().catch(() => ({}));

        const tracksRes = await fetch("https://api.spotify.com/v1/me/top/tracks?limit=3&time_range=short_term", {
            headers: { Authorization: `Bearer ${token}` },
        });
        const tracks = await tracksRes.json().catch(() => ({}));

        let premium = false;
        try {
            premium = await isPremium(String(me.id || ""));
        } catch (_) {
            premium = false;
        }

        return res.json({
            ok: true,
            me: { id: me.id, display_name: me.display_name },
            premium,
            sampleTopTracks: (tracks?.items || [])
                .slice(0, 3)
                .map((t) => `${t.name} - ${t.artists?.[0]?.name || ""}`.trim()),
        });
    } catch (e) {
        console.error(e);
        return res.json({ ok: false, error: String(e) });
    }
});

/* -----------------------------
   AI generate
------------------------------ */
async function analyzeIntentPlan({ userText, requestedCount, spotifyProfileText }) {
    const intentPrompt = `
You are the Intent Analyzer for a premium music curation service.
Summarize the user's goal into a concise JSON plan with extra structure for flow and variety.
Focus on mood, activity, tempo, energy pacing, and familiarity vs. discovery balance.
Energy curve must span the full playlist with gradual shifts (avoid jumps > 2 points between neighbors).
Define 3-5 energy_curve_segments (intro / build / peak / outro style) to guide transitions.
Add genre_anchors (core styles to stick to) and language_mix (TR/EN ratio if implied by the request).
Set avoid_repeats_rules to prevent artist/decade/genre fatigue.

User text: ${userText}
requested_count: ${requestedCount}
${spotifyProfileText ? `Listener context: ${spotifyProfileText}` : ""}
`.trim();

    const response = await client.responses.create({
        model: "gpt-5-mini",
        input: [
            {
                role: "system",
                content:
                    "Extract an intent plan for a playlist. Return only the JSON schema fields. Do not include narration or explanations.",
            },
            { role: "user", content: intentPrompt },
        ],
        text: {
            format: {
                type: "json_schema",
                name: intentSchema.name,
                schema: intentSchema.schema,
                strict: true,
            },
        },
    });

    const jsonText = response.output_text;
    const plan = JSON.parse(jsonText);
    plan.energy_curve = smoothEnergyCurve(plan.energy_curve, requestedCount);

    if (!Array.isArray(plan.energy_curve_segments) || !plan.energy_curve_segments.length) {
        plan.energy_curve_segments = ["intro", "flow", "peak", "outro"];
    }

    if (!Array.isArray(plan.genre_anchors) || !plan.genre_anchors.length) {
        plan.genre_anchors = ["pop"];
    }

    if (!plan.language_mix) {
        plan.language_mix = "TR ağırlıklı";
    }

    if (!plan.avoid_repeats_rules) {
        plan.avoid_repeats_rules = {
            artist_back_to_back: true,
            artist_per_playlist: 2,
            decade_repeat_limit: 6,
            genre_repeat_limit: 6,
        };
    }
    return plan;
}

async function generatePlaylistFromIntent({
    userText,
    requestedCount,
    spotifyProfileText,
    intentPlan,
    previousPlaylist,
}) {
    const systemPrompt = `
You are a premium music director crafting intentional, human-feeling playlists.

Premium intent plan (never expose to the user):
${JSON.stringify(intentPlan, null, 2)}

STRICT RULES:
- You will be given requested_count and must return exactly that many tracks.
- Obey the intent plan's energy_curve and energy_curve_segments to keep a smooth intro → flow → peak → outro progression; avoid abrupt jumps.
- Use intentPlan.genre_anchors as guardrails; no abrupt genre jumps unless the user asked for chaos. Prefer bridge tracks when shifting styles.
- Honor language_mix (e.g., TR/EN ratio) and keep the title + description in the matching language.
- Honor avoid_repeats_rules (artist_back_to_back, artist_per_playlist, decade_repeat_limit, genre_repeat_limit). Never place tracks by the same artist back-to-back.
- Maintain a familiar/discovery balance ~70/30 unless specified. Keep approachable core, tasteful discovery.
- Follow tempo_range, primary_mood, secondary_mood, activity, and vibe_keywords when choosing tracks.
- Mention the flow structure explicitly in the description (e.g., "Tracks 1-4 warm-up, 5-12 akış, 13-20 doruk/outro").
- Use plain ASCII characters only. Do not use smart quotes or special symbols. Ensure vibe_tags are clean words without stray quotes.
- Avoid fake songs. Prefer widely available tracks.
- Output MUST be valid JSON matching the playlist schema, no explanations.

Discovery balance:
- Keep 70% familiar vibe and 30% discovery unless intentPlan.familiarity_bias says otherwise.
- Do not repeat the same artist more than intentPlan.avoid_repeats_rules.artist_per_playlist times, and never consecutively.
- If a previous playlist is provided, change at least 50% of the tracks while keeping the same mood/activity/tempo band and the intent energy curve.
`.trim();

const userPrompt = `
User request: ${userText}
requested_count: ${requestedCount}
Intent energy guidance: ${intentPlan.energy_curve.join(", ")}
Familiarity: ${intentPlan.familiarity_bias}
Energy segments: ${intentPlan.energy_curve_segments?.join(" -> ") || "intro, flow, peak, outro"}
Genres to anchor: ${intentPlan.genre_anchors?.join(", ")}
Language mix: ${intentPlan.language_mix}
${spotifyProfileText ? `Listener context: ${spotifyProfileText}` : ""}
${previousPlaylist ? `Previous tracklist for alternatives: ${(previousPlaylist.tracks || [])
    .map((t) => `${t.artist} - ${t.song}`)
    .join(" | ")}` : ""}
`.trim();

    const exactSchema = structuredClone(playlistSchema);
    exactSchema.schema.properties.tracks.minItems = requestedCount;
    exactSchema.schema.properties.tracks.maxItems = requestedCount;

    const response = await client.responses.create({
        model: "gpt-5-mini",
        input: [
            { role: "system", content: systemPrompt },
            { role: "user", content: userPrompt },
        ],
        text: {
            format: {
                type: "json_schema",
                name: playlistSchema.name,
                schema: exactSchema.schema,
                strict: true,
            },
        },
    });

    return response.output_text;
}

async function generateFreePlaylist({ userText, requestedCount, spotifyProfileText }) {
    const systemPrompt = `
You are a lightweight playlist maker. Keep it mainstream-friendly and simple.

BASIC RULES ONLY:
- You will be given requested_count and must return exactly that many tracks.
- Avoid putting the same artist back-to-back; cap any artist at 2 appearances.
- Keep song picks safe and popular; stay within the user's broad vibe without over-curating.
- Respect the user's language: if they write in Turkish, set language="tr" and use Turkish for title/description; otherwise English.
- Keep title short and plain. Tags should be simple words (no quotes).
- Use plain ASCII characters only. No smart quotes or fancy punctuation.
- Output MUST be valid JSON only, matching the provided schema.

Flow guidance (keep it simple, not too strict):
- Early tracks ease in, middle has the main energy, final tracks land softly.

${spotifyProfileText}
`.trim();

    const userPrompt = `User request: ${userText}\nrequested_count: ${requestedCount}`;

    const exactSchema = structuredClone(playlistSchema);
    exactSchema.schema.properties.tracks.minItems = requestedCount;
    exactSchema.schema.properties.tracks.maxItems = requestedCount;

    const response = await client.responses.create({
        model: "gpt-5-mini",
        input: [
            { role: "system", content: systemPrompt },
            { role: "user", content: userPrompt },
        ],
        text: {
            format: {
                type: "json_schema",
                name: playlistSchema.name,
                schema: exactSchema.schema,
                strict: true,
            },
        },
    });

    return response.output_text;
}

app.post("/api/generate", async (req, res) => {
    const userText = String(req.body?.text ?? "").trim();
    if (!userText) return res.status(400).json({ error: "Missing text" });

    if (userText.length > 2000) {
        return res.status(400).json({ error: "Text too long (max 2000 chars)" });
    }

    try {
        const { spotifyId, premium, spotifyProfileText } = await resolveUserSession(req, res);

        // Count + premium/free limit
        const requestedCountRaw = Number(req.body?.count ?? 20);
        let requestedCount = Math.max(20, Math.min(200, Number.isFinite(requestedCountRaw) ? requestedCountRaw : 20));
        const hardMax = premium ? 200 : 40;
        requestedCount = Math.max(20, Math.min(hardMax, requestedCount));

        let jsonText;
        let intentPlan = null;

        if (premium) {
            intentPlan = await analyzeIntentPlan({ userText, requestedCount, spotifyProfileText });
            jsonText = await generatePlaylistFromIntent({
                userText,
                requestedCount,
                spotifyProfileText,
                intentPlan,
                previousPlaylist: null,
            });
        } else {
            jsonText = await generateFreePlaylist({ userText, requestedCount, spotifyProfileText });
        }

        let data;
        try {
            data = JSON.parse(jsonText);
        } catch (err) {
            console.error("AI invalid JSON:", jsonText?.slice?.(0, 300));
            return res.status(400).json({ error: "AI returned invalid JSON" });
        }

        const targetLength = data.tracks?.length || requestedCount;
        data.energy_curve = premium
            ? smoothEnergyCurve(intentPlan?.energy_curve, targetLength)
            : buildEnergyCurve(targetLength);

        try {
            if (premium && spotifyId && intentPlan) {
                setIntentPlanForUser(spotifyId, intentPlan, userText, requestedCount, data);
            }

            if (spotifyId) await markPlaylistCreated(spotifyId, `count=${requestedCount}`);
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

app.post("/api/refresh", async (req, res) => {
    try {
        const { spotifyId, premium, spotifyProfileText } = await resolveUserSession(req, res);

        if (!spotifyId) return res.status(401).json({ error: "Spotify not connected" });
        if (!premium) return res.status(403).json({ error: "Premium required" });

        const cached = getIntentPlanForUser(spotifyId);
        if (!cached?.plan || !cached?.text) {
            return res.status(400).json({ error: "No intent available" });
        }

        const intentPlan = cached.plan;
        const userText = cached.text;
        const requestedCount = Math.max(20, Math.min(200, Number(cached.count) || 20));

        const jsonText = await generatePlaylistFromIntent({
            userText,
            requestedCount,
            spotifyProfileText,
            intentPlan,
            previousPlaylist: cached.playlist,
        });

        let data;
        try {
            data = JSON.parse(jsonText);
        } catch (err) {
            console.error("refresh AI invalid JSON:", jsonText?.slice?.(0, 300));
            return res.status(400).json({ error: "AI returned invalid JSON" });
        }

        const targetLength = data.tracks?.length || requestedCount;
        data.energy_curve = smoothEnergyCurve(intentPlan.energy_curve, targetLength);

        try {
            setIntentPlanForUser(spotifyId, intentPlan, userText, requestedCount, data);
            await markPlaylistCreated(spotifyId, `refresh_count=${requestedCount}`);
        } catch (e) {
            console.error("refresh markPlaylistCreated failed:", e);
        }

        res.setHeader("Content-Type", "application/json; charset=utf-8");
        return res.json(data);
    } catch (e) {
        console.error("refresh crash:", e);
        return res.status(500).json({ error: String(e?.message || e) });
    }
});

app.post("/api/feedback", async (req, res) => {
    try {
        if (!dbEnabled || !pool) {
            return res.status(503).json({ ok: false, error: "Geri bildirim şu an kaydedilemiyor (DB yok)." });
        }

        const spotify_id = await getSpotifyMeId(req, res);
        if (!spotify_id) return res.status(401).json({ ok: false, error: "Önce Spotify ile giriş yap." });

        const message = String(req.body?.message || "").trim();
        if (message.length < 5) return res.status(400).json({ ok: false, error: "Mesaj çok kısa." });
        if (message.length > 2000) return res.status(400).json({ ok: false, error: "Mesaj 2000 karakteri aşmamalı." });

        await saveFeedback(spotify_id, message);
        return res.json({ ok: true });
    } catch (e) {
        console.error("feedback failed:", e);
        return res.status(500).json({ ok: false, error: "Geri bildirim kaydedilemedi. Sonra tekrar dene." });
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

        let premium = false;
        try {
            premium = await isPremium(String(me.id || ""));
        } catch (_) {
            premium = false; // DB yoksa premium false kabul et
        }

        try {
            if (!premium) {
                const used = await countSavedToday(String(me.id || ""));
                if (used >= 1) {
                    return res.status(403).json({
                        error: "Free save limit reached (1/day). Upgrade required.",
                        upgrade_required: true,
                        limit: { saves_per_day: 1 },
                        used,
                    });
                }
            }
        } catch (e) {
            console.error("countSavedToday failed:", e);
        }

        const body = req.body || {};
        const title = normalizeStr(body.title || body.name || "Spotimaker Playlist");
        const description = normalizeStr(body.description || "");
        const tracks = Array.isArray(body.tracks) ? body.tracks : [];

        if (!tracks.length) return res.status(400).json({ error: "Missing tracks" });

        const created = await spotifyCreatePlaylist(req, res, me.id, title, description);
        if (!created.ok) {
            console.error("create playlist failed:", created.json || created.text);
            return res.status(500).json({ error: "create playlist failed", details: created.json || created.text });
        }

        const playlistId = created.json?.id;
        if (!playlistId) return res.status(500).json({ error: "create playlist returned no id" });

        const uris = [];
        for (const t of tracks) {
            const artist = normalizeStr(t?.artist);
            const song = normalizeStr(t?.song);
            if (!artist || !song) continue;

            const q = `track:${song} artist:${artist}`;
            const hit = await spotifySearchTrack(req, res, q);
            if (hit?.uri) uris.push(hit.uri);
        }

        if (!uris.length) return res.status(400).json({ error: "No Spotify matches found for provided tracks" });

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
            premium,
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
        if (!pool) return res.status(200).json({ ok: false, error: "DB_NOT_CONFIGURED" });

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
app.post("/api/admin/codes/create", async (req, res) => {
    try {
        if (!requireAdmin(req, res)) return;

        const days = Number(req.body?.days ?? 30);
        const max_uses = Number(req.body?.max_uses ?? 1);
        const note = String(req.body?.note ?? "");

        const codeObj = await createRedeemCode({ days, max_uses, note });

        return res.json({ ok: true, code: codeObj?.code || null, meta: codeObj || null });
    } catch (e) {
        console.error("codes/create failed:", e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

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

app.get("/admin", async (req, res) => {
    try {
        if (!requireAdmin(req, res)) return;

        const stats = await getStats();
        const users = await getUsers(200);
        let feedback = [];
        let feedbackError = "";

        if (dbEnabled && pool) {
            try {
                feedback = await getFeedbackMessages(200);
            } catch (e) {
                console.error("feedback fetch failed", e);
                feedbackError = "Geri bildirimler çekilemedi.";
            }
        } else {
            feedbackError = "DB devre dışı (feedback yok).";
        }

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

        const feedbackRow = (f) => `
      <tr>
        <td>${escapeHtml(f.display_name || "(isim yok)")}</td>
        <td>${escapeHtml(f.spotify_id || "")}</td>
        <td>${escapeHtml(f.message || "")}</td>
        <td>${f.created_at ? new Date(f.created_at).toLocaleString() : ""}</td>
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

  <h2>Kullanıcı Geri Bildirimleri</h2>
  ${feedbackError
        ? `<div class="card">${escapeHtml(feedbackError)}</div>`
        : `<table>
        <thead>
          <tr><th>İsim</th><th>Spotify ID</th><th>Mesaj</th><th>Zaman</th></tr>
        </thead>
        <tbody>${(Array.isArray(feedback) ? feedback : []).map(feedbackRow).join("")}</tbody>
      </table>`}

  <h2>Redeem Code Generator</h2>
  <div class="card" style="max-width:520px">
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <label>Days <input id="days" type="number" value="30" min="1" style="width:80px"></label>
      <label>Max uses <input id="max_uses" type="number" value="1" min="1" style="width:80px"></label>
      <label>Note <input id="note" type="text" value="admin" style="width:200px"></label>
      <button id="gen">Generate</button>
    </div>
    <div style="margin-top:10px;font-family:ui-monospace,Consolas,monospace" id="out"></div>
    <small style="display:block;margin-top:8px;color:#666">This calls POST /api/admin/codes/create using your same admin token.</small>
  </div>

  <script>
    const token = new URLSearchParams(location.search).get("token") || "";
    const out = document.getElementById("out");

    document.getElementById("gen").onclick = async () => {
      out.textContent = "Generating...";
      const days = Number(document.getElementById("days").value || 30);
      const max_uses = Number(document.getElementById("max_uses").value || 1);
      const note = String(document.getElementById("note").value || "");

      const r = await fetch("/api/admin/codes/create?token=" + encodeURIComponent(token), {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ days, max_uses, note })
      });

      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) {
        out.textContent = "Error: " + (j.error || r.status);
        return;
      }
      out.textContent = "CODE: " + j.code;
    };
  </script>

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

app.get("/api/redeem", (req, res) => res.status(405).send('Use POST /api/redeem with JSON body: {code:"..."}'));
app.get("/api/admin/codes/create", (req, res) => res.status(405).send("Use POST /api/admin/codes/create (admin token required)."));

// --- boot ---
const port = process.env.PORT || 8787;

(async () => {
    try {
        // ✅ DB varsa init et, yoksa devam et
        await initDb();
        console.log("DB ready ✅");
    } catch (e) {
        console.warn("DB init skipped ⚠️", String(e?.message || e));
    }

    app.listen(port, () => {
        console.log(`Spotimaker running on http://localhost:${port}`);
    });
})().catch((e) => {
    console.error("BOOT ERROR:", e);
    process.exit(1);
});
