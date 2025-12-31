import express from "express";
import OpenAI from "openai";
import path from "path";
import { fileURLToPath } from "url";
import querystring from "querystring";
import crypto from "crypto";
import { upsertUser, markPlaylistCreated, markPlaylistSaved, getUsers, getStats, isPremium, countSavedToday } from "./db.mjs";
async function getSpotifyMeId(req) {
    const token = getCookie(req, "spotify_access_token");
    if (!token) return "";
    try {
        const meRes = await fetch("https://api.spotify.com/v1/me", {
            headers: { Authorization: `Bearer ${token}` }
        });
        const me = await meRes.json();
        if (!meRes.ok) return "";
        return String(me?.id || "");
    } catch {
        return "";
    }
}
    


// ---- simple in-memory cache for Spotify profile (MVP) ----
const spotifyProfileCache = new Map();
// key: spotify_access_token
// value: { text: string, ts: number }
const SPOTIFY_PROFILE_TTL = 15 * 60 * 1000; // 15 minutes

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- cookie helpers (MVP) ---
function buildEnergyCurve(n) {
    const arr = [];
    if (!Number.isFinite(n) || n <= 0) return arr;

    // 0-25%: ease-in (3->6)
    // 25-70%: main peak (6->9)
    // 70-100%: resolution (9->5)
    for (let i = 0; i < n; i++) {
        const x = i / Math.max(1, n - 1);
        let v;

        if (x < 0.25) {
            v = 3 + Math.round(3 * (x / 0.25));
        } else if (x < 0.70) {
            v = 6 + Math.round(3 * ((x - 0.25) / 0.45));
        } else {
            v = 9 - Math.round(4 * ((x - 0.70) / 0.30));
        }

        arr.push(Math.max(1, Math.min(10, v)));
    }
    return arr;
}

function clearCookie(res, req, name) {
    const isProd = process.env.NODE_ENV === "production";

    // Ayný isimli cookie farklý Domain/Path ile set edilmiþ olabilir.
    // Bu yüzden birkaç varyasyonla öldürüyoruz.
    const host = (req?.hostname || "").split(":")[0]; // spotimaker.onrender.com gibi
    const domains = [
        undefined,          // domain belirtme
        host || undefined,  // spotimaker.onrender.com
        ".onrender.com"     // wildcard domain (sende bu þekilde set edilmiþ olabilir)
    ].filter((d, i, a) => a.indexOf(d) === i);

    const paths = ["/", undefined].filter((p, i, a) => a.indexOf(p) === i);

    for (const domain of domains) {
        for (const path of paths) {
            const parts = [
                `${name}=`,
                "Max-Age=0",
                "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                `Path=${path || "/"}`,
                domain ? `Domain=${domain}` : "",
                "HttpOnly",
                "SameSite=Lax",
                isProd ? "Secure" : ""
            ].filter(Boolean);

            res.append("Set-Cookie", parts.join("; "));
        }
    }
}

function getCookie(req, name) {
    const header = req.headers.cookie || "";
    const parts = header.split(";").map(v => v.trim());
    const found = parts.find(p => p.startsWith(name + "="));
    if (!found) return "";
    return decodeURIComponent(found.split("=").slice(1).join("="));
}
function setCookie(res, name, value, maxAgeMs) {
    const isProd = process.env.NODE_ENV === "production";
    const parts = [
        `${name}=${encodeURIComponent(value)}`,
        "Path=/",
        `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
        "HttpOnly",
        "SameSite=Lax"
    ];
    if (isProd) parts.push("Secure");
    res.append("Set-Cookie", parts.join("; "));
}

// --- paths ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- OpenAI client ---
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// --- JSON Schema: Spotimaker playlist output ---
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
        required: ["language", "title", "description", "vibe_tags",  "tracks"]
    }
};

// --- ROUTES ---
app.get("/api/debug/users", (req, res) => {
    try {
        if (!requireAdmin(req, res)) return;
        return res.json({ stats: getStats(), users: getUsers(20) });
    } catch (e) {
        console.error("DEBUG USERS ERROR:", e);
        return res.status(500).json({ error: "debug users crashed" });
    }
});

app.get("/debug/spotify", async (req, res) => {
    const token = getCookie(req, "spotify_access_token");

    if (!token) return res.json({ ok: false, reason: "no spotify_access_token cookie" });

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
            sampleTopTracks: (tracks.items || []).map(t => `${t.name} - ${t.artists?.[0]?.name || ""}`)
        });
    } catch (e) {
        console.error(e);
        return res.json({ ok: false, error: String(e) });
    }
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Spotify OAuth
app.get("/login", (req, res) => {
    try {
        const state = crypto.randomBytes(12).toString("hex");
        setCookie(res, "spotify_state", state, 10 * 60 * 1000);

        const scope = [
            "user-top-read",
            "playlist-read-private",
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
            return res.status(500).send("Sunucu ayarý eksik: Spotify giriþ bilgileri tanýmlý deðil (CLIENT_ID / REDIRECT_URI).");
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
        return res.status(500).send("Spotify giriþ baþlatýlýrken hata oluþtu: " + (e?.message || String(e)));
    }
});

app.get("/callback", async (req, res) => {
    try {
        const code = String(req.query.code || "");
        const state = String(req.query.state || "");
        const savedState = getCookie(req, "spotify_state");

        if (!code) return res.status(400).send("No code");
        if (!state || !savedState || state !== savedState) {
            return res.status(400).send("Invalid state");
        }

        const body = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: String(process.env.SPOTIFY_REDIRECT_URI || "").trim()
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
        try {
            const meRes = await fetch("https://api.spotify.com/v1/me", {
                headers: { Authorization: `Bearer ${data.access_token}` }
            });
            const me = await meRes.json();
            if (me?.id) {
                upsertUser({ spotify_id: me.id, display_name: me.display_name });
                console.log("LOGIN_EVENT", {
                    spotify_id: me.id,
                    display_name: me.display_name || null,
                    time: new Date().toISOString()
                });

            } else {
                console.error("Spotify /me missing id:", me);
            }
        } catch (e) {
            console.error("upsertUser failed:", e);
        }
        clearCookie(res, req, "spotify_state");

        setCookie(res, "spotify_access_token", data.access_token, (data.expires_in || 3600) * 1000);
        return res.redirect("/");
    } catch (err) {
        console.error(err);
        return res.status(500).send("Callback failed");
    }
});
function requireSpotifyToken(req, res) {
    const token = getCookie(req, "spotify_access_token");
    if (!token) {
        res.status(401).json({ error: "Not logged in to Spotify. Go to /login" });
        return null;
    }
    return token;
}
    // Çýkýþ yap: cookie temizle, ana sayfaya dön
    app.get("/logout", (req, res) => {
        try {
            clearCookie(res, req, "spotify_access_token");
            clearCookie(res, req, "spotify_state");
            return res.redirect(302, "/");
        } catch (e) {
            console.error("logout failed:", e);
            return res.redirect(302, "/");
        }
    });

    // Hesap deðiþtir: cookie temizle, Spotify login'e force ile git (show_dialog=true)
    app.get("/switch-account", (req, res) => {
        try {
            clearCookie(res, req, "spotify_access_token");
            clearCookie(res, req, "spotify_state");
            return res.redirect(302, "/login?force=1");
        } catch (e) {
            console.error("switch-account failed:", e);
            return res.redirect(302, "/login?force=1");
        }
    });

    app.get("/debug/cookies", (req, res) => {
        res.json({
            hostname: req.hostname,
            cookieHeader: req.headers.cookie || "",
            accessTokenPresent: Boolean(getCookie(req, "spotify_access_token")),
            statePresent: Boolean(getCookie(req, "spotify_state"))
        });
    });

app.get("/spotify/top", async (req, res) => {
    try {
        const token = requireSpotifyToken(req, res);
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

app.get("/api/me", async (req, res) => {
    try {
        const token = getCookie(req, "spotify_access_token");
        if (!token) return res.status(200).json({ ok: false });

        const r = await fetch("https://api.spotify.com/v1/me", {
            headers: { Authorization: `Bearer ${token}` }
        });

        const data = await r.json();
        if (!r.ok) {
            console.error("Spotify /me error:", data);
            return res.status(200).json({ ok: false });
        }

        const premium = isPremium(data.id);

        return res.status(200).json({
            ok: true,
            me: {
                id: data.id,
                display_name: data.display_name
            },
            premium
        });
    } catch (e) {
        console.error("api/me failed:", e);
        return res.status(200).json({ ok: false });
    }
});

app.get("/api/spotify/status", (req, res) => res.redirect(302, "/api/me"));

// AI generate
app.post("/api/generate", async (req, res) => {
    try {
        const spotifyToken = getCookie(req, "spotify_access_token");
        let spotifyProfileText = "";

        if (spotifyToken) {
            const cached = spotifyProfileCache.get(spotifyToken);
            const now = Date.now();

            if (cached && (now - cached.ts) < SPOTIFY_PROFILE_TTL) {
                //  cache hit
                spotifyProfileText = cached.text;
            } else {
                try {
                    const [tracksRes, artistsRes] = await Promise.all([
                        fetch("https://api.spotify.com/v1/me/top/tracks?limit=5&time_range=short_term", {
                            headers: { Authorization: `Bearer ${spotifyToken}` }
                        }),
                        fetch("https://api.spotify.com/v1/me/top/artists?limit=5&time_range=short_term", {
                            headers: { Authorization: `Bearer ${spotifyToken}` }
                        })
                    ]);

                    if (tracksRes.ok && artistsRes.ok) {
                        const tracksJson = await tracksRes.json();
                        const artistsJson = await artistsRes.json();

                        const topTracks = (tracksJson.items || [])
                            .map(t => `${t.name} by ${t.artists?.[0]?.name || ""}`)
                            .join(", ");

                        const topArtists = (artistsJson.items || [])
                            .map(a => a.name)
                            .join(", ");

                        spotifyProfileText = `
User listening profile:
Top artists: ${topArtists}
Top tracks: ${topTracks}

Use this profile to personalize the playlist.
`.trim();

                        //  cache write
                        spotifyProfileCache.set(spotifyToken, {
                            text: spotifyProfileText,
                            ts: now
                        });
                    }
                } catch (e) {
                    console.error("Spotify profile fetch failed", e);
                }
            }
        }

        const userText = String(req.body?.text ?? "").trim();
        const requestedCountRaw = Number(req.body?.count ?? 20);
        let requestedCount = Math.max(20, Math.min(200, Number.isFinite(requestedCountRaw) ? requestedCountRaw : 20));

        // --- PREMIUM/FREE LIMITS ---
        let premium = false;
        try {
            // spotify baðlýysa premium kontrol edelim (me.id ile)
            if (spotifyToken) {
                const meRes = await fetch("https://api.spotify.com/v1/me", {
                    headers: { Authorization: `Bearer ${spotifyToken}` }
                });
                const me = await meRes.json();
                if (meRes.ok && me?.id) premium = isPremium(me.id);
            }
        } catch (e) {
            console.error("premium check failed", e);
        }

        const FREE_MAX = 40;
        const PREMIUM_MAX = 200;
        const hardMax = premium ? PREMIUM_MAX : FREE_MAX;
        requestedCount = Math.max(20, Math.min(hardMax, requestedCount));

        if (!userText) return res.status(400).json({ error: "Missing text" });

        const systemPrompt = `
You are an expert music curator and playlist designer.
You deeply understand mood, emotion, tempo, and how music guides feelings over time.
STRICT RULES:
-You will be given requested_count.
-You MUST return exactly requested_count tracks.
- Follow the user's mood, energy, language, and era strictly.
- If the user provides example songs or artists, include at least one of them in the playlist.
- Match the overall vibe to the examples given.
- Do NOT ignore constraints.
- Avoid generic or unrelated songs.
- Use plain ASCII characters only.
- Output clean, readable text.
-Example songs are emotional anchors.
-Do not drift far from the genre, emotional tone, and tempo of the example song.

Critical rules:
-Never ask for confirmation. Never ask questions.
-Do not write "approval needed" or similar.
-Always produce the final playlist output
-Absolutely no placeholders.
-Every track must be a real, widely known released song on Spotify.
-If unsure, replace with a safer mainstream real song.
-Never output "Alternative Track", "Project", "Artist - Song" guesses, or generic labels.
- Output MUST be valid JSON only, matching the provided schema.
- Do not invent fake songs. Prefer widely available tracks.
- Avoid repeating the same artist more than 2 times.

Language rule:
- If the user writes in Turkish, set language="tr" and write title+description in Turkish.
- If the user writes in English, set language="en" and write title+description in English.
- Do not mix languages in title/description.
-If the request is in Turkish and emotional, avoid aggressive Turkish rap or hard rock unless explicitly requested.

Emotional arc rule:
- Tracks 1–5: ease-in / set the mood
- Tracks 6–15: main emotional peak
- Tracks 16–20: resolution based on user input
-Energy interpretation rule:
-Energy refers to emotional flow and momentum, not loudness or aggression.
-Higher energy does NOT mean aggressive rap, trap, EDM, or hard rock unless explicitly requested.
-For energy levels 6-7, prefer midtempo, melodic, emotionally driven tracks that feel dynamic but controlled.



No cringe. No corporate tone.
IMPORTANT:
Use plain ASCII characters only.
Do not use smart quotes, special punctuation, or non-ASCII symbols.
Use simple apostrophes and standard characters only.
${spotifyProfileText}

    `.trim();

        const userPrompt = `User request: ${userText}\nrequested_count: ${requestedCount}`;

        // Make schema exact per request (no escaping to 50 etc.)
        const exactSchema = structuredClone(playlistSchema);
        exactSchema.schema.properties.tracks.minItems = requestedCount;
        exactSchema.schema.properties.tracks.maxItems = requestedCount;


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
        console.log("OPENAI_USAGE", response.usage || null);

        const data = JSON.parse(jsonText);
        // server-generated energy curve (saves output tokens)
        data.energy_curve = buildEnergyCurve((data.tracks && data.tracks.length) ? data.tracks.length : requestedCount);

        console.log("GENERATE_EVENT", {
            spotify_connected: Boolean(spotifyToken),
            requestedCount,
            time: new Date().toISOString()
        });

        // ---- admin stats: playlist_created (only if Spotify is connected) ----
        try {
            if (spotifyToken) {
                const meRes = await fetch("https://api.spotify.com/v1/me", {
                    headers: { Authorization: `Bearer ${spotifyToken}` }
                });
                const me = await meRes.json();
                if (meRes.ok && me?.id) {
                    markPlaylistCreated(me.id, `count=${requestedCount}`);
                }
            }
        } catch (e) {
            console.error("markPlaylistCreated failed:", e);
        }


        res.setHeader("Content-Type", "application/json; charset=utf-8");
        return res.json(data);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Failed to generate playlist" });
    }
});
async function saveSpotifyPlaylist(req, res) {
    try {
        const token = getCookie(req, "spotify_access_token");
        if (!token) return res.status(401).json({ error: "Spotify not connected" });

        const title = String(req.body?.title || "").trim() || "Spotimaker Playlist";
        const description = String(req.body?.description || "").trim();
        const tracks = Array.isArray(req.body?.tracks) ? req.body.tracks : [];

        if (tracks.length < 1) return res.status(400).json({ error: "No tracks provided" });

        // 1) Get current user
        const meRes = await fetch("https://api.spotify.com/v1/me", {
            headers: { Authorization: `Bearer ${token}` }
        });
        const me = await meRes.json();
        if (!meRes.ok) return res.status(500).json({ error: "Failed to read Spotify profile", details: me });
        // --- PREMIUM/FREE DAILY SAVE LIMIT ---
const premium = isPremium(me.id);
const FREE_DAILY_SAVE = 1;

if (!premium) {
    const savedToday = countSavedToday(me.id, "Europe/Istanbul");
    if (savedToday >= FREE_DAILY_SAVE) {
        return res.status(429).json({
            error: "Free gunluk Spotify'a kaydetme limiti doldu. Premium ile limitsiz.",
            savedToday,
            limit: FREE_DAILY_SAVE
        });
    }
}


        // 2) Create playlist
        const createRes = await fetch(`https://api.spotify.com/v1/users/${me.id}/playlists`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                name: title,
                description: description || "Made with Spotimaker",
                public: false
            })
        });

        const created = await createRes.json();
        if (!createRes.ok) return res.status(500).json({ error: "Failed to create playlist", details: created });

        const playlistId = created.id;

        // ---- helpers: normalize + concurrency-limited Spotify search ----
        function normalizeStr(s) {
            return String(s || "")
                .replace(/\s+/g, " ")
                .replace(/\((.*?)\)/g, "")      // remove (...) like (Remastered)
                .replace(/\[(.*?)\]/g, "")      // remove [...] like [Live]
                .replace(/feat\.?/ig, "")
                .replace(/ft\.?/ig, "")
                .replace(/–/g, "-")
                .trim();
        }

        // Simple concurrency limiter (no deps)
        async function mapLimit(items, limit, mapper) {
            const results = new Array(items.length);
            let i = 0;
            const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
                while (true) {
                    const idx = i++;
                    if (idx >= items.length) break;
                    results[idx] = await mapper(items[idx], idx);
                }
            });
            await Promise.all(workers);
            return results;
        }

        // helper: search a track URI (better query + safer fallback)
        async function findTrackUri(artist, song) {
            const a = normalizeStr(artist);
            const s = normalizeStr(song);
            if (!a || !s) return null;

            // 1) strict query with quotes
            const q1 = `track:"${s}" artist:"${a}"`;
            const url1 = `https://api.spotify.com/v1/search?type=track&limit=1&q=${encodeURIComponent(q1)}`;

            const r1 = await fetch(url1, { headers: { Authorization: `Bearer ${token}` } });
            const j1 = await r1.json().catch(() => ({}));
            if (r1.ok) {
                const item1 = j1?.tracks?.items?.[0];
                if (item1?.uri) return item1.uri;
            }

            // 2) fallback: broader query
            const q2 = `${s} ${a}`;
            const url2 = `https://api.spotify.com/v1/search?type=track&limit=1&q=${encodeURIComponent(q2)}`;

            const r2 = await fetch(url2, { headers: { Authorization: `Bearer ${token}` } });
            const j2 = await r2.json().catch(() => ({}));
            if (!r2.ok) return null;

            const item2 = j2?.tracks?.items?.[0];
            return item2?.uri || null;
        }

        // 3) Resolve URIs (concurrency-limited for speed + avoid rate limits)
        const cleanedTracks = (tracks || [])
            .map(t => ({
                artist: String(t.artist || "").trim(),
                song: String(t.song || "").trim()
            }))
            .filter(t => t.artist && t.song);

        const resolved = await mapLimit(cleanedTracks, 8, async (t) => { // 8 = good default
            const uri = await findTrackUri(t.artist, t.song);
            return { ...t, uri };
        });

        const uris = resolved.filter(x => x.uri).map(x => x.uri);
        const skipped = resolved.filter(x => !x.uri).map(x => ({ artist: x.artist, song: x.song }));

        if (uris.length === 0) {
            return res.status(400).json({
                error: "No tracks matched on Spotify",
                playlist: created,
                skipped
            });
        }

        // 4) Add to playlist (Spotify allows up to 100 URIs per request)
        // ---- helper: add tracks with retry (handles 429 + transient 5xx) ----
        async function addTracksChunkWithRetry(playlistId, chunk, maxAttempts = 4) {
            let attempt = 0;

            while (attempt < maxAttempts) {
                attempt++;

                const addRes = await fetch(`https://api.spotify.com/v1/playlists/${playlistId}/tracks`, {
                    method: "POST",
                    headers: {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ uris: chunk })
                });

                const text = await addRes.text().catch(() => "");
                let addJson = {};
                try { addJson = text ? JSON.parse(text) : {}; } catch { addJson = { raw: text }; }

                // success
                if (addRes.ok) return { ok: true, data: addJson };

                // token expired / auth issues -> no point retrying
                if (addRes.status === 401 || addRes.status === 403) {
                    return { ok: false, status: addRes.status, data: addJson, fatal: true };
                }

                // rate limited -> wait and retry
                if (addRes.status === 429) {
                    const ra = Number(addRes.headers.get("retry-after") || "1");
                    const waitMs = Math.max(1000, ra * 1000);
                    await new Promise(r => setTimeout(r, waitMs));
                    continue;
                }

                // transient server errors -> retry with backoff
                if (addRes.status >= 500 && addRes.status <= 599) {
                    const waitMs = 600 * attempt; // simple backoff
                    await new Promise(r => setTimeout(r, waitMs));
                    continue;
                }

                // other 4xx -> probably bad request, don't retry
                return { ok: false, status: addRes.status, data: addJson, fatal: true };
            }

            return { ok: false, status: 429, data: { error: { message: "rate_limited_retries_exhausted" } }, fatal: true };
        }

        // 4) Add to playlist (Spotify allows up to 100 URIs per request)
        for (let i = 0; i < uris.length; i += 100) {
            const chunk = uris.slice(i, i + 100);

            const r = await addTracksChunkWithRetry(playlistId, chunk, 4);
            if (!r.ok) {
                console.error("Failed adding tracks:", r.status, r.data);

                return res.status(500).json({
                    error: `Failed adding tracks (status ${r.status})`,
                    spotify: r.data,
                    playlist: created,
                    skipped
                });
            }
        }
        
            // ---- admin stats: playlist_saved (write once, after all chunks succeed) ----
            try {
                if (me?.id) {
                    markPlaylistSaved(
                        me.id,
                        `playlist=${playlistId};added=${uris.length};requested=${tracks.length};skipped=${skipped.length}`
                    );
                }
            } catch (e) {
                console.error("markPlaylistSaved failed:", e);
            }
    
        
        console.log("SAVE_EVENT", {
            spotify_id: me?.id,
            playlistId,
            added: uris.length,
            requested: tracks.length,
            skipped: skipped.length,
            time: new Date().toISOString()
        });

        return res.json({
            ok: true,
            added: uris.length,
            requested: tracks.length,
            skipped,
            playlist: {
                id: playlistId,
                name: created.name,
                url: created.external_urls?.spotify || null
            }
        });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: "Spotify save failed" });
    }
}
app.post("/spotify/save", saveSpotifyPlaylist);
app.post("/api/spotify/save", saveSpotifyPlaylist);

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


app.get("/admin", (req, res) => {
    try {
        if (!requireAdmin(req, res)) return;

        const stats = getStats();
        const users = getUsers(200);

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
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Spotimaker Admin</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial; padding:24px; max-width:1100px; margin:0 auto;}
    .cards{display:flex; gap:12px; flex-wrap:wrap; margin-bottom:16px;}
    .card{border:1px solid #ddd; border-radius:12px; padding:12px 14px; min-width:180px;}
    table{width:100%; border-collapse:collapse;}
    th,td{border-bottom:1px solid #eee; padding:10px; font-size:14px;}
    th{text-align:left; background:#fafafa; position:sticky; top:0;}
  </style>
</head>
<body>
  <h1>Spotimaker Admin</h1>
  <div class="cards">
    <div class="card"><b>Total users</b><div>${stats.totalUsers}</div></div>
    <div class="card"><b>Active 24h</b><div>${stats.active24h}</div></div>
    <div class="card"><b>Total events</b><div>${stats.totalEvents}</div></div>
  </div>

  <h2>Users (latest first)</h2>
  <table>
    <thead>
      <tr>
        <th>Display name</th>
        <th>Spotify ID</th>
        <th>First seen</th>
        <th>Last seen</th>
        <th>Created</th>
        <th>Saved</th>
        <th>Logins</th>
      </tr>
    </thead>
    <tbody>
      ${(users || []).map(row).join("")}
    </tbody>
  </table>
</body>
</html>`);
    } catch (e) {
        console.error("ADMIN ERROR:", e);
        return res.status(500).send("Admin crashed. Check logs.");
    }
});


// static LAST
app.use(express.static(path.join(__dirname, "public")));

const port = process.env.PORT || 8787;
app.listen(port, () => {
    console.log(`Spotimaker running on http://localhost:${port}`);
});
