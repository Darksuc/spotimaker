import express from "express";
import OpenAI from "openai";
import path from "path";
import { fileURLToPath } from "url";
import querystring from "querystring";
import crypto from "crypto";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- cookie helpers (MVP) ---
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
    res.setHeader("Set-Cookie", cookie);
}

function getCookie(req, name) {
    const header = req.headers.cookie || "";
    const parts = header.split(";").map(v => v.trim());
    const found = parts.find(p => p.startsWith(name + "="));
    if (!found) return "";
    return decodeURIComponent(found.split("=").slice(1).join("="));
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
            energy_curve: {
                type: "array",
                minItems: 20,
                maxItems: 20,
                items: { type: "integer", minimum: 1, maximum: 10 }
            },
            tracks: {
                type: "array",
                minItems: 20,
                maxItems: 20,
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
        required: ["language", "title", "description", "vibe_tags", "energy_curve", "tracks"]
    }
};

// --- ROUTES ---

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Spotify OAuth
app.get("/login", (req, res) => {
    const state = crypto.randomBytes(12).toString("hex");
    setCookie(res, "spotify_state", state, 10 * 60 * 1000);

    const scope = [
        "user-top-read",
        "playlist-read-private",
        "playlist-modify-public",
        "playlist-modify-private"
    ].join(" ");

    const params = querystring.stringify({
        response_type: "code",
        client_id: process.env.SPOTIFY_CLIENT_ID,
        scope,
        redirect_uri: process.env.SPOTIFY_REDIRECT_URI.trim(),
        state
    });

    res.redirect(`https://accounts.spotify.com/authorize?${params}`);
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
            redirect_uri: process.env.SPOTIFY_REDIRECT_URI.trim()
        });
        function requireSpotifyToken(req, res) {
            const token = getCookie(req, "spotify_access_token");
            if (!token) {
                res.status(401).json({ error: "Not logged in to Spotify. Go to /login" });
                return null;
            }
            return token;
        }
        app.get("/spotify/top", async (req, res) => {
            try {
                const token = requireSpotifyToken(req, res);
                if (!token) return;

                const timeRange = String(req.query.time_range || "short_term"); // short_term | medium_term | long_term

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

        setCookie(res, "spotify_access_token", data.access_token, (data.expires_in || 3600) * 1000);
        return res.redirect("/");
    } catch (err) {
        console.error(err);
        return res.status(500).send("Callback failed");
    }
});

// AI generate
app.post("/api/generate", async (req, res) => {
    try {
        const spotifyToken = getCookie(req, "spotify_access_token");
        let spotifyProfileText = "";

        if (spotifyToken) {
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
                }
            } catch (e) {
                console.error("Spotify profile fetch failed", e);
            }
        }

        const userText = String(req.body?.text ?? "").trim();
        if (!userText) return res.status(400).json({ error: "Missing text" });

        const systemPrompt = `
You are an expert music curator and playlist designer.
You deeply understand mood, emotion, tempo, and how music guides feelings over time.
STRICT RULES:
- Follow the user's mood, energy, language, and era strictly.
- If the user provides example songs or artists, include at least one of them in the playlist.
- Match the overall vibe to the examples given.
- Do NOT ignore constraints.
- Avoid generic or unrelated songs.
- Use plain ASCII characters only.
- Output clean, readable text.

Critical rules:
- Output MUST be valid JSON only, matching the provided schema.
- Do not invent fake songs. Prefer widely available tracks.
- Avoid repeating the same artist more than 2 times.

Language rule:
- If the user writes in Turkish, set language="tr" and write title+description in Turkish.
- If the user writes in English, set language="en" and write title+description in English.
- Do not mix languages in title/description.

Emotional arc rule:
- Tracks 1–5: ease-in / set the mood
- Tracks 6–15: main emotional peak
- Tracks 16–20: resolution based on user input


No cringe. No corporate tone.
IMPORTANT:
Use plain ASCII characters only.
Do not use smart quotes, special punctuation, or non-ASCII symbols.
Use simple apostrophes and standard characters only.
${spotifyProfileText}

    `.trim();

        const userPrompt = `User request: ${userText}`;

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
                    schema: playlistSchema.schema,
                    strict: true
                }
            }
        });

        const jsonText = response.output_text;
        const data = JSON.parse(jsonText);

        res.setHeader("Content-Type", "application/json; charset=utf-8");
        return res.json(data);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Failed to generate playlist" });
    }
});

// static LAST
app.use(express.static(path.join(__dirname, "public")));

const port = process.env.PORT || 8787;
app.listen(port, () => {
    console.log(`Spotimaker running on http://localhost:${port}`);
});
