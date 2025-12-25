import express from "express";
import OpenAI from "openai";
import path from "path";
import { fileURLToPath } from "url";
import querystring from "querystring";
import crypto from "crypto";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ROUTES (static'ten once)
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

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
        redirect_uri: process.env.SPOTIFY_REDIRECT_URI,
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
            redirect_uri: process.env.SPOTIFY_REDIRECT_URI
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
    app.use(express.static(path.join(__dirname, "public")));

    const port = process.env.PORT || 8787;
    app.listen(port, () => {
        console.log(`Spotimaker running on http://localhost:${port}`);
    });

});




