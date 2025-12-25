import express from "express";
import OpenAI from "openai";
import path from "path";
import { fileURLToPath } from "url";


const app = express();
app.use(express.json());
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// JSON Schema: Spotimaker playlist çýktýsý
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
  },
  strict: true
};

app.post("/api/generate", async (req, res) => {
    try {
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

        setInterval(() => {
            // keep process alive
        }, 1000 * 60 * 5);

    }
});
