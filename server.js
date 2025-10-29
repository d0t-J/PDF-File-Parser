/**
 * server.js
 * PDF/TXT parser with OCR fallback using pdftoppm + tesseract CLI.
 *
 * POST /parse-pdf
 * - form field: file (binary)
 * - form field: job_description (string)
 * - header: x-service-key: <SERVICE_KEY> (if SERVICE_KEY env var set)
 *
 * Returns JSON { parsedResume, computedScore, rawText, ocrUsed, pagesProcessed }
 */

import express from "express";
import multer from "multer";
import fs from "fs/promises";
import path from "path";
import os from "os";
import { spawn } from "child_process";
import pdf from "pdf-parse";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import fsSync from "fs";

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret_change_me";
const STORAGE_DIR =
    process.env.STORAGE_DIR || path.join(process.cwd(), "storage");

// ensure a cross-platform temp upload directory (use OS temp on Windows/Linux)
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(os.tmpdir(), "uploads");
if (!fsSync.existsSync(UPLOAD_DIR))
    fsSync.mkdirSync(UPLOAD_DIR, { recursive: true });

if (!fsSync.existsSync(STORAGE_DIR))
    fsSync.mkdirSync(STORAGE_DIR, { recursive: true });

// init sqlite DB (file stored inside app; on App Platform this is ephemeral unless you use volumes — ok for demo)
const DB_PATH = process.env.DB_PATH || path.join(process.cwd(), "data.sqlite");
const db = new Database(DB_PATH);

// create tables if not exist
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS resumes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  filename TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  parsed_json TEXT,
  job_description TEXT,
  computed_score INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS interviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  resume_id INTEGER,
  job_description TEXT,
  history_json TEXT DEFAULT '[]',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (resume_id) REFERENCES resumes(id)
);
`);

// --- Auth helpers & endpoints ---

function generateToken(user) {
    return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
        expiresIn: "12h",
    });
}

function authMiddleware(req, res, next) {
    const auth = (req.headers.authorization || "").split(" ");
    if (auth.length !== 2 || auth[0] !== "Bearer")
        return res.status(401).json({ error: "Missing token" });
    const token = auth[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // { id, email, iat, exp }
        return next();
    } catch (e) {
        return res.status(401).json({ error: "Invalid token" });
    }
}

app.post("/signup", express.json(), async (req, res) => {
    try {
        const { email, password } = req.body || {};
        if (!email || !password)
            return res.status(400).json({ error: "email & password required" });
        const exists = db
            .prepare("SELECT id FROM users WHERE email = ?")
            .get(email);
        if (exists)
            return res.status(400).json({ error: "User already exists" });
        const hash = await bcrypt.hash(password, 10);
        const info = db
            .prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .run(email, hash);
        const user = { id: info.lastInsertRowid, email };
        const token = generateToken(user);
        return res.json({ token, user: { id: user.id, email: user.email } });
    } catch (err) {
        console.error("signup error:", err);
        return res.status(500).json({ error: String(err) });
    }
});

app.post("/login", express.json(), (req, res) => {
    try {
        const { email, password } = req.body || {};
        if (!email || !password)
            return res.status(400).json({ error: "email & password required" });
        const row = db
            .prepare(
                "SELECT id, email, password_hash FROM users WHERE email = ?"
            )
            .get(email);
        if (!row) return res.status(401).json({ error: "Invalid credentials" });
        const ok = bcrypt.compareSync(password, row.password_hash);
        if (!ok) return res.status(401).json({ error: "Invalid credentials" });
        const token = generateToken({ id: row.id, email: row.email });
        return res.json({ token, user: { id: row.id, email: row.email } });
    } catch (err) {
        console.error("login error:", err);
        return res.status(500).json({ error: String(err) });
    }
});

const upload = multer({
    dest: UPLOAD_DIR,
    limits: { fileSize: 30 * 1024 * 1024 },
}); // 30MB limit

const SERVICE_KEY = process.env.SERVICE_KEY || "";
const PORT = process.env.PORT || 4001;

// Basic health endpoints
app.get("/", (_req, res) => res.json({ ok: true, service: "parser-service" }));
app.get("/healthz", (_req, res) => res.status(200).send("ok"));

/* ----------------- utility functions ----------------- */

function runCommand(cmd, args, opts = {}) {
    return new Promise((resolve, reject) => {
        const ps = spawn(cmd, args, {
            stdio: ["ignore", "pipe", "pipe"],
            ...opts,
        });
        let stdout = "";
        let stderr = "";
        ps.stdout.on("data", (d) => (stdout += d.toString()));
        ps.stderr.on("data", (d) => (stderr += d.toString()));
        ps.on("close", (code) => {
            if (code === 0) resolve({ stdout, stderr, code });
            else
                reject(
                    new Error(
                        `Command ${cmd} ${args.join(
                            " "
                        )} exited ${code} : ${stderr}`
                    )
                );
        });
    });
}

async function pdfToPNGs(pdfPath, outPrefix) {
    // convert PDF to PNG pages using pdftoppm
    await runCommand("pdftoppm", ["-png", pdfPath, outPrefix]);
    const dir = path.dirname(outPrefix);
    const base = path.basename(outPrefix);
    const files = await fs.readdir(dir);
    const matches = files
        .filter((f) => f.startsWith(base) && f.endsWith(".png"))
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    return matches.map((f) => path.join(dir, f));
}

async function tesseractImageToText(imgPath, lang = "eng") {
    const { stdout } = await runCommand("tesseract", [
        imgPath,
        "stdout",
        "-l",
        lang,
    ]);
    return stdout;
}

/* ----------------- parsing heuristics ----------------- */

function parseResumeHeuristics(rawText) {
    rawText = (rawText || "").replace(/\r\n/g, "\n").trim();
    const out = {
        name: null,
        email: null,
        skills: [],
        experience: [],
        education: [],
        resume_text: rawText,
    };

    const emailMatch = rawText.match(
        /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}/i
    );
    if (emailMatch) out.email = emailMatch[0];

    const lines = rawText
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
    for (let i = 0; i < Math.min(6, lines.length); i++) {
        const l = lines[i];
        if (
            !l.includes("@") &&
            /^[A-Za-z ,.'-]+$/.test(l) &&
            l.split(" ").length >= 2 &&
            l.length < 60
        ) {
            out.name = l;
            break;
        }
    }

    const lower = rawText.toLowerCase();
    const KNOWN = [
        "python",
        "java",
        "c++",
        "c#",
        "javascript",
        "typescript",
        "react",
        "vue",
        "angular",
        "node",
        "express",
        "django",
        "flask",
        "sql",
        "postgresql",
        "mysql",
        "mongodb",
        "git",
        "docker",
        "kubernetes",
        "aws",
        "gcp",
        "azure",
        "tensorflow",
        "pytorch",
        "nlp",
        "linux",
        "rest",
        "grpc",
        "graphql",
    ];
    const skillCandidates = new Set();
    for (const k of KNOWN) if (lower.includes(k)) skillCandidates.add(k);

    const skillSection = rawText.match(/skills?:\s*([\s\S]{0,300})/i);
    if (skillSection) {
        const tokens = skillSection[1]
            .split(/[,•\n\/;|-]/)
            .map((s) => s.trim())
            .filter(Boolean);
        for (const t of tokens) {
            if (t.length < 60) skillCandidates.add(t.toLowerCase());
        }
    }

    out.skills = Array.from(skillCandidates).slice(0, 80);

    const blocks = rawText
        .split(/\n{2,}/)
        .map((b) => b.trim())
        .filter(Boolean);
    for (const b of blocks) {
        if (
            /experience|company|intern|software|engineer|developer|worked at|responsible for/i.test(
                b
            ) ||
            /\b(20|19)\d{2}\b/.test(b)
        ) {
            const firstLine = b.split("\n")[0];
            let title = null,
                org = null;
            const atParts = firstLine.split(/ at |,@ |, | - | — /i);
            if (atParts.length >= 2) {
                title = atParts[0].trim();
                org = atParts.slice(1).join(" ").trim();
            } else {
                title = firstLine.trim();
            }
            const yearsMatch = b.match(
                /(\b(19|20)\d{2}\b)(?:\s*[-–to]+\s*(\b(19|20)\d{2}\b))?/i
            );
            const years = yearsMatch ? yearsMatch[0] : null;
            out.experience.push({ title, org, desc: b, years });
        }
        if (/education|university|college|degree|bachelor|master/i.test(b)) {
            out.education.push(b);
        }
    }

    return out;
}

function computeScore(parsedResume, jobDesc) {
    const jd = (jobDesc || "").toLowerCase();
    const jdSkills = jd.match(/([a-z0-9+#\.\-]{2,30})/g) || [];
    const tokenFilter = jdSkills
        .filter((t) => /[a-z]/i.test(t))
        .map((t) => t.toLowerCase());
    const uniqueJd = Array.from(new Set(tokenFilter)).slice(0, 80);

    const resumeSkills = (parsedResume.skills || []).map((s) =>
        s.toLowerCase()
    );
    const matched = uniqueJd.filter((k) =>
        resumeSkills.some((rs) => rs.includes(k) || k.includes(rs))
    ).length;
    const jdCount = uniqueJd.length || 0;
    const keyword_overlap = jdCount
        ? matched / jdCount
        : Math.min(resumeSkills.length / 6, 1);

    const yearsReq = (jd.match(/(\b[1-9]\d?)\+?\s*(years|yrs)/i) || [])[1];
    let years_score = 0.8;
    if (yearsReq) {
        const req = parseInt(yearsReq, 10);
        let tot = 0;
        (parsedResume.experience || []).forEach((e) => {
            const m = (e.years || "").match(
                /(\b(19|20)\d{2}\b).*(\b(19|20)\d{2}\b)/
            );
            if (m) {
                const y1 = parseInt(m[1]);
                const y2 = parseInt(m[3]);
                if (!isNaN(y1) && !isNaN(y2)) tot += Math.abs(y2 - y1);
            }
        });
        years_score = req && tot ? Math.min(tot / req, 1) : 0.4;
    }

    const finalScore = Math.round(
        (0.6 * keyword_overlap + 0.4 * years_score) * 100
    );
    return {
        score: finalScore,
        matched,
        jdCount,
        keyword_overlap,
        years_score,
    };
}

/* ----------------- main route ----------------- */

app.post("/parse-pdf", upload.single("file"), async (req, res) => {
    try {
        if (SERVICE_KEY) {
            const key = (req.headers["x-service-key"] || "").toString();
            if (!key || key !== SERVICE_KEY) {
                return res
                    .status(401)
                    .json({ error: "Unauthorized (invalid service key)" });
            }
        }

        const job_description = (req.body.job_description || "").toString();
        if (!req.file)
            return res
                .status(400)
                .json({ error: "Missing 'file' in form-data" });

        const filePath = req.file.path;
        const originalName = req.file.originalname || "";
        const ext = (originalName.split(".").pop() || "").toLowerCase();

        let rawText = "";
        let ocrUsed = false;
        let pagesProcessed = 0;

        if (ext === "txt" || req.file.mimetype === "text/plain") {
            rawText = (await fs.readFile(filePath, "utf8")).toString();
        } else {
            const data = await fs.readFile(filePath);
            try {
                const parsed = await pdf(data, { max: 50 });
                rawText = parsed && parsed.text ? parsed.text.trim() : "";
            } catch (e) {
                rawText = "";
            }

            if (!rawText || rawText.length < 150) {
                ocrUsed = true;
                const outPrefix = path.join(
                    os.tmpdir(),
                    `pdf2img_${Date.now()}`
                );
                try {
                    const pngFiles = await pdfToPNGs(filePath, outPrefix);
                    pagesProcessed = pngFiles.length;
                    const ocrTexts = [];
                    for (const p of pngFiles) {
                        try {
                            const txt = await tesseractImageToText(p, "eng");
                            ocrTexts.push(txt.trim());
                        } catch (ocrErr) {
                            console.warn(
                                "OCR error for page:",
                                p,
                                ocrErr.message
                            );
                        }
                    }
                    rawText = ocrTexts.join("\n\n");
                    for (const p of pngFiles) {
                        try {
                            await fs.unlink(p);
                        } catch {}
                    }
                } catch (convErr) {
                    console.warn(
                        "PDF->PNG conversion failed:",
                        convErr.message
                    );
                }
            }
        }

        if (!rawText) rawText = "";

        const parsedResume = parseResumeHeuristics(rawText);
        const computed = computeScore(parsedResume, job_description);

        try {
            await fs.unlink(filePath);
        } catch (e) {
            /* ignore */
        }

        return res.json({
            parsedResume,
            computedScore: computed.score,
            rawText,
            ocrUsed,
            pagesProcessed,
            _debug: computed,
        });
    } catch (err) {
        console.error("parse-pdf error:", err);
        return res.status(500).json({ error: String(err) });
    }
});

// POST /upload-and-save  (authenticated)
// form-data: file (pdf/txt), job_description (text)
app.post(
    "/upload-and-save",
    authMiddleware,
    upload.single("file"),
    async (req, res) => {
        try {
            if (!req.file)
                return res.status(400).json({ error: "Missing file" });

            // reuse code: read file and get rawText + parsedResume + computedScore
            const filePath = req.file.path;
            const originalName = req.file.originalname || "";
            const ext = (originalName.split(".").pop() || "").toLowerCase();

            // extract rawText using same logic as parse route
            let rawText = "";
            let ocrUsed = false;
            let pagesProcessed = 0;

            if (ext === "txt" || req.file.mimetype === "text/plain") {
                rawText = (await fs.readFile(filePath, "utf8")).toString();
            } else {
                const data = await fs.readFile(filePath);
                try {
                    const parsed = await pdf(data, { max: 50 });
                    rawText = parsed && parsed.text ? parsed.text.trim() : "";
                } catch (e) {
                    rawText = "";
                }
                if (!rawText || rawText.length < 150) {
                    ocrUsed = true;
                    const outPrefix = path.join(
                        os.tmpdir(),
                        `pdf2img_${Date.now()}`
                    );
                    try {
                        const pngFiles = await pdfToPNGs(filePath, outPrefix);
                        pagesProcessed = pngFiles.length;
                        const ocrTexts = [];
                        for (const p of pngFiles) {
                            try {
                                const txt = await tesseractImageToText(
                                    p,
                                    "eng"
                                );
                                ocrTexts.push(txt.trim());
                            } catch (e) {
                                console.warn("ocr page err", e.message);
                            }
                        }
                        rawText = ocrTexts.join("\n\n");
                        for (const p of pngFiles) {
                            try {
                                await fs.unlink(p);
                            } catch {}
                        }
                    } catch (err) {
                        console.warn(
                            "pdf->png conversion failed:",
                            err.message
                        );
                    }
                }
            }
            if (!rawText) rawText = "";

            // parse & compute (re-use your functions)
            const parsedResume = parseResumeHeuristics(rawText);
            const computed = computeScore(
                parsedResume,
                req.body.job_description || ""
            );

            // Persist file: create unique filename and move to STORAGE_DIR
            const uid = uuidv4();
            const storedFilename = `${Date.now()}_${uid}_${originalName.replace(
                /\s+/g,
                "_"
            )}`;
            const destPath = path.join(STORAGE_DIR, storedFilename);
            // move file into storage safely (rename may fail across devices -> fallback to copy)
            try {
                await fs.rename(filePath, destPath);
            } catch (renameErr) {
                // fallback: copy + unlink
                try {
                    const dataBuf = await fs.readFile(filePath);
                    await fs.writeFile(destPath, dataBuf);
                    await fs.unlink(filePath);
                } catch (copyErr) {
                    console.error(
                        "Failed to move uploaded file:",
                        renameErr,
                        copyErr
                    );
                    return res
                        .status(500)
                        .json({ error: "Failed to store uploaded file." });
                }
            }

            // Save record in DB
            const insert = db.prepare(
                `INSERT INTO resumes (user_id, filename, stored_path, parsed_json, job_description, computed_score) VALUES (?, ?, ?, ?, ?, ?)`
            );
            const info = insert.run(
                req.user.id,
                originalName,
                destPath,
                JSON.stringify(parsedResume),
                req.body.job_description || "",
                computed.score
            );

            const resumeId = info.lastInsertRowid;

            return res.json({
                ok: true,
                resumeId,
                parsedResume,
                computedScore: computed.score,
                stored_path: destPath,
                ocrUsed,
                pagesProcessed,
            });
        } catch (err) {
            console.error("upload-and-save error:", err);
            return res.status(500).json({ error: String(err) });
        }
    }
);

app.get("/resumes", authMiddleware, (req, res) => {
    try {
        const rows = db
            .prepare(
                "SELECT id, filename, job_description, computed_score, created_at FROM resumes WHERE user_id = ? ORDER BY created_at DESC"
            )
            .all(req.user.id);
        return res.json({ resumes: rows });
    } catch (err) {
        console.error("resumes error:", err);
        return res.status(500).json({ error: String(err) });
    }
});

// Optional: serve file download (only for owner)
app.get("/resumes/:id/download", authMiddleware, (req, res) => {
    const id = parseInt(req.params.id, 10);
    const row = db
        .prepare(
            "SELECT user_id, filename, stored_path FROM resumes WHERE id = ?"
        )
        .get(id);
    if (!row) return res.status(404).json({ error: "Not found" });
    if (row.user_id !== req.user.id)
        return res.status(403).json({ error: "Forbidden" });
    return res.download(row.stored_path, row.filename);
});

// ---------- 3F: OpenAI helper + interview endpoints ----------
/**
 * callLLM(messages)
 * - uses global fetch (Node 18+) or falls back to node-fetch if unavailable.
 * - returns parsed JSON response from OpenAI call or null if OPENAI_KEY missing.
 */
/**
 * callLLM(messages)
 * - Supports two providers:
 *   1) AI/ML API (aimlapi.com) if AIMLAPI_KEY is set (base: AIMLAPI_BASE or https://api.aimlapi.com)
 *   2) OpenAI if OPENAI_KEY is set (fallback)
 *
 * Both providers accept an OpenAI-compatible chat/completions request.
 * The function returns the parsed JSON response from the provider.
 */
async function callLLM(messages) {
    // choose provider
    const aimlKey = process.env.AIMLAPI_KEY || process.env.AIML_API_KEY || "";
    const openaiKey = process.env.OPENAI_KEY || "";

    // no provider configured
    if (!aimlKey && !openaiKey) return null;

    // ensure global fetch exists (Node 18+). If not present, dynamically import node-fetch
    if (typeof fetch === "undefined") {
        // eslint-disable-next-line no-undef
        global.fetch = (await import("node-fetch")).default;
    }

    // Prepare OpenAI-style payload
    const payload = {
        model:
            process.env.AI_MODEL ||
            process.env.OPENAI_MODEL ||
            "openai/gpt-5-pro",
        messages,
        temperature: parseFloat(process.env.AI_TEMP || "0.2"),
        max_tokens: parseInt(process.env.AI_MAX_TOKENS || "700", 10),
    };

    // 1) if AIMLAPI_KEY available, call AI/ML API (OpenAI-compatible)
    if (aimlKey) {
        const base =
            process.env.AIMLAPI_BASE ||
            process.env.AIML_API_BASE ||
            "https://api.aimlapi.com";
        const url = `${base.replace(/\/$/, "")}/v1/chat/completions`;
        const resp = await fetch(url, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${aimlKey}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });
        if (!resp.ok) {
            const errText = await resp.text();
            throw new Error(`AI/ML API error ${resp.status}: ${errText}`);
        }
        return await resp.json();
    }

    // 2) fallback to OpenAI
    if (openaiKey) {
        const url = "https://api.openai.com/v1/chat/completions";
        const resp = await fetch(url, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${openaiKey}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });
        if (!resp.ok) {
            const errText = await resp.text();
            throw new Error(`OpenAI error ${resp.status}: ${errText}`);
        }
        return await resp.json();
    }

    return null;
}

// Start an interview session
app.post(
    "/interview/start",
    authMiddleware,
    express.json(),
    async (req, res) => {
        try {
            const { resume_id } = req.body || {};
            if (!resume_id)
                return res.status(400).json({ error: "resume_id required" });

            const rr = db
                .prepare(
                    "SELECT parsed_json, job_description FROM resumes WHERE id = ? AND user_id = ?"
                )
                .get(resume_id, req.user.id);
            if (!rr) return res.status(404).json({ error: "Resume not found" });

            const parsed = JSON.parse(rr.parsed_json || "{}");
            const jobDesc = rr.job_description || "";

            const systemPrompt = `You are a concise mock interviewer. Use the resume JSON and job description to ask targeted interview questions. Ask one question at a time. Return plain text (question) as the assistant response.`;
            const messages = [
                { role: "system", content: systemPrompt },
                {
                    role: "user",
                    content: JSON.stringify({
                        resume: parsed,
                        job_description: jobDesc,
                    }),
                },
            ];

            let firstQuestion =
                "Tell me about a recent project you worked on that's relevant to this role.";
            // try LLM via AIMLAPI or OPENAI (callLLM chooses provider)
            try {
                const out = await callLLM(messages);
                if (out?.choices?.[0]?.message?.content) {
                    firstQuestion = out.choices[0].message.content.trim();
                }
            } catch (e) {
                console.warn("LLM first question failed:", e.message);
                // fallback keeps default firstQuestion
            }

            // persist interview
            const insert = db.prepare(
                "INSERT INTO interviews (user_id, resume_id, job_description, history_json) VALUES (?, ?, ?, ?)"
            );
            const info = insert.run(
                req.user.id,
                resume_id,
                jobDesc,
                JSON.stringify([{ role: "assistant", text: firstQuestion }])
            );
            const interviewId = info.lastInsertRowid;

            return res.json({ interviewId, next_question: firstQuestion });
        } catch (err) {
            console.error("interview/start error:", err);
            return res.status(500).json({ error: String(err) });
        }
    }
);

// Answer a question and get feedback + next question
app.post(
    "/interview/answer",
    authMiddleware,
    express.json(),
    async (req, res) => {
        try {
            const { interview_id, answer } = req.body || {};
            if (!interview_id || typeof answer !== "string")
                return res
                    .status(400)
                    .json({ error: "interview_id and answer required" });

            const row = db
                .prepare(
                    "SELECT id, user_id, resume_id, job_description, history_json FROM interviews WHERE id = ?"
                )
                .get(interview_id);
            if (!row)
                return res.status(404).json({ error: "Interview not found" });
            if (row.user_id !== req.user.id)
                return res.status(403).json({ error: "Forbidden" });

            const history = JSON.parse(row.history_json || "[]");
            history.push({ role: "user", text: answer });

            // prepare LLM messages (trim history to last few turns)
            const resumeRow = db
                .prepare("SELECT parsed_json FROM resumes WHERE id = ?")
                .get(row.resume_id);
            const parsedResume = resumeRow
                ? JSON.parse(resumeRow.parsed_json || "{}")
                : {};
            const jobDesc = row.job_description || "";

            const systemPrompt = `You are a mock interviewer + coach. Evaluate the user's last answer in 2-3 sentences (strengths + one improvement). Then ask a single concise follow-up question. Return JSON exactly: {"feedback":"...","next_question":"...","done":false}`;
            const messages = [
                { role: "system", content: systemPrompt },
                {
                    role: "user",
                    content: JSON.stringify({
                        resume: parsedResume,
                        job_description: jobDesc,
                        history: history.slice(-8),
                    }),
                },
            ];

            let feedback =
                "Nice answer — be more specific and add numbers if possible.";
            let nextQ =
                "What was the most technically difficult bug you fixed? Describe steps you took.";
            let done = false;

            // try LLM via AIMLAPI or OPENAI (callLLM chooses provider)
            try {
                const out = await callLLM(messages);
                const text = out?.choices?.[0]?.message?.content || "";
                try {
                    const parsedOut = JSON.parse(text);
                    feedback = parsedOut.feedback || feedback;
                    nextQ = parsedOut.next_question || nextQ;
                    done = parsedOut.done || false;
                } catch {
                    // fallback: use plain text pieces
                    const lines = text
                        .split("\n")
                        .map((l) => l.trim())
                        .filter(Boolean);
                    feedback = lines.slice(0, 2).join(" ") || feedback;
                    nextQ = lines.slice(2, 4).join(" ") || nextQ;
                }
            } catch (e) {
                console.warn("LLM interview/answer failed:", e.message);
                // fallback remains
            }

            history.push({ role: "assistant", text: feedback });
            if (!done) history.push({ role: "assistant", text: nextQ });

            db.prepare(
                "UPDATE interviews SET history_json = ? WHERE id = ?"
            ).run(JSON.stringify(history), interview_id);

            return res.json({ feedback, next_question: nextQ, done });
        } catch (err) {
            console.error("interview/answer error:", err);
            return res.status(500).json({ error: String(err) });
        }
    }
);

app.listen(PORT, () => console.log(`parser-service listening on ${PORT}`));
