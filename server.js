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

const upload = multer({
    dest: "/tmp/uploads",
    limits: { fileSize: 30 * 1024 * 1024 },
}); // 30MB limit
const app = express();

const SERVICE_KEY = process.env.SERVICE_KEY || "";
const PORT = process.env.PORT || 4001;

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

app.listen(PORT, () => console.log(`parser-service listening on ${PORT}`));
