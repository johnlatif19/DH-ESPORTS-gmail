import express from "express";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import fs from "fs/promises";
import path from "path";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: true, limit: "200kb" }));
app.use(cookieParser());

function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

// ===== ENV =====
const JWT_SECRET = mustEnv("JWT_SECRET");
const ADMIN_USER = mustEnv("ADMIN_USER");
const ADMIN_PASS = mustEnv("ADMIN_PASS");

const SMTP_HOST = mustEnv("SMTP_HOST");
const SMTP_USER = mustEnv("SMTP_USER");
const SMTP_PASS = mustEnv("SMTP_PASS");
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || "false").toLowerCase() === "true";

const BRAND_NAME = process.env.BRAND_NAME || "Clan DH-ESPORTS";
const BRAND_URL = process.env.BRAND_URL || "https://clan-dh-esports.up.railway.app";
const LOGO_URL = process.env.LOGO_URL || "";
const FROM_NAME = process.env.FROM_NAME || BRAND_NAME;
const FROM_EMAIL = mustEnv("FROM_EMAIL");

// ===== Rate limits =====
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
});

const sendLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
});

// ===== SMTP =====
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE,
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

// ===== Helpers =====
function signToken(payload) {
  // JWT per RFC 7519 
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "2h" });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function authMiddleware(req, res, next) {
  const token = req.cookies?.auth_token;
  if (!token) return res.redirect("/login");
  try {
    req.user = verifyToken(token);
    next();
  } catch {
    return res.redirect("/login");
  }
}

function escapeHtml(str = "") {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Email HTML (tables + inline CSS) لعرض أفضل عبر عملاء البريد
function buildEmailHtml({ toEmail, subject, message }) {
  const safeMsg = escapeHtml(message).replaceAll("\n", "<br/>");
  const title = escapeHtml(subject || `رسالة من ${BRAND_NAME}`);

  // 🔥 اللوجو ثابت هنا
  const logo = "https://i.postimg.cc/x8GzBpJz/IMG-20260416-WA0124.jpg";

  return `
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes" />
  <title>DH-ESPORTS</title>
  <style>
    /* Basic resets and fallbacks for email clients */
    .ExternalClass, .ReadMsgBody { width: 100%; background-color: #0f172a; }
    body, table, td, p, a { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
    table, td { border-collapse: collapse; mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
    img { border: 0; height: auto; line-height: 100%; outline: none; text-decoration: none; -ms-interpolation-mode: bicubic; }
    /* Responsive container */
    @media screen and (max-width: 600px) {
      .email-container { width: 100% !important; }
      .content-padding { padding: 20px 16px !important; }
      .button-td { padding: 0 16px 30px !important; }
      .msg-inner { padding: 16px !important; }
      .header-inner { padding: 16px !important; }
      .brand-text { font-size: 16px !important; }
      .site-button { padding: 12px 24px !important; font-size: 15px !important; }
    }
  </style>
</head>
<body style="margin:0;padding:0;background:#0f172a;font-family: 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f172a;padding:30px 10px;" role="presentation">
    <tr>
      <td align="center">

        <!-- Main container: wider radius, energetic design -->
        <table width="600" cellpadding="0" cellspacing="0" class="email-container" style="max-width:600px;width:100%;background:#ffffff;border-radius:28px;overflow:hidden;box-shadow:0 20px 35px -12px rgba(0,0,0,0.25);border:1px solid rgba(255,255,255,0.08);">

          <!-- Dynamic Header with energetic gradient and bold style -->
          <tr>
            <td style="background:linear-gradient(135deg, #0b1120 0%, #1e293b 100%);padding:24px 28px;" align="left" class="header-inner">
              <table width="100%" role="presentation">
                <tr>
                  <td style="vertical-align:middle; width:60px;">
                    <!-- logo area with vibrant border/shadow -->
                    <img src="${logo}" width="54" style="border-radius:18px;display:block;box-shadow:0 8px 14px -6px rgba(0,0,0,0.3);border:2px solid rgba(59,130,246,0.4);" alt="Brand Logo" />
                  </td>
                  <td style="vertical-align:middle;padding-left:14px;">
                    <div style="font-size:22px;font-weight:800;color:#ffffff;letter-spacing:-0.3px;font-family:inherit;line-height:1.2;" class="brand-text">
                      ${BRAND_NAME}
                    </div>
                    <div style="font-size:13px;color:#a5f3fc;margin-top:6px;font-weight:500;letter-spacing:0.3px;background:rgba(255,255,255,0.1);display:inline-block;padding:2px 12px;border-radius:40px;">
                      ✨ ${title} ✨
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Highlight bar / decorative element -->
          <tr>
            <td style="background:linear-gradient(90deg, #3b82f6, #8b5cf6, #ec489a); height:5px;"></td>
          </tr>

          <!-- Main Message Block: vibrant and modern card style -->
          <tr>
            <td style="padding:30px 28px 20px 28px;font-family:inherit;color:#0f172a;" class="content-padding">
              <!-- Recipient line with cute icon -->
              <div style="font-size:14px;color:#475569;margin-bottom:18px;display:flex;align-items:center;gap:6px;background:#f8fafc;padding:8px 14px;border-radius:60px;width:fit-content;">
                <span style="font-size:16px;">📧</span> 
                <span style="font-weight:500;">إلى: </span> 
                <span style="font-weight:600;color:#0f172a;direction:ltr;unicode-bidi:embed;">${escapeHtml(toEmail)}</span>
              </div>

              <!-- Message bubble with energetic background, subtle pattern, engaging style -->
              <div style="background:linear-gradient(145deg, #ffffff 0%, #fefce8 100%);padding:22px 24px;border-radius:28px;font-size:16px;line-height:1.55;color:#1e293b;border-left:6px solid #f97316;box-shadow:0 6px 12px -8px rgba(0,0,0,0.1);">
                <!-- Adding a playful quote icon -->
                <div style="font-size:28px;margin-bottom:8px;opacity:0.7;">💬</div>
                <div style="font-weight:400;">
                  ${safeMsg}
                </div>
                <!-- tiny decorative spark -->
                <div style="margin-top:18px;border-top:2px dashed #fed7aa;padding-top:12px;font-size:13px;color:#b45309;display:flex;justify-content:flex-end;align-items:center;gap:6px;">
                </div>
              </div>
             </td>
          </tr>

          <!-- Action Button Area with energetic CTA & hover style (inline fallback) -->
          <tr>
            <td align="center" style="padding:10px 28px 35px 28px;" class="button-td">
              <table border="0" cellpadding="0" cellspacing="0" role="presentation">
                <tr>
                  <td align="center" style="border-radius:60px; background:linear-gradient(105deg, #2563eb 0%, #4f46e5 100%); box-shadow:0 10px 18px -8px #1e3a8a;">
                    <a href="${BRAND_URL}" 
                       style="display:inline-block; background:transparent; color:#ffffff; padding:14px 32px; border-radius:60px; text-decoration:none; font-weight:800; font-family:inherit; font-size:16px; letter-spacing:0.5px; border:1px solid rgba(255,255,255,0.2); transition: all 0.2s ease;">
                      🚀  زيارة الموقع  🚀
                    </a>
                  </td>
                </tr>
              </table>

          <!-- Extra flair: motivational mini section (keep fresh but simple) -->
          <tr>
            <td style="padding:0 28px 24px 28px;">
              <table width="100%" style="background:#f1f5f9; border-radius:24px; padding:12px 16px;" role="presentation">
                <tr>
                  <td align="center" style="font-size:13px; color:#334155; font-weight:500;">
                    ⚡ تواصل معنا على مدار الساعة ⚡ <br/>
                    <span style="color:#2563eb; font-weight:600;">${BRAND_NAME}</span> يقدم لك أفضل التجارب
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer: clean but with energetic vibe -->
          <tr>
            <td style="background:#111827; padding:22px 20px 20px; text-align:center;">
              <div style="color:#cbd5e1; font-size:12px; font-family:inherit; line-height:1.5;">
                © ${new Date().getFullYear()} ${BRAND_NAME} — جميع الحقوق محفوظة
              </div>

              <!-- invisible spacer for safety -->
              <div style="height:4px;"></div>
            </td>
          </tr>
        </table>

      </td>
    </tr>
  </table>
</body>
</html>
`;
}

async function sendHtmlPage(res, filename) {
  // مهم على Vercel: اقرأ من process.cwd() + includeFiles في vercel.json
  const filePath = path.join(process.cwd(), filename);
  const html = await fs.readFile(filePath, "utf8");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(html);
}

// ===== Pages =====
app.get("/", (req, res) => res.redirect("/dashboard"));

app.get("/login", async (req, res) => {
  try {
    await sendHtmlPage(res, "login.html");
  } catch (e) {
    res.status(500).send("Missing login.html (must be next to server.js + included in Vercel function)");
  }
});

app.get("/dashboard", authMiddleware, async (req, res) => {
  try {
    await sendHtmlPage(res, "dashboard.html");
  } catch (e) {
    res.status(500).send("Missing dashboard.html (must be next to server.js + included in Vercel function)");
  }
});

// ===== API: Auth =====
app.post("/api/auth/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: "Missing username/password" });
  }

  if (String(username) !== ADMIN_USER || String(password) !== ADMIN_PASS) {
    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  }

  const token = signToken({ sub: ADMIN_USER, role: "admin" });

  res.cookie("auth_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: true, // Vercel HTTPS
    maxAge: 2 * 60 * 60 * 1000,
    path: "/",
  });

  return res.json({ ok: true });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("auth_token", { path: "/" });
  res.json({ ok: true });
});

// ===== API: Send =====
app.post("/api/send", authMiddleware, sendLimiter, async (req, res) => {
  try {
    const { toEmail, subject, message } = req.body || {};
    if (!toEmail || !message) {
      return res.status(400).json({ ok: false, error: "toEmail and message are required" });
    }
    if (String(message).length > 5000) {
      return res.status(400).json({ ok: false, error: "Message too long" });
    }

    const html = buildEmailHtml({ toEmail, subject, message });

    const info = await transporter.sendMail({
      from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
      to: toEmail,
      subject: subject || `رسالة من ${BRAND_NAME}`,
      html,
      text: message,
    });

    // SMTP RFC 5321 
    return res.json({ ok: true, messageId: info.messageId });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err?.message || "Send failed" });
  }
});

// ===== Start (Local only) =====
// على Vercel مش هيحتاج listen فعليًا، بس وجوده مش بيكسر محليًا.
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on :${PORT}`));
