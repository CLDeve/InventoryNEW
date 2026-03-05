const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const ADMIN_INITIAL_PASSWORD = (process.env.ADMIN_INITIAL_PASSWORD || "ADMIN123").trim().toUpperCase();

if (!process.env.DATABASE_URL) {
  // eslint-disable-next-line no-console
  console.error("DATABASE_URL is required. Set it in Render environment.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false }
});

const app = express();
app.use(express.json({ limit: "10mb" }));

function createId() {
  return typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function normalizeUpper(value) {
  return String(value || "").trim().toUpperCase();
}

function normalizeAction(value) {
  return normalizeUpper(value) === "INACTIVE" ? "INACTIVE" : "ACTIVE";
}

function normalizeM2M(value) {
  return normalizeUpper(value) === "KNOX" ? "KNOX" : "SOTI";
}

function normalizeRetainLine(value) {
  return normalizeUpper(value) === "YES" ? "YES" : "NO";
}

function normalizeMonthlyCostPrice(value) {
  const normalized = String(value || "")
    .trim()
    .replace(/[$,\s]/g, "");
  const parsed = Number(normalized);
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return Number(parsed.toFixed(2));
}

function normalizeDateValue(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";

  function normalizeYear(yearInput) {
    const yearText = String(yearInput || "").trim();
    if (!/^\d{2,4}$/.test(yearText)) return null;
    const yearNumber = Number(yearText);
    if (yearText.length === 2) return 2000 + yearNumber;
    return yearNumber;
  }

  function monthFromText(text) {
    const monthMap = {
      JAN: 1, FEB: 2, MAR: 3, APR: 4, MAY: 5, JUN: 6,
      JUL: 7, AUG: 8, SEP: 9, OCT: 10, NOV: 11, DEC: 12
    };
    const key = String(text || "").trim().slice(0, 3).toUpperCase();
    return monthMap[key] || 0;
  }

  function toIsoDate(yearInput, monthInput, dayInput) {
    const year = Number(yearInput);
    const month = Number(monthInput);
    const day = Number(dayInput);
    if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) return "";
    if (month < 1 || month > 12 || day < 1 || day > 31) return "";

    const iso = `${String(year).padStart(4, "0")}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
    const date = new Date(`${iso}T00:00:00Z`);
    if (Number.isNaN(date.getTime())) return "";
    if (date.getUTCFullYear() !== year || date.getUTCMonth() + 1 !== month || date.getUTCDate() !== day) return "";
    return iso;
  }

  const core = raw
    .replace(/^\uFEFF/, "")
    .replace(/\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[APMapm]{2})?$/, "")
    .trim();

  // ISO date (also accepts timestamp-like suffixes from exported tools).
  const isoMatch = core.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[T\s].*)?$/);
  if (isoMatch) {
    const iso = toIsoDate(isoMatch[1], isoMatch[2], isoMatch[3]);
    if (iso) return iso;
  }

  // DD/MM/YYYY or D/M/YYYY
  // Also accepts MM/DD/YYYY when non-ambiguous.
  const slashNumeric = core.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})$/);
  if (slashNumeric) {
    const first = Number(slashNumeric[1]);
    const second = Number(slashNumeric[2]);
    const year = normalizeYear(slashNumeric[3]);
    if (!year) return "";

    const dmy = toIsoDate(year, second, first); // day/month/year
    const mdy = toIsoDate(year, first, second); // month/day/year
    if (first > 12 && second <= 12) return dmy;
    if (second > 12 && first <= 12) return mdy;
    if (dmy && mdy) return dmy;
    if (dmy || mdy) return dmy || mdy;
  }

  // DD/MMM/YYYY (e.g., 02/MAR/2026)
  const dmyMonthName = core.match(/^(\d{1,2})[\/\-\s]([A-Za-z]{3,9})[\/\-\s](\d{2,4})$/);
  if (dmyMonthName) {
    const day = dmyMonthName[1];
    const month = monthFromText(dmyMonthName[2]);
    const year = normalizeYear(dmyMonthName[3]);
    if (!month || !year) return "";
    const iso = toIsoDate(year, month, day);
    if (iso) return iso;
  }

  // MMM/DD/YYYY (e.g., MAR/02/2026) and MMM-DD-YYYY.
  const mdyMonthName = core.match(/^([A-Za-z]{3,9})[\/\-\s](\d{1,2})[\/\-\s](\d{2,4})$/);
  if (mdyMonthName) {
    const month = monthFromText(mdyMonthName[1]);
    const day = mdyMonthName[2];
    const year = normalizeYear(mdyMonthName[3]);
    if (!month || !year) return "";
    const iso = toIsoDate(year, month, day);
    if (iso) return iso;
  }

  // Excel serial date numbers (days since 1899-12-30).
  if (/^\d{5,6}$/.test(core)) {
    const serial = Number(core);
    if (Number.isFinite(serial) && serial > 0) {
      const baseMs = Date.UTC(1899, 11, 30);
      const date = new Date(baseMs + (serial * 24 * 60 * 60 * 1000));
      const iso = toIsoDate(date.getUTCFullYear(), date.getUTCMonth() + 1, date.getUTCDate());
      if (iso) return iso;
    }
  }

  // Fallback for textual month variants such as "5-Mar-26".
  if (/[A-Za-z]/.test(core)) {
    const parsed = new Date(core);
    if (!Number.isNaN(parsed.getTime())) {
      const iso = toIsoDate(parsed.getUTCFullYear(), parsed.getUTCMonth() + 1, parsed.getUTCDate());
      if (iso) return iso;
    }
  }

  return "";
}

function toFiniteNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function toRightsRow(rights) {
  return {
    device_master: Boolean(rights && rights.deviceMaster),
    dashboard_page: Boolean(rights && rights.dashboardPage),
    issuing_page: Boolean(rights && rights.issuingPage),
    user_setup: Boolean(rights && rights.userSetup),
    action_log: Boolean(rights && rights.actionLog),
    user_management: Boolean(rights && rights.userManagement)
  };
}

function toRightsPayload(row) {
  return {
    deviceMaster: Boolean(row.device_master),
    dashboardPage: Boolean(row.dashboard_page),
    issuingPage: Boolean(row.issuing_page),
    userSetup: Boolean(row.user_setup),
    actionLog: Boolean(row.action_log),
    userManagement: Boolean(row.user_management)
  };
}

function hasAtLeastOneRight(rights) {
  return Boolean(
    rights && (rights.deviceMaster || rights.dashboardPage || rights.issuingPage || rights.userSetup || rights.actionLog || rights.userManagement)
  );
}

function userFromRow(row) {
  return {
    id: row.id,
    username: row.username,
    fullName: row.full_name,
    canLogin: Boolean(row.can_login),
    rights: toRightsPayload(row),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function addActionLog({ page, action, details, actorUsername }) {
  try {
    await pool.query(
      `INSERT INTO action_logs (id, event_time, page, action, details, actor_username)
       VALUES ($1, NOW(), $2, $3, $4, $5)`,
      [createId(), String(page || "SYSTEM"), String(action || "INFO"), String(details || ""), actorUsername || null]
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error("Action log write failed:", err.message);
  }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      can_login BOOLEAN NOT NULL DEFAULT TRUE,
      device_master BOOLEAN NOT NULL DEFAULT FALSE,
      dashboard_page BOOLEAN NOT NULL DEFAULT FALSE,
      issuing_page BOOLEAN NOT NULL DEFAULT FALSE,
      user_setup BOOLEAN NOT NULL DEFAULT FALSE,
      action_log BOOLEAN NOT NULL DEFAULT FALSE,
      user_management BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS dashboard_page BOOLEAN`);
  await pool.query(`UPDATE users SET dashboard_page = FALSE WHERE dashboard_page IS NULL`);
  await pool.query(`UPDATE users SET dashboard_page = TRUE WHERE device_master = TRUE AND dashboard_page = FALSE`);
  await pool.query(`ALTER TABLE users ALTER COLUMN dashboard_page SET DEFAULT FALSE`);
  await pool.query(`ALTER TABLE users ALTER COLUMN dashboard_page SET NOT NULL`);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS issuing_page BOOLEAN`);
  await pool.query(`UPDATE users SET issuing_page = FALSE WHERE issuing_page IS NULL`);
  await pool.query(`ALTER TABLE users ALTER COLUMN issuing_page SET DEFAULT FALSE`);
  await pool.query(`ALTER TABLE users ALTER COLUMN issuing_page SET NOT NULL`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_records (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      imei_number TEXT NOT NULL,
      device_model TEXT NOT NULL,
      mobile_number TEXT NOT NULL,
      sim_card_number TEXT NOT NULL,
      contract_number TEXT NOT NULL,
      contract_start_date DATE NOT NULL,
      contract_end_date DATE NOT NULL,
      m2m_start_date DATE NOT NULL,
      m2m_end_date DATE NOT NULL,
      m2m TEXT NOT NULL DEFAULT 'SOTI',
      retain_line TEXT NOT NULL DEFAULT 'NO',
      monthly_cost_price NUMERIC(12,2) NOT NULL DEFAULT 0,
      issued BOOLEAN NOT NULL DEFAULT FALSE,
      issued_at TIMESTAMPTZ,
      issued_to TEXT,
      issued_by TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Forward-compatible migration for already-created databases.
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS device_id TEXT`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS m2m TEXT`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS retain_line TEXT`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS m2m_start_date DATE`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS m2m_end_date DATE`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS monthly_cost_price NUMERIC(12,2)`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS issued BOOLEAN`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS issued_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS issued_to TEXT`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS issued_by TEXT`);
  await pool.query(`UPDATE device_records SET device_id = imei_number WHERE device_id IS NULL OR device_id = ''`);
  await pool.query(`UPDATE device_records SET m2m = 'SOTI' WHERE m2m IS NULL OR m2m = ''`);
  await pool.query(`UPDATE device_records SET retain_line = 'NO' WHERE retain_line IS NULL OR retain_line = ''`);
  await pool.query(`UPDATE device_records SET m2m_start_date = contract_start_date WHERE m2m_start_date IS NULL`);
  await pool.query(`UPDATE device_records SET m2m_end_date = contract_end_date WHERE m2m_end_date IS NULL`);
  await pool.query(`UPDATE device_records SET monthly_cost_price = 0 WHERE monthly_cost_price IS NULL`);
  await pool.query(`UPDATE device_records SET issued = FALSE WHERE issued IS NULL`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN m2m SET DEFAULT 'SOTI'`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN retain_line SET DEFAULT 'NO'`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN monthly_cost_price SET DEFAULT 0`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN issued SET DEFAULT FALSE`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN device_id SET NOT NULL`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN m2m_start_date SET NOT NULL`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN m2m_end_date SET NOT NULL`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN m2m SET NOT NULL`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN retain_line SET NOT NULL`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN monthly_cost_price SET NOT NULL`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN issued SET NOT NULL`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_device_records_device_id ON device_records (device_id);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_device_records_imei_number ON device_records (imei_number);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_device_records_issued_imei ON device_records (issued, imei_number);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_device_records_issued_device_id ON device_records (issued, device_id);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_setup_records (
      id TEXT PRIMARY KEY,
      staff_id TEXT NOT NULL,
      name TEXT NOT NULL,
      org_unit TEXT NOT NULL,
      action_status TEXT NOT NULL DEFAULT 'ACTIVE',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS action_logs (
      id TEXT PRIMARY KEY,
      event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      page TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT,
      actor_username TEXT
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_action_logs_event_time ON action_logs (event_time DESC);
  `);
}

async function ensureBootstrapAdmin() {
  const activeResult = await pool.query(
    `SELECT COUNT(*)::int AS count
     FROM users
     WHERE can_login = TRUE
       AND (device_master = TRUE OR dashboard_page = TRUE OR issuing_page = TRUE OR user_setup = TRUE OR action_log = TRUE OR user_management = TRUE)`
  );

  if (activeResult.rows[0].count > 0) return;

  const passwordHash = await bcrypt.hash(ADMIN_INITIAL_PASSWORD, 10);
  const existing = await pool.query("SELECT id FROM users WHERE UPPER(username) = 'ADMIN' LIMIT 1");

  if (existing.rowCount > 0) {
    await pool.query(
      `UPDATE users
       SET full_name = $2,
           password_hash = $3,
           can_login = TRUE,
           device_master = TRUE,
           dashboard_page = TRUE,
           issuing_page = TRUE,
           user_setup = TRUE,
           action_log = TRUE,
           user_management = TRUE,
           updated_at = NOW()
       WHERE id = $1`,
      [existing.rows[0].id, "SYSTEM ADMINISTRATOR", passwordHash]
    );

    await addActionLog({
      page: "SYSTEM",
      action: "RECOVERY",
      details: "Recovered ADMIN account (ADMIN / ADMIN123).",
      actorUsername: "SYSTEM"
    });
    return;
  }

  await pool.query(
    `INSERT INTO users (
      id, username, full_name, password_hash, can_login,
      device_master, dashboard_page, issuing_page, user_setup, action_log, user_management
    ) VALUES ($1, $2, $3, $4, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE)`,
    [createId(), "ADMIN", "SYSTEM ADMINISTRATOR", passwordHash]
  );

  await addActionLog({
    page: "SYSTEM",
    action: "BOOTSTRAP",
    details: "Created default ADMIN user.",
    actorUsername: "SYSTEM"
  });
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      fullName: user.fullName,
      rights: user.rights
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function getTokenFromRequest(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return null;
  return auth.slice(7).trim();
}

async function authMiddleware(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) {
    return res.status(401).json({ message: "Unauthorized." });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ message: "Invalid token." });
  }

  const result = await pool.query(
    `SELECT * FROM users WHERE id = $1 LIMIT 1`,
    [decoded.sub]
  );

  if (result.rowCount === 0) {
    return res.status(401).json({ message: "User not found." });
  }

  const user = userFromRow(result.rows[0]);
  if (!user.canLogin) {
    return res.status(403).json({ message: "User is disabled." });
  }

  req.user = user;
  req.token = token;
  return next();
}

function requireRight(rightKey) {
  return (req, res, next) => {
    if (!req.user || !req.user.rights || !req.user.rights[rightKey]) {
      return res.status(403).json({ message: "Access denied." });
    }
    return next();
  };
}

function validateDeviceRecordInput(payload) {
  const monthlyCostRaw = String(payload.monthlyCostPrice || "").trim();
  let monthlyCostPrice = normalizeMonthlyCostPrice(payload.monthlyCostPrice);
  if (monthlyCostPrice === null && !monthlyCostRaw) {
    monthlyCostPrice = 0;
  }

  const contractStartDate = normalizeDateValue(payload.contractStartDate);
  const contractEndDate = normalizeDateValue(payload.contractEndDate);
  const rawM2mStartDate = normalizeDateValue(payload.m2mStartDate);
  const rawM2mEndDate = normalizeDateValue(payload.m2mEndDate);
  const imeiNumber = normalizeUpper(payload.imeiNumber);
  const deviceId = normalizeUpper(payload.deviceId) || imeiNumber;
  const record = {
    deviceId,
    imeiNumber,
    deviceModel: normalizeUpper(payload.deviceModel),
    mobileNumber: normalizeUpper(payload.mobileNumber),
    simCardNumber: normalizeUpper(payload.simCardNumber),
    contractNumber: normalizeUpper(payload.contractNumber),
    contractStartDate,
    contractEndDate,
    // Backward compatibility for older CSV files:
    // if M2M dates are missing, use contract dates.
    m2mStartDate: rawM2mStartDate || contractStartDate,
    m2mEndDate: rawM2mEndDate || contractEndDate,
    m2m: normalizeM2M(payload.m2m),
    retainLine: normalizeRetainLine(payload.retainLine),
    monthlyCostPrice
  };

  const required = [
    record.deviceId,
    record.imeiNumber,
    record.deviceModel,
    record.mobileNumber,
    record.simCardNumber,
    record.contractNumber,
    record.contractStartDate,
    record.contractEndDate,
    record.m2mStartDate,
    record.m2mEndDate,
    record.m2m
  ];

  if (required.some((value) => !value)) {
    return {
      ok: false,
      message: "All device fields are required. Use date format YYYY-MM-DD, DD/MM/YYYY, MM/DD/YYYY (when unambiguous), or DD/MMM/YYYY."
    };
  }

  if (record.contractStartDate > record.contractEndDate) {
    return { ok: false, message: "Contract Start Date cannot be after Contract End Date." };
  }
  if (record.m2mStartDate > record.m2mEndDate) {
    return { ok: false, message: "M2M Start Date cannot be after M2M End Date." };
  }

  if (record.monthlyCostPrice === null) {
    return { ok: false, message: "Monthly Cost Price must be a valid non-negative number." };
  }

  return { ok: true, record };
}

function validateUserSetupRecordInput(payload) {
  const record = {
    staffId: normalizeUpper(payload.staffId),
    name: normalizeUpper(payload.name),
    orgUnit: normalizeUpper(payload.orgUnit),
    action: normalizeAction(payload.action)
  };

  if (!record.staffId || !record.name || !record.orgUnit) {
    return { ok: false, message: "Staff ID, Name, and Org Unit are required." };
  }

  return { ok: true, record };
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.post("/api/auth/login", async (req, res) => {
  await ensureBootstrapAdmin();

  const username = normalizeUpper(req.body && req.body.username);
  const password = normalizeUpper(req.body && req.body.password);

  if (!username || !password) {
    await addActionLog({ page: "SYSTEM", action: "LOGIN FAILED", details: "Missing username or password.", actorUsername: "SYSTEM" });
    return res.status(400).json({ message: "USERNAME AND PASSWORD ARE REQUIRED." });
  }

  const result = await pool.query(
    `SELECT * FROM users WHERE UPPER(username) = $1 LIMIT 1`,
    [username]
  );

  if (result.rowCount === 0) {
    await addActionLog({ page: "SYSTEM", action: "LOGIN FAILED", details: `Unknown user ${username}.`, actorUsername: "SYSTEM" });
    return res.status(401).json({ message: "INVALID USERNAME OR PASSWORD." });
  }

  const row = result.rows[0];
  const user = userFromRow(row);

  if (!user.canLogin) {
    await addActionLog({ page: "SYSTEM", action: "LOGIN FAILED", details: `Disabled user ${username}.`, actorUsername: "SYSTEM" });
    return res.status(403).json({ message: "THIS USER IS DISABLED." });
  }

  const matched = await bcrypt.compare(password, row.password_hash);
  if (!matched) {
    await addActionLog({ page: "SYSTEM", action: "LOGIN FAILED", details: `Incorrect password for ${username}.`, actorUsername: "SYSTEM" });
    return res.status(401).json({ message: "INVALID USERNAME OR PASSWORD." });
  }

  const token = signToken(user);
  await addActionLog({ page: "SYSTEM", action: "LOGIN", details: `User ${user.username} logged in.`, actorUsername: user.username });

  return res.json({
    token,
    user
  });
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  res.json({ user: req.user });
});

app.post("/api/auth/logout", authMiddleware, async (req, res) => {
  await addActionLog({ page: "SYSTEM", action: "LOGOUT", details: `User ${req.user.username} logged out.`, actorUsername: req.user.username });
  return res.json({ ok: true });
});

app.post("/api/action-logs", authMiddleware, async (req, res) => {
  const page = String((req.body && req.body.page) || "SYSTEM").slice(0, 120);
  const action = String((req.body && req.body.action) || "INFO").slice(0, 120);
  const details = String((req.body && req.body.details) || "").slice(0, 2000);
  await addActionLog({ page, action, details, actorUsername: req.user.username });
  return res.json({ ok: true });
});

app.get("/api/action-logs", authMiddleware, requireRight("actionLog"), async (req, res) => {
  const result = await pool.query(
    `SELECT id, event_time, page, action, details, actor_username
     FROM action_logs
     ORDER BY event_time DESC
     LIMIT 2000`
  );

  const logs = result.rows.map((row) => ({
    id: row.id,
    timestamp: row.event_time,
    page: row.page,
    action: row.action,
    details: row.details,
    actorUsername: row.actor_username
  }));

  return res.json({ logs });
});

app.delete("/api/action-logs", authMiddleware, requireRight("actionLog"), async (req, res) => {
  await pool.query("DELETE FROM action_logs");
  await addActionLog({
    page: "Action Log Page",
    action: "CLEAR LOGS",
    details: `Cleared all action logs by ${req.user.username}.`,
    actorUsername: req.user.username
  });
  return res.json({ ok: true });
});

app.get("/api/dashboard/summary", authMiddleware, requireRight("dashboardPage"), async (req, res) => {
  const totalsResult = await pool.query(
    `SELECT COUNT(*)::int AS total_devices,
            COALESCE(SUM(monthly_cost_price), 0) AS total_running_cost
     FROM device_records`
  );

  const m2mResult = await pool.query(
    `SELECT m2m,
            COUNT(*)::int AS device_count,
            COALESCE(SUM(monthly_cost_price), 0) AS running_cost
     FROM device_records
     GROUP BY m2m
     ORDER BY m2m ASC`
  );

  const modelResult = await pool.query(
    `SELECT device_model,
            COUNT(*)::int AS device_count,
            COALESCE(SUM(monthly_cost_price), 0) AS running_cost
     FROM device_records
     GROUP BY device_model
     ORDER BY device_count DESC, device_model ASC`
  );

  const totalsRow = totalsResult.rows[0] || {};
  const m2mBreakdown = m2mResult.rows.map((row) => ({
    m2m: row.m2m,
    count: Number(row.device_count) || 0,
    runningCost: toFiniteNumber(row.running_cost)
  }));
  const modelBreakdown = modelResult.rows.map((row) => ({
    deviceModel: row.device_model,
    count: Number(row.device_count) || 0,
    runningCost: toFiniteNumber(row.running_cost)
  }));

  return res.json({
    totalDevices: Number(totalsRow.total_devices) || 0,
    totalRunningCost: toFiniteNumber(totalsRow.total_running_cost),
    m2mBreakdown,
    modelBreakdown
  });
});

app.get("/api/device-records", authMiddleware, requireRight("deviceMaster"), async (req, res) => {
  const result = await pool.query(
    `SELECT id, device_id, imei_number, device_model, mobile_number, sim_card_number,
            contract_number, contract_start_date, contract_end_date, m2m_start_date, m2m_end_date,
            m2m, retain_line, monthly_cost_price, issued, issued_at, issued_to, issued_by
     FROM device_records
     ORDER BY created_at DESC`
  );

  const records = result.rows.map((row) => ({
    id: row.id,
    deviceId: row.device_id,
    imeiNumber: row.imei_number,
    deviceModel: row.device_model,
    mobileNumber: row.mobile_number,
    simCardNumber: row.sim_card_number,
    contractNumber: row.contract_number,
    contractStartDate: row.contract_start_date,
    contractEndDate: row.contract_end_date,
    m2mStartDate: row.m2m_start_date,
    m2mEndDate: row.m2m_end_date,
    m2m: row.m2m,
    retainLine: row.retain_line,
    monthlyCostPrice: row.monthly_cost_price,
    issued: Boolean(row.issued),
    issuedAt: row.issued_at,
    issuedTo: row.issued_to,
    issuedBy: row.issued_by
  }));

  return res.json({ records });
});

app.get("/api/device-records/available", authMiddleware, requireRight("issuingPage"), async (req, res) => {
  const result = await pool.query(
    `SELECT id, device_id, imei_number, device_model, mobile_number, sim_card_number,
            contract_number, contract_start_date, contract_end_date, m2m_start_date, m2m_end_date,
            m2m, retain_line, monthly_cost_price
     FROM device_records
     WHERE issued = FALSE
     ORDER BY created_at DESC`
  );

  const records = result.rows.map((row) => ({
    id: row.id,
    deviceId: row.device_id,
    imeiNumber: row.imei_number,
    deviceModel: row.device_model,
    mobileNumber: row.mobile_number,
    simCardNumber: row.sim_card_number,
    contractNumber: row.contract_number,
    contractStartDate: row.contract_start_date,
    contractEndDate: row.contract_end_date,
    m2mStartDate: row.m2m_start_date,
    m2mEndDate: row.m2m_end_date,
    m2m: row.m2m,
    retainLine: row.retain_line,
    monthlyCostPrice: row.monthly_cost_price
  }));

  return res.json({ records });
});

app.post("/api/device-records", authMiddleware, requireRight("deviceMaster"), async (req, res) => {
  const validated = validateDeviceRecordInput(req.body || {});
  if (!validated.ok) {
    return res.status(400).json({ message: validated.message });
  }

  const record = validated.record;
  const id = createId();

  await pool.query(
    `INSERT INTO device_records (
      id, device_id, imei_number, device_model, mobile_number, sim_card_number,
      contract_number, contract_start_date, contract_end_date, m2m_start_date, m2m_end_date, m2m, retain_line, monthly_cost_price
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      id,
      record.deviceId,
      record.imeiNumber,
      record.deviceModel,
      record.mobileNumber,
      record.simCardNumber,
      record.contractNumber,
      record.contractStartDate,
      record.contractEndDate,
      record.m2mStartDate,
      record.m2mEndDate,
      record.m2m,
      record.retainLine,
      record.monthlyCostPrice
    ]
  );

  await addActionLog({
    page: "Device Master Page",
    action: "ADD RECORD",
    details: `USER ${req.user.username}: IMEI ${record.imeiNumber}`,
    actorUsername: req.user.username
  });

  return res.status(201).json({
    record: {
      id,
      ...record
    }
  });
});

app.delete("/api/device-records/:id", authMiddleware, requireRight("deviceMaster"), async (req, res) => {
  const id = String(req.params.id || "");
  const find = await pool.query("SELECT imei_number FROM device_records WHERE id = $1", [id]);
  if (find.rowCount === 0) {
    return res.status(404).json({ message: "Record not found." });
  }

  await pool.query("DELETE FROM device_records WHERE id = $1", [id]);

  await addActionLog({
    page: "Device Master Page",
    action: "DELETE RECORD",
    details: `USER ${req.user.username}: IMEI ${find.rows[0].imei_number}`,
    actorUsername: req.user.username
  });

  return res.json({ ok: true });
});

app.post("/api/device-records/bulk", authMiddleware, requireRight("deviceMaster"), async (req, res) => {
  const inputRecords = Array.isArray(req.body && req.body.records) ? req.body.records : [];
  if (inputRecords.length === 0) {
    return res.status(400).json({ message: "No records provided." });
  }

  let importedCount = 0;
  let skippedCount = 0;
  const errors = [];

  for (let index = 0; index < inputRecords.length; index += 1) {
    const item = inputRecords[index];
    const validated = validateDeviceRecordInput(item || {});
    if (!validated.ok) {
      skippedCount += 1;
      if (errors.length < 10) {
        errors.push({
          row: index + 2, // +1 header row, +1 zero-based index
          reason: validated.message
        });
      }
      continue;
    }

    const record = validated.record;
    await pool.query(
      `INSERT INTO device_records (
        id, device_id, imei_number, device_model, mobile_number, sim_card_number,
        contract_number, contract_start_date, contract_end_date, m2m_start_date, m2m_end_date, m2m, retain_line, monthly_cost_price
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [
        createId(),
        record.deviceId,
        record.imeiNumber,
        record.deviceModel,
        record.mobileNumber,
        record.simCardNumber,
        record.contractNumber,
        record.contractStartDate,
        record.contractEndDate,
        record.m2mStartDate,
        record.m2mEndDate,
        record.m2m,
        record.retainLine,
        record.monthlyCostPrice
      ]
    );
    importedCount += 1;
  }

  await addActionLog({
    page: "Device Master Page",
    action: importedCount > 0 ? "BULK UPLOAD" : "BULK UPLOAD FAILED",
    details: `USER ${req.user.username}: Imported ${importedCount}, skipped ${skippedCount}`,
    actorUsername: req.user.username
  });

  if (importedCount === 0) {
    const first = errors[0];
    const message = first
      ? `Bulk upload failed at row ${first.row}: ${first.reason}`
      : "Bulk upload failed: no valid rows found.";
    return res.status(400).json({ message, importedCount, skippedCount, errors });
  }

  return res.json({ importedCount, skippedCount, errors });
});

app.post("/api/device-records/issue", authMiddleware, requireRight("issuingPage"), async (req, res) => {
  const deviceId = normalizeUpper(req.body && req.body.deviceId);
  const imeiNumber = normalizeUpper(req.body && req.body.imeiNumber);
  const issuedTo = normalizeUpper(req.body && req.body.issuedTo);

  if (!deviceId && !imeiNumber) {
    return res.status(400).json({ message: "DEVICE ID IS REQUIRED." });
  }

  const issueField = deviceId ? "device_id" : "imei_number";
  const issueValue = deviceId || imeiNumber;
  const result = await pool.query(
    `WITH picked AS (
       SELECT id
       FROM device_records
       WHERE ${issueField} = $1
         AND issued = FALSE
       ORDER BY created_at ASC
       LIMIT 1
       FOR UPDATE SKIP LOCKED
     )
     UPDATE device_records d
     SET issued = TRUE,
         issued_at = NOW(),
         issued_by = $2,
         issued_to = NULLIF($3, ''),
         updated_at = NOW()
     FROM picked
     WHERE d.id = picked.id
     RETURNING d.id, d.device_id, d.imei_number, d.device_model, d.mobile_number, d.sim_card_number,
               d.contract_number, d.contract_start_date, d.contract_end_date, d.m2m_start_date, d.m2m_end_date,
               d.m2m, d.retain_line, d.monthly_cost_price, d.issued, d.issued_at, d.issued_to, d.issued_by`,
    [issueValue, req.user.username, issuedTo]
  );

  if (result.rowCount === 0) {
    return res.status(404).json({ message: "DEVICE NOT FOUND OR ALREADY ISSUED." });
  }

  const row = result.rows[0];
  await addActionLog({
    page: "Issuing Page",
    action: "ISSUE DEVICE",
    details: `USER ${req.user.username}: DEVICE ID ${row.device_id}${issuedTo ? ` TO ${issuedTo}` : ""}`,
    actorUsername: req.user.username
  });

  return res.json({
    record: {
      id: row.id,
      deviceId: row.device_id,
      imeiNumber: row.imei_number,
      deviceModel: row.device_model,
      mobileNumber: row.mobile_number,
      simCardNumber: row.sim_card_number,
      contractNumber: row.contract_number,
      contractStartDate: row.contract_start_date,
      contractEndDate: row.contract_end_date,
      m2mStartDate: row.m2m_start_date,
      m2mEndDate: row.m2m_end_date,
      m2m: row.m2m,
      retainLine: row.retain_line,
      monthlyCostPrice: row.monthly_cost_price,
      issued: Boolean(row.issued),
      issuedAt: row.issued_at,
      issuedTo: row.issued_to,
      issuedBy: row.issued_by
    }
  });
});

app.get("/api/user-setup-records", authMiddleware, requireRight("userSetup"), async (req, res) => {
  const result = await pool.query(
    `SELECT id, staff_id, name, org_unit, action_status
     FROM user_setup_records
     ORDER BY created_at DESC`
  );

  const records = result.rows.map((row) => ({
    id: row.id,
    staffId: row.staff_id,
    name: row.name,
    orgUnit: row.org_unit,
    action: normalizeAction(row.action_status)
  }));

  return res.json({ records });
});

app.post("/api/user-setup-records", authMiddleware, requireRight("userSetup"), async (req, res) => {
  const validated = validateUserSetupRecordInput(req.body || {});
  if (!validated.ok) {
    return res.status(400).json({ message: validated.message });
  }

  const record = validated.record;
  const id = createId();

  await pool.query(
    `INSERT INTO user_setup_records (id, staff_id, name, org_unit, action_status)
     VALUES ($1,$2,$3,$4,$5)`,
    [id, record.staffId, record.name, record.orgUnit, record.action]
  );

  await addActionLog({
    page: "User Setup Page",
    action: "ADD RECORD",
    details: `USER ${req.user.username}: Staff ID ${record.staffId}`,
    actorUsername: req.user.username
  });

  return res.status(201).json({ record: { id, ...record } });
});

app.patch("/api/user-setup-records/:id/action", authMiddleware, requireRight("userSetup"), async (req, res) => {
  const id = String(req.params.id || "");
  const action = normalizeAction(req.body && req.body.action);
  const find = await pool.query("SELECT staff_id FROM user_setup_records WHERE id = $1", [id]);
  if (find.rowCount === 0) {
    return res.status(404).json({ message: "Record not found." });
  }

  await pool.query(
    `UPDATE user_setup_records
     SET action_status = $2, updated_at = NOW()
     WHERE id = $1`,
    [id, action]
  );

  await addActionLog({
    page: "User Setup Page",
    action: "UPDATE ACTION",
    details: `USER ${req.user.username}: Staff ID ${find.rows[0].staff_id} set to ${action}`,
    actorUsername: req.user.username
  });

  return res.json({ ok: true, action });
});

app.post("/api/user-setup-records/bulk", authMiddleware, requireRight("userSetup"), async (req, res) => {
  const inputRecords = Array.isArray(req.body && req.body.records) ? req.body.records : [];
  if (inputRecords.length === 0) {
    return res.status(400).json({ message: "No records provided." });
  }

  let importedCount = 0;
  let skippedCount = 0;

  for (const item of inputRecords) {
    const validated = validateUserSetupRecordInput(item || {});
    if (!validated.ok) {
      skippedCount += 1;
      continue;
    }

    const record = validated.record;
    await pool.query(
      `INSERT INTO user_setup_records (id, staff_id, name, org_unit, action_status)
       VALUES ($1,$2,$3,$4,$5)`,
      [createId(), record.staffId, record.name, record.orgUnit, record.action]
    );
    importedCount += 1;
  }

  await addActionLog({
    page: "User Setup Page",
    action: importedCount > 0 ? "BULK UPLOAD" : "BULK UPLOAD FAILED",
    details: `USER ${req.user.username}: Imported ${importedCount}, skipped ${skippedCount}`,
    actorUsername: req.user.username
  });

  return res.json({ importedCount, skippedCount });
});

app.get("/api/users", authMiddleware, requireRight("userManagement"), async (req, res) => {
  const result = await pool.query(
    `SELECT id, username, full_name, can_login,
            device_master, dashboard_page, issuing_page, user_setup, action_log, user_management,
            created_at, updated_at
     FROM users
     ORDER BY username ASC`
  );

  return res.json({ users: result.rows.map(userFromRow) });
});

async function validateManagersAfterChange(usersResultRows) {
  return usersResultRows.some((row) => Boolean(row.can_login && row.user_management));
}

app.post("/api/users", authMiddleware, requireRight("userManagement"), async (req, res) => {
  const username = normalizeUpper(req.body && req.body.username);
  const fullName = normalizeUpper(req.body && req.body.fullName);
  const password = normalizeUpper(req.body && req.body.password);
  const canLogin = Boolean(req.body && req.body.canLogin);
  const rights = toRightsRow(req.body && req.body.rights);

  if (!username) return res.status(400).json({ message: "USERNAME IS REQUIRED." });
  if (!fullName) return res.status(400).json({ message: "FULL NAME IS REQUIRED." });
  if (!password) return res.status(400).json({ message: "PASSWORD IS REQUIRED." });
  if (!hasAtLeastOneRight(toRightsPayload(rights))) {
    return res.status(400).json({ message: "AT LEAST ONE RIGHT MUST BE ENABLED." });
  }

  const existing = await pool.query("SELECT id FROM users WHERE UPPER(username) = $1 LIMIT 1", [username]);
  if (existing.rowCount > 0) {
    return res.status(409).json({ message: "USERNAME ALREADY EXISTS." });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const id = createId();

  await pool.query(
    `INSERT INTO users (
      id, username, full_name, password_hash, can_login,
      device_master, dashboard_page, issuing_page, user_setup, action_log, user_management
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      id,
      username,
      fullName,
      passwordHash,
      canLogin,
      rights.device_master,
      rights.dashboard_page,
      rights.issuing_page,
      rights.user_setup,
      rights.action_log,
      rights.user_management
    ]
  );

  const allRows = await pool.query("SELECT can_login, user_management FROM users");
  if (!(await validateManagersAfterChange(allRows.rows))) {
    await pool.query("DELETE FROM users WHERE id = $1", [id]);
    return res.status(400).json({ message: "AT LEAST ONE ACTIVE USER MANAGER IS REQUIRED." });
  }

  await addActionLog({
    page: "User Management Page",
    action: "CREATE USER",
    details: `${req.user.username} -> ${username} (${canLogin ? "ENABLED" : "DISABLED"})`,
    actorUsername: req.user.username
  });

  const result = await pool.query(
    `SELECT id, username, full_name, can_login,
            device_master, dashboard_page, issuing_page, user_setup, action_log, user_management,
            created_at, updated_at
     FROM users WHERE id = $1`,
    [id]
  );

  return res.status(201).json({ user: userFromRow(result.rows[0]) });
});

app.put("/api/users/:id", authMiddleware, requireRight("userManagement"), async (req, res) => {
  const id = String(req.params.id || "");
  const username = normalizeUpper(req.body && req.body.username);
  const fullName = normalizeUpper(req.body && req.body.fullName);
  const password = normalizeUpper(req.body && req.body.password);
  const canLogin = Boolean(req.body && req.body.canLogin);
  const rights = toRightsRow(req.body && req.body.rights);

  if (!username) return res.status(400).json({ message: "USERNAME IS REQUIRED." });
  if (!fullName) return res.status(400).json({ message: "FULL NAME IS REQUIRED." });
  if (!password) return res.status(400).json({ message: "PASSWORD IS REQUIRED." });
  if (!hasAtLeastOneRight(toRightsPayload(rights))) {
    return res.status(400).json({ message: "AT LEAST ONE RIGHT MUST BE ENABLED." });
  }

  const existing = await pool.query("SELECT * FROM users WHERE id = $1 LIMIT 1", [id]);
  if (existing.rowCount === 0) return res.status(404).json({ message: "USER NOT FOUND." });

  const duplicate = await pool.query(
    "SELECT id FROM users WHERE UPPER(username) = $1 AND id <> $2 LIMIT 1",
    [username, id]
  );
  if (duplicate.rowCount > 0) {
    return res.status(409).json({ message: "USERNAME ALREADY EXISTS." });
  }

  if (req.user.id === id && (!canLogin || !rights.user_management)) {
    return res.status(400).json({ message: "YOU CANNOT REMOVE YOUR OWN USER MANAGEMENT ACCESS." });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  await pool.query(
    `UPDATE users
     SET username = $2,
         full_name = $3,
         password_hash = $4,
         can_login = $5,
         device_master = $6,
         dashboard_page = $7,
         issuing_page = $8,
         user_setup = $9,
         action_log = $10,
         user_management = $11,
         updated_at = NOW()
     WHERE id = $1`,
    [
      id,
      username,
      fullName,
      passwordHash,
      canLogin,
      rights.device_master,
      rights.dashboard_page,
      rights.issuing_page,
      rights.user_setup,
      rights.action_log,
      rights.user_management
    ]
  );

  const allRows = await pool.query("SELECT can_login, user_management FROM users");
  if (!(await validateManagersAfterChange(allRows.rows))) {
    const prev = existing.rows[0];
    await pool.query(
      `UPDATE users
       SET username = $2,
           full_name = $3,
           password_hash = $4,
           can_login = $5,
           device_master = $6,
           dashboard_page = $7,
           issuing_page = $8,
           user_setup = $9,
           action_log = $10,
           user_management = $11,
           updated_at = NOW()
       WHERE id = $1`,
      [
        id,
        prev.username,
        prev.full_name,
        prev.password_hash,
        prev.can_login,
        prev.device_master,
        prev.dashboard_page,
        prev.issuing_page,
        prev.user_setup,
        prev.action_log,
        prev.user_management
      ]
    );
    return res.status(400).json({ message: "AT LEAST ONE ACTIVE USER MANAGER IS REQUIRED." });
  }

  await addActionLog({
    page: "User Management Page",
    action: "UPDATE USER",
    details: `${req.user.username} -> ${username} (${canLogin ? "ENABLED" : "DISABLED"})`,
    actorUsername: req.user.username
  });

  const result = await pool.query(
    `SELECT id, username, full_name, can_login,
            device_master, dashboard_page, issuing_page, user_setup, action_log, user_management,
            created_at, updated_at
     FROM users WHERE id = $1`,
    [id]
  );

  return res.json({ user: userFromRow(result.rows[0]) });
});

app.delete("/api/users/:id", authMiddleware, requireRight("userManagement"), async (req, res) => {
  const id = String(req.params.id || "");
  if (req.user.id === id) {
    return res.status(400).json({ message: "YOU CANNOT DELETE YOUR OWN ACCOUNT." });
  }

  const target = await pool.query("SELECT id, username FROM users WHERE id = $1", [id]);
  if (target.rowCount === 0) {
    return res.status(404).json({ message: "USER NOT FOUND." });
  }

  const managersResult = await pool.query(
    `SELECT COUNT(*)::int AS count
     FROM users
     WHERE can_login = TRUE AND user_management = TRUE`
  );
  if (managersResult.rows[0].count <= 1) {
    const checkTarget = await pool.query("SELECT can_login, user_management FROM users WHERE id = $1", [id]);
    if (checkTarget.rowCount > 0 && checkTarget.rows[0].can_login && checkTarget.rows[0].user_management) {
      return res.status(400).json({ message: "CANNOT DELETE THE LAST ACTIVE USER MANAGER." });
    }
  }

  await pool.query("DELETE FROM users WHERE id = $1", [id]);

  await addActionLog({
    page: "User Management Page",
    action: "DELETE USER",
    details: `${req.user.username} -> ${target.rows[0].username}`,
    actorUsername: req.user.username
  });

  return res.json({ ok: true });
});

app.use(express.static(path.resolve(__dirname)));

app.get("/", (req, res) => {
  res.sendFile(path.resolve(__dirname, "index.html"));
});

app.use((err, req, res, next) => {
  // eslint-disable-next-line no-console
  console.error(err);
  res.status(500).json({ message: "Internal server error." });
});

async function start() {
  await initDb();
  await ensureBootstrapAdmin();

  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Inventory server listening on http://0.0.0.0:${PORT}`);
  });
}

start().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("Failed to start server:", err);
  process.exit(1);
});
