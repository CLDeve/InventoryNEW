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
app.use(express.json({ limit: "2mb" }));

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

function normalizeMonthlyCostPrice(value) {
  const parsed = Number(String(value || "").trim());
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return Number(parsed.toFixed(2));
}

function toRightsRow(rights) {
  return {
    device_master: Boolean(rights && rights.deviceMaster),
    user_setup: Boolean(rights && rights.userSetup),
    action_log: Boolean(rights && rights.actionLog),
    user_management: Boolean(rights && rights.userManagement)
  };
}

function toRightsPayload(row) {
  return {
    deviceMaster: Boolean(row.device_master),
    userSetup: Boolean(row.user_setup),
    actionLog: Boolean(row.action_log),
    userManagement: Boolean(row.user_management)
  };
}

function hasAtLeastOneRight(rights) {
  return Boolean(rights && (rights.deviceMaster || rights.userSetup || rights.actionLog || rights.userManagement));
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
      user_setup BOOLEAN NOT NULL DEFAULT FALSE,
      action_log BOOLEAN NOT NULL DEFAULT FALSE,
      user_management BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

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
      m2m TEXT NOT NULL DEFAULT 'SOTI',
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
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS monthly_cost_price NUMERIC(12,2)`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS issued BOOLEAN`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS issued_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS issued_to TEXT`);
  await pool.query(`ALTER TABLE device_records ADD COLUMN IF NOT EXISTS issued_by TEXT`);
  await pool.query(`UPDATE device_records SET device_id = imei_number WHERE device_id IS NULL OR device_id = ''`);
  await pool.query(`UPDATE device_records SET m2m = 'SOTI' WHERE m2m IS NULL OR m2m = ''`);
  await pool.query(`UPDATE device_records SET monthly_cost_price = 0 WHERE monthly_cost_price IS NULL`);
  await pool.query(`UPDATE device_records SET issued = FALSE WHERE issued IS NULL`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN m2m SET DEFAULT 'SOTI'`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN monthly_cost_price SET DEFAULT 0`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN issued SET DEFAULT FALSE`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN device_id SET NOT NULL`);
  await pool.query(`ALTER TABLE device_records ALTER COLUMN m2m SET NOT NULL`);
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
       AND (device_master = TRUE OR user_setup = TRUE OR action_log = TRUE OR user_management = TRUE)`
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
      device_master, user_setup, action_log, user_management
    ) VALUES ($1, $2, $3, $4, TRUE, TRUE, TRUE, TRUE, TRUE)`,
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
  const record = {
    deviceId: normalizeUpper(payload.deviceId),
    imeiNumber: normalizeUpper(payload.imeiNumber),
    deviceModel: normalizeUpper(payload.deviceModel),
    mobileNumber: normalizeUpper(payload.mobileNumber),
    simCardNumber: normalizeUpper(payload.simCardNumber),
    contractNumber: normalizeUpper(payload.contractNumber),
    contractStartDate: String(payload.contractStartDate || "").trim(),
    contractEndDate: String(payload.contractEndDate || "").trim(),
    m2m: normalizeM2M(payload.m2m),
    monthlyCostPrice: normalizeMonthlyCostPrice(payload.monthlyCostPrice)
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
    record.m2m
  ];

  if (required.some((value) => !value)) {
    return { ok: false, message: "All device fields are required." };
  }

  if (record.contractStartDate > record.contractEndDate) {
    return { ok: false, message: "Contract Start Date cannot be after Contract End Date." };
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

app.get("/api/device-records", authMiddleware, requireRight("deviceMaster"), async (req, res) => {
  const result = await pool.query(
    `SELECT id, device_id, imei_number, device_model, mobile_number, sim_card_number,
            contract_number, contract_start_date, contract_end_date,
            m2m, monthly_cost_price, issued, issued_at, issued_to, issued_by
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
    m2m: row.m2m,
    monthlyCostPrice: row.monthly_cost_price,
    issued: Boolean(row.issued),
    issuedAt: row.issued_at,
    issuedTo: row.issued_to,
    issuedBy: row.issued_by
  }));

  return res.json({ records });
});

app.get("/api/device-records/available", authMiddleware, requireRight("deviceMaster"), async (req, res) => {
  const result = await pool.query(
    `SELECT id, device_id, imei_number, device_model, mobile_number, sim_card_number,
            contract_number, contract_start_date, contract_end_date,
            m2m, monthly_cost_price
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
    m2m: row.m2m,
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
      contract_number, contract_start_date, contract_end_date, m2m, monthly_cost_price
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
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
      record.m2m,
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

  for (const item of inputRecords) {
    const validated = validateDeviceRecordInput(item || {});
    if (!validated.ok) {
      skippedCount += 1;
      continue;
    }

    const record = validated.record;
    await pool.query(
      `INSERT INTO device_records (
        id, device_id, imei_number, device_model, mobile_number, sim_card_number,
        contract_number, contract_start_date, contract_end_date, m2m, monthly_cost_price
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
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
        record.m2m,
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

  return res.json({ importedCount, skippedCount });
});

app.post("/api/device-records/issue", authMiddleware, requireRight("deviceMaster"), async (req, res) => {
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
               d.contract_number, d.contract_start_date, d.contract_end_date,
               d.m2m, d.monthly_cost_price, d.issued, d.issued_at, d.issued_to, d.issued_by`,
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
      m2m: row.m2m,
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
            device_master, user_setup, action_log, user_management,
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
      device_master, user_setup, action_log, user_management
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      id,
      username,
      fullName,
      passwordHash,
      canLogin,
      rights.device_master,
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
            device_master, user_setup, action_log, user_management,
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
         user_setup = $7,
         action_log = $8,
         user_management = $9,
         updated_at = NOW()
     WHERE id = $1`,
    [
      id,
      username,
      fullName,
      passwordHash,
      canLogin,
      rights.device_master,
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
           user_setup = $7,
           action_log = $8,
           user_management = $9,
           updated_at = NOW()
       WHERE id = $1`,
      [
        id,
        prev.username,
        prev.full_name,
        prev.password_hash,
        prev.can_login,
        prev.device_master,
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
            device_master, user_setup, action_log, user_management,
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
