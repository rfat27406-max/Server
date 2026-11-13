
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from "@simplewebauthn/server";

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8"
};

const encoder = new TextEncoder();

const COOKIE = "bs_admin_session";
const SESSION_SECONDS = 8 * 60 * 60;
const MAX_BODY_SIZE = 5000;
const MAX_WEBAUTHN_BODY_SIZE = 100 * 1024;
const CHALLENGE_TTL = 5 * 60 * 1000;

// ==========================================
// JSON RESPONSE
// ==========================================

function json(data, status = 200, headers = {}) {
  const responseHeaders = new Headers(JSON_HEADERS);

  for (const [key, value] of Object.entries(headers)) {
    responseHeaders.set(key, value);
  }

  return new Response(JSON.stringify(data), {
    status,
    headers: responseHeaders
  });
}

// ==========================================
// SECURITY HELPERS
// ==========================================

function normalize(value) {
  return String(value ?? "")
    .normalize("NFKC")
    .trim()
    .toLocaleLowerCase("ar");
}

function clean(value, max) {
  return String(value ?? "")
    .normalize("NFKC")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, max);
}

function safeEqual(a, b) {
  const x = encoder.encode(String(a ?? ""));
  const y = encoder.encode(String(b ?? ""));

  let diff = x.length ^ y.length;
  const length = Math.max(x.length, y.length);

  for (let i = 0; i < length; i++) {
    diff |= (x[i] || 0) ^ (y[i] || 0);
  }

  return diff === 0;
}

async function digest(value) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return [...new Uint8Array(hash)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function hmac(value, secret) {
  if (!secret) {
    throw new Error("SESSION_SECRET is missing");
  }

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(value)
  );

  return btoa(
    String.fromCharCode(...new Uint8Array(signature))
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// ==========================================
// REQUEST BODY
// ==========================================

async function readJsonBody(request, maxSize) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("نوع البيانات غير صالح");
  }

  const declaredLength = Number(
    request.headers.get("Content-Length") || 0
  );

  if (declaredLength > maxSize) {
    throw new Error("حجم البيانات كبير");
  }

  const buffer = await request.arrayBuffer();

  if (buffer.byteLength > maxSize) {
    throw new Error("حجم البيانات كبير");
  }

  const data = JSON.parse(
    new TextDecoder().decode(buffer)
  );

  if (
    !data ||
    typeof data !== "object" ||
    Array.isArray(data)
  ) {
    throw new Error("بيانات غير صالحة");
  }

  return data;
}

async function body(request) {
  return readJsonBody(request, MAX_BODY_SIZE);
}

async function webauthnBody(request) {
  return readJsonBody(request, MAX_WEBAUTHN_BODY_SIZE);
}

// ==========================================
// COOKIE AND SESSION
// ==========================================

function cookieValue(request, name) {
  const raw = request.headers.get("Cookie") || "";

  const part = raw
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(name + "="));

  if (!part) return "";

  try {
    return decodeURIComponent(
      part.slice(name.length + 1)
    );
  } catch {
    return "";
  }
}

async function makeSession(env) {
  const payload = btoa(JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS,
    nonce: crypto.randomUUID()
  }));

  const signature = await hmac(
    payload,
    env.SESSION_SECRET
  );

  return `${payload}.${signature}`;
}

async function validSession(request, env) {
  if (!env.SESSION_SECRET) return false;

  const value = cookieValue(request, COOKIE);
  const parts = value.split(".");

  if (parts.length !== 2) return false;

  const [payload, signature] = parts;

  const expectedSignature = await hmac(
    payload,
    env.SESSION_SECRET
  );

  if (!safeEqual(signature, expectedSignature)) {
    return false;
  }

  try {
    const session = JSON.parse(atob(payload));

    return (
      Number.isFinite(session.exp) &&
      session.exp > Math.floor(Date.now() / 1000)
    );
  } catch {
    return false;
  }
}

function sessionCookie(token) {
  return [
    `${COOKIE}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "Secure",
    "SameSite=None",
    "Path=/",
    `Max-Age=${SESSION_SECONDS}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${COOKIE}=`,
    "HttpOnly",
    "Secure",
    "SameSite=None",
    "Path=/",
    "Max-Age=0"
  ].join("; ");
}

// ==========================================
// CORS
// ==========================================

function allowedOrigins(env) {
  return [
    env.STUDENT_ORIGIN,
    env.ADMIN_ORIGIN
  ].filter(Boolean);
}

function validOrigin(request, env) {
  const origin = request.headers.get("Origin");

  return !!origin && allowedOrigins(env).includes(origin);
}

function validStudentOrigin(request, env) {
  return (
    !!env.STUDENT_ORIGIN &&
    request.headers.get("Origin") === env.STUDENT_ORIGIN
  );
}

function corsHeaders(origin, env) {
  if (!origin || !allowedOrigins(env).includes(origin)) {
    return {};
  }

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin"
  };
}

function secureResponse(response, request, env) {
  const headers = new Headers(response.headers);
  const origin = request.headers.get("Origin");

  for (const [key, value] of Object.entries(
    corsHeaders(origin, env)
  )) {
    headers.set(key, value);
  }

  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Cache-Control", "no-store");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

// ==========================================
// ADMIN RATE LIMIT
// ==========================================

async function rateLimit(env, ipHash) {
  const windowStart = Date.now() - 15 * 60 * 1000;

  const row = await env.DB.prepare(`
    SELECT COUNT(*) AS n
    FROM login_attempts
    WHERE ip_hash = ?
      AND created_at > ?
  `)
    .bind(ipHash, windowStart)
    .first();

  return (row?.n || 0) < 5;
}

async function recordFailure(env, ipHash) {
  await env.DB.prepare(`
    INSERT INTO login_attempts(ip_hash, created_at)
    VALUES(?, ?)
  `)
    .bind(ipHash, Date.now())
    .run();
}

// ==========================================
// ADMIN AUTHORIZATION
// ==========================================

async function requireAdmin(request, env) {
  return (
    validOrigin(request, env) &&
    await validSession(request, env)
  );
}

// ==========================================
// WEBAUTHN HELPERS
// ==========================================

function getWebAuthnConfig(env) {
  if (!env.STUDENT_ORIGIN) {
    throw new Error("STUDENT_ORIGIN is missing");
  }

  const origin = new URL(env.STUDENT_ORIGIN);

  if (origin.protocol !== "https:") {
    throw new Error("WebAuthn requires HTTPS");
  }

  return {
    expectedOrigin: origin.origin,
    rpID: origin.hostname,
    rpName: "Belhrach School"
  };
}

function bearerToken(request) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);

  return match ? match[1].trim() : "";
}

function bytesToBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const normalized = String(value)
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = normalized + "=".repeat(
    (4 - normalized.length % 4) % 4
  );

  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    char => char.charCodeAt(0)
  );
}

async function getApprovedStudent(env, token) {
  if (!token || token.length < 50 || token.length > 150) {
    return null;
  }

  return await env.DB.prepare(`
    SELECT
      r.id AS request_id,
      r.status AS request_status,
      s.id AS student_id,
      s.first_name,
      s.last_name,
      s.account_status
    FROM student_requests r
    JOIN students s ON s.id = r.student_id
    WHERE r.tracking_token_hash = ?
      AND r.status = 'approved'
      AND s.account_status = 'active'
    LIMIT 1
  `)
    .bind(await digest(token))
    .first();
}

async function getActiveCredential(env, studentId) {
  return await env.DB.prepare(`
    SELECT
      id,
      credential_id,
      public_key,
      sign_count,
      transports,
      device_name
    FROM student_credentials
    WHERE student_id = ?
      AND revoked_at IS NULL
    LIMIT 1
  `)
    .bind(studentId)
    .first();
}

// ==========================================
// ATTENDANCE CLOCK
// ==========================================

async function getAttendanceClock(env) {
  const settings = await env.DB.prepare(`
    SELECT
      timezone,
      opening_time,
      late_time,
      closing_time
    FROM attendance_settings
    WHERE id = 1
    LIMIT 1
  `).first();

  if (!settings) {
    throw new Error("Attendance settings are missing");
  }

  const timezone = settings.timezone || "Africa/Algiers";
  const now = new Date();

  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23"
  }).formatToParts(now);

  const values = {};

  for (const part of parts) {
    if (part.type !== "literal") {
      values[part.type] = part.value;
    }
  }

  const date = `${values.year}-${values.month}-${values.day}`;
  const time = `${values.hour}:${values.minute}`;

  return {
    date,
    time,
    timezone,
    openingTime: settings.opening_time,
    lateTime: settings.late_time,
    closingTime: settings.closing_time,
    timestamp: now.getTime()
  };
}

function attendanceWindow(clock) {
  if (clock.time < clock.openingTime) {
    return "not_open";
  }

  if (clock.time > clock.closingTime) {
    return "closed";
  }

  return "open";
}

function getAttendanceStatus(record, clock) {
  if (record?.status === "present") return "present";
  if (record?.status === "late") return "late";

  const window = attendanceWindow(clock);

  if (window === "not_open") return "not_open";
  if (window === "closed") return "absent";

  return "not_yet";
}

// ==========================================
// WEBAUTHN: REGISTRATION OPTIONS
// ==========================================

async function registrationOptions(request, env) {
  if (!validStudentOrigin(request, env)) {
    return json({ error: "مصدر الطلب غير مسموح" }, 403);
  }

  const token = bearerToken(request);
  const student = await getApprovedStudent(env, token);

  if (!student) {
    return json({
      error: "الحساب غير موجود أو غير مفعل"
    }, 401);
  }

  const existing = await env.DB.prepare(`
    SELECT id, revoked_at
    FROM student_credentials
    WHERE student_id = ?
    LIMIT 1
  `)
    .bind(student.student_id)
    .first();

  if (existing) {
    return json({
      error: existing.revoked_at
        ? "تم إلغاء الجهاز السابق. يرجى التواصل مع الإدارة لإعادة ربط جهازك."
        : "تم ربط جهاز بحسابك مسبقاً."
    }, 409);
  }

  const config = getWebAuthnConfig(env);

  const options = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userID: encoder.encode(student.student_id),
    userName: `${student.first_name} ${student.last_name}`,
    userDisplayName: `${student.first_name} ${student.last_name}`,
    attestationType: "none",
    timeout: 60000,
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required"
    }
  });

  const now = Date.now();
  const challengeId = crypto.randomUUID();

  await env.DB.prepare(`
    DELETE FROM webauthn_challenges
    WHERE student_id = ?
      AND purpose = 'registration'
      AND expires_at <= ?
  `)
    .bind(student.student_id, now)
    .run();

  await env.DB.prepare(`
    INSERT INTO webauthn_challenges (
      id,
      challenge,
      student_id,
      purpose,
      expires_at,
      created_at
    )
    VALUES (?, ?, ?, 'registration', ?, ?)
  `)
    .bind(
      challengeId,
      options.challenge,
      student.student_id,
      now + CHALLENGE_TTL,
      now
    )
    .run();

  return json({
    options,
    challengeId
  });
}

// ==========================================
// WEBAUTHN: VERIFY REGISTRATION
// ==========================================

async function verifyRegistration(request, env) {
  if (!validStudentOrigin(request, env)) {
    return json({ error: "مصدر الطلب غير مسموح" }, 403);
  }

  let data;

  try {
    data = await webauthnBody(request);
  } catch {
    return json({ error: "بيانات التسجيل غير صالحة" }, 400);
  }

  const token = bearerToken(request);
  const student = await getApprovedStudent(env, token);

  if (!student) {
    return json({
      error: "الحساب غير موجود أو غير مفعل"
    }, 401);
  }

  const challengeId = String(data.challengeId || "");

  if (!/^[0-9a-f-]{36}$/i.test(challengeId)) {
    return json({ error: "طلب التسجيل غير صالح" }, 400);
  }

  if (!data.response || typeof data.response !== "object") {
    return json({ error: "استجابة الجهاز غير صالحة" }, 400);
  }

  const now = Date.now();

  const challengeRow = await env.DB.prepare(`
    SELECT id, challenge
    FROM webauthn_challenges
    WHERE id = ?
      AND student_id = ?
      AND purpose = 'registration'
      AND expires_at > ?
    LIMIT 1
  `)
    .bind(challengeId, student.student_id, now)
    .first();

  if (!challengeRow) {
    return json({
      error: "انتهت صلاحية طلب التسجيل. حاول مجدداً."
    }, 400);
  }

  const config = getWebAuthnConfig(env);

  let verification;

  try {
    verification = await verifyRegistrationResponse({
      response: data.response,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: config.expectedOrigin,
      expectedRPID: config.rpID,
      requireUserVerification: true
    });
  } catch (error) {
    console.error(
      "WebAuthn registration verification failed:",
      error
    );

    return json({
      error: "تعذر التحقق من الجهاز. حاول مجدداً."
    }, 400);
  }

  if (
    !verification.verified ||
    !verification.registrationInfo
  ) {
    return json({
      error: "لم ينجح التحقق من الجهاز"
    }, 400);
  }

  const credential = verification.registrationInfo.credential;

  const credentialId = credential.id;
  const publicKey = bytesToBase64Url(credential.publicKey);
  const signCount = credential.counter || 0;
  const transports = JSON.stringify(
    credential.transports || []
  );

  const deviceName = clean(
    data.deviceName || "جهاز التلميذ",
    100
  );

  try {
    const result = await env.DB.prepare(`
      INSERT INTO student_credentials (
        id,
        student_id,
        credential_id,
        public_key,
        sign_count,
        device_name,
        transports,
        created_at,
        last_used_at,
        revoked_at
      )
      SELECT
        ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL
      WHERE EXISTS (
        SELECT 1
        FROM webauthn_challenges
        WHERE id = ?
          AND student_id = ?
          AND purpose = 'registration'
          AND expires_at > ?
      )
    `)
      .bind(
        crypto.randomUUID(),
        student.student_id,
        credentialId,
        publicKey,
        signCount,
        deviceName,
        transports,
        now,
        now,
        challengeId,
        student.student_id,
        now
      )
      .run();

    if (!result.meta?.changes) {
      return json({
        error: "انتهت صلاحية طلب التسجيل أو تمت معالجته مسبقاً."
      }, 409);
    }

    await env.DB.prepare(`
      DELETE FROM webauthn_challenges
      WHERE id = ?
        AND student_id = ?
        AND purpose = 'registration'
    `)
      .bind(challengeId, student.student_id)
      .run();

  } catch (error) {
    console.error("Credential storage failed:", error);

    return json({
      error: "تعذر حفظ الجهاز. ربما تم ربط جهاز بحسابك مسبقاً."
    }, 409);
  }

  await env.DB.prepare(`
    INSERT INTO attendance_audit (
      id,
      admin_action,
      target_student_id,
      details,
      created_at
    )
    VALUES (?, 'student_device_registered', ?, ?, ?)
  `)
    .bind(
      crypto.randomUUID(),
      student.student_id,
      JSON.stringify({ deviceName }),
      now
    )
    .run();

  return json({
    ok: true,
    registered: true,
    message: "تم ربط جهازك بنجاح"
  });
}

// ==========================================
// ATTENDANCE: AUTHENTICATION OPTIONS
// ==========================================

async function attendanceOptions(request, env) {
  if (!validStudentOrigin(request, env)) {
    return json({ error: "مصدر الطلب غير مسموح" }, 403);
  }

  const student = await getApprovedStudent(
    env,
    bearerToken(request)
  );

  if (!student) {
    return json({
      error: "الحساب غير موجود أو غير مفعل"
    }, 401);
  }

  const credential = await getActiveCredential(
    env,
    student.student_id
  );

  if (!credential) {
    return json({
      error: "لم يتم ربط جهاز بهذا الحساب. اربط جهازك أولاً."
    }, 409);
  }

  const clock = await getAttendanceClock(env);
  const window = attendanceWindow(clock);

  if (window === "not_open") {
    return json({
      error: `لم يبدأ وقت تسجيل الحضور بعد. يبدأ عند ${clock.openingTime}.`
    }, 403);
  }

  if (window === "closed") {
    return json({
      error: "انتهى وقت تسجيل الحضور لهذا اليوم."
    }, 403);
  }

  const existing = await env.DB.prepare(`
    SELECT id, status, check_in_at
    FROM attendance_records
    WHERE student_id = ?
      AND attendance_date = ?
    LIMIT 1
  `)
    .bind(student.student_id, clock.date)
    .first();

  if (existing) {
    return json({
      error: "تم تسجيل حضورك اليوم مسبقاً.",
      alreadyRecorded: true,
      attendance: {
        status: existing.status,
        checkInAt: existing.check_in_at
      }
    }, 409);
  }

  const config = getWebAuthnConfig(env);

  let transports = [];

  try {
    transports = JSON.parse(credential.transports || "[]");
  } catch {
    transports = [];
  }

  const options = await generateAuthenticationOptions({
    rpID: config.rpID,
    timeout: 60000,
    userVerification: "required",
    allowCredentials: [{
      id: credential.credential_id,
      transports
    }]
  });

  const now = Date.now();
  const challengeId = crypto.randomUUID();

  await env.DB.prepare(`
    DELETE FROM webauthn_challenges
    WHERE student_id = ?
      AND purpose = 'attendance'
      AND expires_at <= ?
  `)
    .bind(student.student_id, now)
    .run();

  await env.DB.prepare(`
    INSERT INTO webauthn_challenges (
      id,
      challenge,
      student_id,
      purpose,
      expires_at,
      created_at
    )
    VALUES (?, ?, ?, 'attendance', ?, ?)
  `)
    .bind(
      challengeId,
      options.challenge,
      student.student_id,
      now + CHALLENGE_TTL,
      now
    )
    .run();

  return json({
    options,
    challengeId
  });
}

// ==========================================
// ATTENDANCE: VERIFY AND RECORD
// ==========================================

async function verifyAttendance(request, env) {
  if (!validStudentOrigin(request, env)) {
    return json({ error: "مصدر الطلب غير مسموح" }, 403);
  }

  let data;

  try {
    data = await webauthnBody(request);
  } catch {
    return json({ error: "بيانات التحقق غير صالحة" }, 400);
  }

  const student = await getApprovedStudent(
    env,
    bearerToken(request)
  );

  if (!student) {
    return json({
      error: "الحساب غير موجود أو غير مفعل"
    }, 401);
  }

  const challengeId = String(data.challengeId || "");

  if (!/^[0-9a-f-]{36}$/i.test(challengeId)) {
    return json({ error: "طلب الحضور غير صالح" }, 400);
  }

  if (!data.response || typeof data.response !== "object") {
    return json({ error: "استجابة الجهاز غير صالحة" }, 400);
  }

  const now = Date.now();

  const challengeRow = await env.DB.prepare(`
    SELECT id, challenge
    FROM webauthn_challenges
    WHERE id = ?
      AND student_id = ?
      AND purpose = 'attendance'
      AND expires_at > ?
    LIMIT 1
  `)
    .bind(challengeId, student.student_id, now)
    .first();

  if (!challengeRow) {
    return json({
      error: "انتهت صلاحية طلب الحضور. حاول مجدداً."
    }, 400);
  }

  const credential = await getActiveCredential(
    env,
    student.student_id
  );

  if (!credential) {
    return json({
      error: "الجهاز غير مربوط أو تم إلغاؤه."
    }, 409);
  }

  const clock = await getAttendanceClock(env);
  const window = attendanceWindow(clock);

  if (window !== "open") {
    return json({
      error: window === "not_open"
        ? "لم يبدأ وقت تسجيل الحضور."
        : "انتهى وقت تسجيل الحضور."
    }, 403);
  }

  const existing = await env.DB.prepare(`
    SELECT id, status, check_in_at
    FROM attendance_records
    WHERE student_id = ?
      AND attendance_date = ?
    LIMIT 1
  `)
    .bind(student.student_id, clock.date)
    .first();

  if (existing) {
    return json({
      error: "تم تسجيل حضورك اليوم مسبقاً.",
      alreadyRecorded: true
    }, 409);
  }

  const config = getWebAuthnConfig(env);

  let transports = [];

  try {
    transports = JSON.parse(credential.transports || "[]");
  } catch {
    transports = [];
  }

  const storedCredential = {
    id: credential.credential_id,
    publicKey: base64UrlToBytes(credential.public_key),
    counter: Number(credential.sign_count) || 0,
    transports
  };

  let verification;

  try {
    verification = await verifyAuthenticationResponse({
      response: data.response,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: config.expectedOrigin,
      expectedRPID: config.rpID,
      credential: storedCredential,
      requireUserVerification: true
    });
  } catch (error) {
    console.error(
      "WebAuthn attendance verification failed:",
      error
    );

    return json({
      error: "فشل التحقق من الجهاز. حاول مجدداً."
    }, 400);
  }

  if (
    !verification.verified ||
    !verification.authenticationInfo
  ) {
    return json({
      error: "لم ينجح التحقق من الجهاز."
    }, 400);
  }

  const newCounter = Number(
    verification.authenticationInfo.newCounter
  );

  if (!Number.isSafeInteger(newCounter) || newCounter < 0) {
    return json({
      error: "عداد التحقق من الجهاز غير صالح."
    }, 400);
  }

  const finalClock = await getAttendanceClock(env);

  if (
    finalClock.date !== clock.date ||
    attendanceWindow(finalClock) !== "open"
  ) {
    return json({
      error: "انتهت نافذة تسجيل الحضور. لم يتم تسجيل حضورك."
    }, 403);
  }

  const status = finalClock.time < finalClock.lateTime
    ? "present"
    : "late";

  const attendanceId = crypto.randomUUID();
  const auditId = crypto.randomUUID();

  try {
    const results = await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO attendance_records (
          id,
          student_id,
          attendance_date,
          check_in_at,
          status,
          verification_method,
          created_at
        )
        SELECT
          ?, ?, ?, ?, ?, 'webauthn', ?
        WHERE EXISTS (
          SELECT 1
          FROM webauthn_challenges
          WHERE id = ?
            AND student_id = ?
            AND purpose = 'attendance'
            AND expires_at > ?
        )
        AND EXISTS (
          SELECT 1
          FROM student_credentials
          WHERE id = ?
            AND student_id = ?
            AND revoked_at IS NULL
            AND sign_count = ?
        )
        AND NOT EXISTS (
          SELECT 1
          FROM attendance_records
          WHERE student_id = ?
            AND attendance_date = ?
        )
      `).bind(
        attendanceId,
        student.student_id,
        finalClock.date,
        finalClock.timestamp,
        status,
        finalClock.timestamp,
        challengeId,
        student.student_id,
        finalClock.timestamp,
        credential.id,
        student.student_id,
        Number(credential.sign_count) || 0,
        student.student_id,
        finalClock.date
      ),

      env.DB.prepare(`
        DELETE FROM webauthn_challenges
        WHERE id = ?
          AND student_id = ?
          AND purpose = 'attendance'
          AND EXISTS (
            SELECT 1
            FROM attendance_records
            WHERE id = ?
          )
      `).bind(
        challengeId,
        student.student_id,
        attendanceId
      ),

      env.DB.prepare(`
        UPDATE student_credentials
        SET sign_count = ?,
            last_used_at = ?
        WHERE id = ?
          AND student_id = ?
          AND revoked_at IS NULL
          AND EXISTS (
            SELECT 1
            FROM attendance_records
            WHERE id = ?
          )
      `).bind(
        newCounter,
        finalClock.timestamp,
        credential.id,
        student.student_id,
        attendanceId
      ),

      env.DB.prepare(`
        INSERT INTO attendance_audit (
          id,
          admin_action,
          target_student_id,
          details,
          created_at
        )
        SELECT
          ?, 'student_attendance_recorded', ?, ?, ?
        WHERE EXISTS (
          SELECT 1
          FROM attendance_records
          WHERE id = ?
        )
      `).bind(
        auditId,
        student.student_id,
        JSON.stringify({
          date: finalClock.date,
          time: finalClock.time,
          status,
          verificationMethod: "webauthn"
        }),
        finalClock.timestamp,
        attendanceId
      )
    ]);

    const inserted = results[0]?.meta?.changes || 0;

    if (!inserted) {
      const already = await env.DB.prepare(`
        SELECT id
        FROM attendance_records
        WHERE student_id = ?
          AND attendance_date = ?
        LIMIT 1
      `)
        .bind(student.student_id, finalClock.date)
        .first();

      if (already) {
        return json({
          error: "تم تسجيل حضورك اليوم مسبقاً.",
          alreadyRecorded: true
        }, 409);
      }

      return json({
        error: "تعذر تسجيل الحضور. انتهت صلاحية الطلب أو تغيرت حالة الجهاز."
      }, 409);
    }

  } catch (error) {
    console.error("Attendance database transaction failed:", error);

    return json({
      error: "تعذر حفظ الحضور. ربما تم تسجيله مسبقاً."
    }, 409);
  }

  return json({
    ok: true,
    recorded: true,
    attendance: {
      date: finalClock.date,
      time: finalClock.time,
      checkInAt: finalClock.timestamp,
      status,
      timezone: finalClock.timezone
    },
    message: status === "present"
      ? "تم تسجيل حضورك بنجاح."
      : "تم تسجيل حضورك، لكنك متأخر."
  });
}

// ==========================================
// STUDENT: GET TODAY ATTENDANCE
// ==========================================

async function studentTodayAttendance(request, env) {
  if (!validStudentOrigin(request, env)) {
    return json({ error: "مصدر الطلب غير مسموح" }, 403);
  }

  const student = await getApprovedStudent(
    env,
    bearerToken(request)
  );

  if (!student) {
    return json({
      error: "الحساب غير موجود أو غير مفعل"
    }, 401);
  }

  const clock = await getAttendanceClock(env);

  const record = await env.DB.prepare(`
    SELECT
      attendance_date AS date,
      check_in_at AS checkInAt,
      status,
      verification_method AS verificationMethod
    FROM attendance_records
    WHERE student_id = ?
      AND attendance_date = ?
    LIMIT 1
  `)
    .bind(student.student_id, clock.date)
    .first();

  const status = getAttendanceStatus(record, clock);

  return json({
    ok: true,
    date: clock.date,
    time: clock.time,
    timezone: clock.timezone,
    status,
    attendance: record || null
  });
}

// ==========================================
// MAIN API
// ==========================================

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  // HEALTH

  if (path === "/api/health" && method === "GET") {
    return json({
      status: "ok",
      service: "Belhrach School API"
    });
  }

  // STUDENT: CREATE REQUEST

  if (
    path === "/api/student/requests" &&
    method === "POST"
  ) {
    if (!validOrigin(request, env)) {
      return json({ error: "مصدر الطلب غير مسموح" }, 403);
    }

    let data;

    try {
      data = await body(request);
    } catch {
      return json({ error: "بيانات غير صالحة" }, 400);
    }

    const firstName = clean(data.firstName, 60);
    const lastName = clean(data.lastName, 60);
    const className = clean(data.className, 40);

    if (
      firstName.length < 2 ||
      lastName.length < 2 ||
      !className
    ) {
      return json({
        error: "يرجى إدخال الاسم واللقب واختيار القسم بشكل صحيح"
      }, 400);
    }

    const selectedClass = await env.DB.prepare(`
      SELECT id, name
      FROM classes
      WHERE name = ?
    `)
      .bind(className)
      .first();

    if (!selectedClass) {
      return json({
        error: "القسم المختار غير موجود"
      }, 400);
    }

    const id = crypto.randomUUID();
    const token = crypto.randomUUID() + crypto.randomUUID();
    const tokenHash = await digest(token);
    const now = Date.now();

    await env.DB.prepare(`
      INSERT INTO student_requests (
        id,
        first_name,
        last_name,
        class_id,
        status,
        tracking_token_hash,
        created_at
      )
      VALUES (?, ?, ?, ?, 'pending', ?, ?)
    `)
      .bind(
        id,
        firstName,
        lastName,
        selectedClass.id,
        tokenHash,
        now
      )
      .run();

    return json({
      ok: true,
      token,
      status: "pending"
    }, 201);
  }

  // STUDENT: CHECK REQUEST STATUS

  if (
    path === "/api/student/status" &&
    method === "GET"
  ) {
    const token = bearerToken(request);

    if (token.length < 50 || token.length > 150) {
      return json({
        error: "رمز المتابعة غير صالح"
      }, 401);
    }

    const row = await env.DB.prepare(`
      SELECT
        r.status,
        r.student_id,

        EXISTS (
          SELECT 1
          FROM student_credentials sc
          WHERE sc.student_id = r.student_id
            AND sc.revoked_at IS NULL
        ) AS device_registered,

        EXISTS (
          SELECT 1
          FROM student_credentials sc
          WHERE sc.student_id = r.student_id
            AND sc.revoked_at IS NOT NULL
        ) AS device_revoked

      FROM student_requests r
      WHERE r.tracking_token_hash = ?
      LIMIT 1
    `)
      .bind(await digest(token))
      .first();

    if (!row) {
      return json({
        error: "الطلب غير موجود"
      }, 404);
    }

    return json({
      status: row.status,
      setupAvailable: row.status === "approved" && !!row.student_id,
      deviceRegistered: Boolean(row.device_registered),
      deviceRevoked: Boolean(row.device_revoked)
    });
  }

  // STUDENT: REGISTRATION OPTIONS

  if (
    path === "/api/student/webauthn/register/options" &&
    method === "POST"
  ) {
    return await registrationOptions(request, env);
  }

  // STUDENT: REGISTRATION VERIFY

  if (
    path === "/api/student/webauthn/register/verify" &&
    method === "POST"
  ) {
    return await verifyRegistration(request, env);
  }

  // STUDENT: ATTENDANCE OPTIONS

  if (
    path === "/api/student/webauthn/attendance/options" &&
    method === "POST"
  ) {
    return await attendanceOptions(request, env);
  }

  // STUDENT: ATTENDANCE VERIFY

  if (
    path === "/api/student/webauthn/attendance/verify" &&
    method === "POST"
  ) {
    return await verifyAttendance(request, env);
  }

  // STUDENT: TODAY ATTENDANCE

  if (
    path === "/api/student/attendance/today" &&
    method === "GET"
  ) {
    return await studentTodayAttendance(request, env);
  }

  // ADMIN: LOGIN

  if (
    path === "/api/admin/login" &&
    method === "POST"
  ) {
    if (!validOrigin(request, env)) {
      return json({ error: "مصدر الطلب غير مسموح" }, 403);
    }

    if (
      !env.ADMIN_ACCESS_CODE ||
      !env.ADMIN_SECURITY_ANSWER ||
      !env.SESSION_SECRET
    ) {
      return json({
        error: "إعدادات الإدارة غير مكتملة"
      }, 500);
    }

    const ip =
      request.headers.get("CF-Connecting-IP") || "unknown";

    const ipHash = await digest(
      ip + env.SESSION_SECRET
    );

    if (!await rateLimit(env, ipHash)) {
      return json({
        error: "محاولات كثيرة. حاول بعد 15 دقيقة."
      }, 429);
    }

    let data;

    try {
      data = await body(request);
    } catch {
      return json({ error: "بيانات غير صالحة" }, 400);
    }

    const codeOk = safeEqual(
      String(data.code || ""),
      env.ADMIN_ACCESS_CODE
    );

    const answerOk = safeEqual(
      normalize(data.answer),
      normalize(env.ADMIN_SECURITY_ANSWER)
    );

    if (!codeOk || !answerOk) {
      await recordFailure(env, ipHash);

      return json({
        error: "كود الإدارة أو إجابة سؤال التحقق غير صحيحة"
      }, 401);
    }

    await env.DB.prepare(`
      DELETE FROM login_attempts
      WHERE ip_hash = ?
    `)
      .bind(ipHash)
      .run();

    const session = await makeSession(env);

    return json({
      ok: true
    }, 200, {
      "Set-Cookie": sessionCookie(session)
    });
  }

  // ADMIN: LOGOUT

  if (
    path === "/api/admin/logout" &&
    method === "POST"
  ) {
    if (!await requireAdmin(request, env)) {
      return json({ error: "غير مصرح" }, 401);
    }

    return json({
      ok: true
    }, 200, {
      "Set-Cookie": clearSessionCookie()
    });
  }

  // ADMIN: GET REQUESTS

  if (
    path === "/api/admin/requests" &&
    method === "GET"
  ) {
    if (!await requireAdmin(request, env)) {
      return json({ error: "غير مصرح" }, 401);
    }

    const result = await env.DB.prepare(`
      SELECT
        r.id,
        r.first_name AS firstName,
        r.last_name AS lastName,
        c.name AS className,
        r.status,
        r.created_at AS createdAt,
        r.reviewed_at AS reviewedAt,
        r.student_id AS studentId,

        CASE
          WHEN EXISTS (
            SELECT 1
            FROM student_credentials sc
            WHERE sc.student_id = r.student_id
              AND sc.revoked_at IS NULL
          )
          THEN 1
          ELSE 0
        END AS deviceRegistered,

        CASE
          WHEN EXISTS (
            SELECT 1
            FROM student_credentials revoked
            WHERE revoked.student_id = r.student_id
              AND revoked.revoked_at IS NOT NULL
          )
          THEN 1
          ELSE 0
        END AS deviceRevoked

      FROM student_requests r

      JOIN classes c
        ON c.id = r.class_id

      ORDER BY r.created_at DESC
      LIMIT 200
    `).all();

    return json({
      requests: (result.results || []).map(item => ({
        ...item,
        deviceRegistered: Boolean(item.deviceRegistered),
        deviceRevoked: Boolean(item.deviceRevoked)
      }))
    });
  }

  // ==========================================
  // ADMIN: GET STUDENTS BY CLASS
  // ==========================================

  const classStudentsMatch = path.match(
    /^\/api\/admin\/classes\/(.+)\/students$/
  );

  if (classStudentsMatch && method === "GET") {
    if (!await requireAdmin(request, env)) {
      return json({ error: "غير مصرح" }, 401);
    }

    let className;

    try {
      className = clean(
        decodeURIComponent(classStudentsMatch[1]),
        40
      );
    } catch {
      return json({ error: "اسم القسم غير صالح" }, 400);
    }

    if (!className) {
      return json({ error: "اسم القسم مطلوب" }, 400);
    }

    const selectedClass = await env.DB.prepare(`
      SELECT id, name
      FROM classes
      WHERE name = ?
      LIMIT 1
    `)
      .bind(className)
      .first();

    if (!selectedClass) {
      return json({ error: "القسم غير موجود" }, 404);
    }

    const clock = await getAttendanceClock(env);

    const result = await env.DB.prepare(`
      SELECT
        s.id,
        s.first_name AS firstName,
        s.last_name AS lastName,
        s.account_status AS accountStatus,
        s.created_at AS createdAt,

        CASE
          WHEN sc.id IS NOT NULL
            AND sc.revoked_at IS NULL
          THEN 1
          ELSE 0
        END AS deviceRegistered,

        CASE
          WHEN sc.id IS NOT NULL
            AND sc.revoked_at IS NOT NULL
          THEN 1
          ELSE 0
        END AS deviceRevoked,

        ar.status AS recordedAttendanceStatus,
        ar.check_in_at AS checkInAt

      FROM students s

      LEFT JOIN student_credentials sc
        ON sc.student_id = s.id

      LEFT JOIN attendance_records ar
        ON ar.student_id = s.id
        AND ar.attendance_date = ?

      WHERE s.class_id = ?

      ORDER BY
        s.first_name COLLATE NOCASE ASC,
        s.last_name COLLATE NOCASE ASC
    `)
      .bind(clock.date, selectedClass.id)
      .all();

    const students = (result.results || []).map(student => {
      const record = student.recordedAttendanceStatus
        ? { status: student.recordedAttendanceStatus }
        : null;

      return {
        id: student.id,
        firstName: student.firstName,
        lastName: student.lastName,
        accountStatus: student.accountStatus,
        createdAt: student.createdAt,

        deviceRegistered: Boolean(student.deviceRegistered),
        deviceRevoked: Boolean(student.deviceRevoked),

        attendanceStatus: student.accountStatus === "active"
          ? getAttendanceStatus(record, clock)
          : "suspended",

        checkInAt: student.checkInAt
      };
    });

    return json({
      ok: true,

      class: {
        id: selectedClass.id,
        name: selectedClass.name
      },

      total: students.length,

      attendance: {
        date: clock.date,
        time: clock.time,
        timezone: clock.timezone,
        openingTime: clock.openingTime,
        lateTime: clock.lateTime,
        closingTime: clock.closingTime
      },

      students
    });
  }

  // ==========================================
  // ADMIN: APPROVE / REJECT REQUEST
  // ==========================================

  const match = path.match(
    /^\/api\/admin\/requests\/([0-9a-f-]{36})$/i
  );

  if (match && method === "PATCH") {
    if (!await requireAdmin(request, env)) {
      return json({ error: "غير مصرح" }, 401);
    }

    let data;

    try {
      data = await body(request);
    } catch {
      return json({ error: "بيانات غير صالحة" }, 400);
    }

    if (!["approved", "rejected"].includes(data.status)) {
      return json({ error: "قرار غير صالح" }, 400);
    }

    const requestId = match[1];
    const now = Date.now();

    const existing = await env.DB.prepare(`
      SELECT id, status
      FROM student_requests
      WHERE id = ?
    `)
      .bind(requestId)
      .first();

    if (!existing || existing.status !== "pending") {
      return json({
        error: "الطلب غير موجود أو تمت معالجته سابقاً"
      }, 409);
    }

    if (data.status === "rejected") {
      const result = await env.DB.prepare(`
        UPDATE student_requests
        SET status = 'rejected',
            reviewed_at = ?
        WHERE id = ?
          AND status = 'pending'
      `)
        .bind(now, requestId)
        .run();

      if (!result.meta?.changes) {
        return json({
          error: "الطلب غير موجود أو تمت معالجته سابقاً"
        }, 409);
      }

      await env.DB.prepare(`
        INSERT INTO attendance_audit (
          id,
          admin_action,
          target_student_id,
          details,
          created_at
        )
        VALUES (?, 'request_rejected', NULL, ?, ?)
      `)
        .bind(
          crypto.randomUUID(),
          JSON.stringify({ requestId }),
          now
        )
        .run();

      return json({
        ok: true,
        status: "rejected"
      });
    }

    const studentId = crypto.randomUUID();

    const results = await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO students (
          id,
          first_name,
          last_name,
          class_id,
          account_status,
          created_at,
          updated_at
        )
        SELECT
          ?,
          first_name,
          last_name,
          class_id,
          'active',
          ?,
          ?
        FROM student_requests
        WHERE id = ?
          AND status = 'pending'
          AND student_id IS NULL
      `)
        .bind(studentId, now, now, requestId),

      env.DB.prepare(`
        UPDATE student_requests
        SET status = 'approved',
            student_id = ?,
            reviewed_at = ?
        WHERE id = ?
          AND status = 'pending'
          AND student_id IS NULL
      `)
        .bind(studentId, now, requestId)
    ]);

    const created = results[0]?.meta?.changes || 0;
    const updated = results[1]?.meta?.changes || 0;

    if (!created || !updated) {
      return json({
        error: "تعذرت الموافقة على الطلب. ربما تمت معالجته مسبقاً."
      }, 409);
    }

    await env.DB.prepare(`
      INSERT INTO attendance_audit (
        id,
        admin_action,
        target_student_id,
        details,
        created_at
      )
      VALUES (?, 'student_approved', ?, ?, ?)
    `)
      .bind(
        crypto.randomUUID(),
        studentId,
        JSON.stringify({ requestId }),
        now
      )
      .run();

    return json({
      ok: true,
      status: "approved",
      studentId,
      setupAvailable: true
    });
  }

  // ==========================================
  // NOT FOUND
  // ==========================================

  return json({
    error: "المسار غير موجود"
  }, 404);
}

// ==========================================
// CLOUDFLARE WORKER
// ==========================================

export default {
  async fetch(request, env) {
    try {
      const response = await handle(request, env);

      return secureResponse(response, request, env);

    } catch (error) {
      console.error("API error:", error);

      return secureResponse(
        json({
          error: "خطأ داخلي في الخادم"
        }, 500),
        request,
        env
      );
    }
  }
};
