
import {
  generateRegistrationOptions,
  verifyRegistrationResponse
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

  // Check whether the student already has a credential.
  // A revoked credential also blocks self-service replacement.
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

  // Clean expired challenges for this student.
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
    // The INSERT is conditional on the challenge still existing.
    // UNIQUE(student_id) and UNIQUE(credential_id) are additional
    // database-level protections against duplicate registration.
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

    // Consume the challenge after successful credential insertion.
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
      JSON.stringify({
        deviceName
      }),
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
// MAIN API
// ==========================================

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS preflight
  if (method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  // ========================================
  // HEALTH
  // ========================================

  if (path === "/api/health" && method === "GET") {
    return json({
      status: "ok",
      service: "Belhrach School API"
    });
  }

  // ========================================
  // STUDENT: CREATE REQUEST
  // ========================================

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

    const token =
      crypto.randomUUID() + crypto.randomUUID();

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

  // ========================================
  // STUDENT: CHECK REQUEST STATUS
  // ========================================

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
      SELECT status, student_id
      FROM student_requests
      WHERE tracking_token_hash = ?
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
      setupAvailable: row.status === "approved" && !!row.student_id
    });
  }

  // ========================================
  // STUDENT: WEBAUTHN REGISTRATION OPTIONS
  // ========================================

  if (
    path === "/api/student/webauthn/register/options" &&
    method === "POST"
  ) {
    return await registrationOptions(request, env);
  }

  // ========================================
  // STUDENT: WEBAUTHN REGISTRATION VERIFY
  // ========================================

  if (
    path === "/api/student/webauthn/register/verify" &&
    method === "POST"
  ) {
    return await verifyRegistration(request, env);
  }

  // ========================================
  // ADMIN: LOGIN
  // ========================================

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

  // ========================================
  // ADMIN: LOGOUT
  // ========================================

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

  // ========================================
  // ADMIN: GET REQUESTS
  // ========================================

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
          WHEN sc.id IS NOT NULL THEN 1
          ELSE 0
        END AS deviceRegistered

      FROM student_requests r

      JOIN classes c
        ON c.id = r.class_id

      LEFT JOIN student_credentials sc
        ON sc.student_id = r.student_id
        AND sc.revoked_at IS NULL

      ORDER BY r.created_at DESC
      LIMIT 200
    `).all();

    return json({
      requests: (result.results || []).map(item => ({
        ...item,
        deviceRegistered: Boolean(item.deviceRegistered)
      }))
    });
  }

  // ========================================
  // ADMIN: APPROVE / REJECT REQUEST
  // ========================================

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

    // REJECT
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

    // APPROVE: CREATE STUDENT ACCOUNT
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

  // ========================================
  // NOT FOUND
  // ========================================

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
