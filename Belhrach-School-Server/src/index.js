
const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8"
};

const encoder = new TextEncoder();

const COOKIE = "bs_admin_session";
const SESSION_SECONDS = 8 * 60 * 60;
const MAX_BODY_SIZE = 5000;

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
// COOKIE
// ==========================================

function cookieValue(request, name) {
  const raw = request.headers.get("Cookie") || "";

  const part = raw
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(name + "="));

  if (!part) return "";

  const value = part.slice(name.length + 1);

  try {
    return decodeURIComponent(value);
  } catch {
    return "";
  }
}

async function makeSession(env) {
  if (!env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET is missing");
  }

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

function corsHeaders(origin, env) {
  const allowed = allowedOrigins(env);

  if (!origin || !allowed.includes(origin)) {
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

// ==========================================
// SECURITY RESPONSE HEADERS
// ==========================================

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
// REQUEST BODY
// ==========================================

async function body(request) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("نوع البيانات غير صالح");
  }

  const declaredLength = Number(
    request.headers.get("Content-Length") || 0
  );

  if (declaredLength > MAX_BODY_SIZE) {
    throw new Error("حجم البيانات كبير");
  }

  const buffer = await request.arrayBuffer();

  if (buffer.byteLength > MAX_BODY_SIZE) {
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

// ==========================================
// INPUT CLEANING
// ==========================================

function clean(value, max) {
  return String(value ?? "")
    .normalize("NFKC")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, max);
}

// ==========================================
// LOGIN RATE LIMIT
// ==========================================

async function rateLimit(env, ipHash) {
  const now = Date.now();
  const windowStart = now - 15 * 60 * 1000;

  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM login_attempts WHERE ip_hash=? AND created_at>?"
  )
    .bind(ipHash, windowStart)
    .first();

  return (row?.n || 0) < 5;
}

async function recordFailure(env, ipHash) {
  await env.DB.prepare(
    "INSERT INTO login_attempts(ip_hash, created_at) VALUES(?, ?)"
  )
    .bind(ipHash, Date.now())
    .run();
}

// ==========================================
// MAIN API HANDLER
// ==========================================

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS preflight
  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204
    });
  }

  // ========================================
  // HEALTH CHECK
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
      return json({
        error: "مصدر الطلب غير مسموح"
      }, 403);
    }

    let data;

    try {
      data = await body(request);
    } catch {
      return json({
        error: "بيانات غير صالحة"
      }, 400);
    }

    const firstName = clean(data.firstName, 60);
    const lastName = clean(data.lastName, 60);
    const className = clean(data.className, 40);

    if (!firstName || !lastName || !className) {
      return json({
        error: "يرجى ملء جميع الحقول"
      }, 400);
    }

    if (firstName.length < 2 || lastName.length < 2) {
      return json({
        error: "الاسم واللقب يجب أن يحتوي كل منهما على حرفين على الأقل"
      }, 400);
    }

    const id = crypto.randomUUID();

    const token =
      crypto.randomUUID() + crypto.randomUUID();

    const tokenHash = await digest(token);
    const createdAt = Date.now();

    await env.DB.prepare(`
      INSERT INTO student_requests
      (id, first_name, last_name, class_name, status, token_hash, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
      .bind(
        id,
        firstName,
        lastName,
        className,
        "pending",
        tokenHash,
        createdAt
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
    const token = (
      request.headers.get("Authorization") || ""
    ).replace(/^Bearer\s+/i, "");

    if (token.length < 50 || token.length > 150) {
      return json({
        error: "رمز المتابعة غير صالح"
      }, 401);
    }

    const row = await env.DB.prepare(
      "SELECT status FROM student_requests WHERE token_hash=?"
    )
      .bind(await digest(token))
      .first();

    if (!row) {
      return json({
        error: "الطلب غير موجود"
      }, 404);
    }

    return json({
      status: row.status
    });
  }

  // ========================================
  // ADMIN: LOGIN
  // ========================================

  if (
    path === "/api/admin/login" &&
    method === "POST"
  ) {
    if (!validOrigin(request, env)) {
      return json({
        error: "مصدر الطلب غير مسموح"
      }, 403);
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
      return json({
        error: "بيانات غير صالحة"
      }, 400);
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

    await env.DB.prepare(
      "DELETE FROM login_attempts WHERE ip_hash=?"
    )
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
    if (
      !validOrigin(request, env) ||
      !await validSession(request, env)
    ) {
      return json({
        error: "غير مصرح"
      }, 401);
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
    if (
      !validOrigin(request, env) ||
      !await validSession(request, env)
    ) {
      return json({
        error: "غير مصرح"
      }, 401);
    }

    const result = await env.DB.prepare(`
      SELECT
        id,
        first_name AS firstName,
        last_name AS lastName,
        class_name AS className,
        status,
        created_at AS createdAt
      FROM student_requests
      ORDER BY created_at DESC
      LIMIT 200
    `).all();

    return json({
      requests: result.results || []
    });
  }

  // ========================================
  // ADMIN: APPROVE / REJECT REQUEST
  // ========================================

  const match = path.match(
    /^\/api\/admin\/requests\/([0-9a-f-]{36})$/i
  );

  if (match && method === "PATCH") {
    if (
      !validOrigin(request, env) ||
      !await validSession(request, env)
    ) {
      return json({
        error: "غير مصرح"
      }, 401);
    }

    let data;

    try {
      data = await body(request);
    } catch {
      return json({
        error: "بيانات غير صالحة"
      }, 400);
    }

    if (!["approved", "rejected"].includes(data.status)) {
      return json({
        error: "قرار غير صالح"
      }, 400);
    }

    const result = await env.DB.prepare(`
      UPDATE student_requests
      SET status=?
      WHERE id=? AND status='pending'
    `)
      .bind(data.status, match[1])
      .run();

    if (!result.meta?.changes) {
      return json({
        error: "الطلب غير موجود أو تمت معالجته سابقاً"
      }, 409);
    }

    return json({
      ok: true,
      status: data.status
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

      const response = json({
        error: "خطأ داخلي في الخادم"
      }, 500);

      return secureResponse(response, request, env);
    }
  }
};
