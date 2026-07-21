const SESSION_DURATION_SECONDS = 8 * 60 * 60;

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function parsePasswordHash(value) {
  const parts = String(value || "").split("$");

  if (
    parts.length !== 4 ||
    parts[0] !== "pbkdf2-sha256" ||
    !Number.isInteger(Number(parts[1]))
  ) {
    return null;
  }

  return {
    iterations: Number(parts[1]),
    salt: parts[2],
    hash: parts[3]
  };
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) {
    return false;
  }

  let difference = 0;

  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }

  return difference === 0;
}

async function verifyPassword(password, storedHash) {
  const parsed = parsePasswordHash(storedHash);

  if (!parsed) {
    return false;
  }

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: base64ToBytes(parsed.salt),
      iterations: parsed.iterations
    },
    keyMaterial,
    256
  );

  return constantTimeEqual(
    new Uint8Array(derivedBits),
    base64ToBytes(parsed.hash)
  );
}

async function sha256Base64(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return bytesToBase64(new Uint8Array(digest));
}

export async function onRequestPost(context) {
  try {
    const contentType = context.request.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      return json(
        { ok: false, message: "El contenido debe enviarse como JSON." },
        415
      );
    }

    const body = await context.request.json();
    const login = String(body?.login || "").trim().toLowerCase();
    const password = String(body?.password || "");

    if (!login || !password) {
      return json(
        { ok: false, message: "Usuario y contraseña son obligatorios." },
        400
      );
    }

    const user = await context.env.DB
      .prepare(`
        SELECT
          id,
          name,
          local_login,
          role,
          status,
          password_hash
        FROM users
        WHERE LOWER(local_login) = ?
        LIMIT 1
      `)
      .bind(login)
      .first();

    const validPassword =
      user?.status === "active" &&
      await verifyPassword(password, user?.password_hash);

    if (!user || !validPassword) {
      return json(
        { ok: false, message: "Credenciales incorrectas." },
        401
      );
    }

    const sessionId = crypto.randomUUID();
    const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
    const sessionToken = bytesToBase64(tokenBytes)
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");

    const tokenHash = await sha256Base64(sessionToken);
    const expiresAt = new Date(
      Date.now() + SESSION_DURATION_SECONDS * 1000
    ).toISOString();

    await context.env.DB
      .prepare(`
        INSERT INTO sessions (
          id,
          user_id,
          token_hash,
          expires_at,
          user_agent,
          ip_address
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      .bind(
        sessionId,
        user.id,
        tokenHash,
        expiresAt,
        context.request.headers.get("user-agent") || null,
        context.request.headers.get("CF-Connecting-IP") || null
      )
      .run();

    return json(
      {
        ok: true,
        user: {
          id: user.id,
          name: user.name,
          login: user.local_login,
          role: user.role
        }
      },
      200,
      {
        "Set-Cookie": [
          "a365_session=",
          sessionToken,
          "; Path=/",
          "; HttpOnly",
          "; SameSite=Strict",
          `; Max-Age=${SESSION_DURATION_SECONDS}`
        ].join("")
      }
    );
  } catch (error) {
    return json(
      {
        ok: false,
        message: error instanceof Error
          ? error.message
          : "Error interno de autenticación."
      },
      500
    );
  }
}
