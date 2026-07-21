function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store"
    }
  });
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("cookie") || "";

  for (const part of cookieHeader.split(";")) {
    const [cookieName, ...valueParts] = part.trim().split("=");

    if (cookieName === name) {
      return valueParts.join("=");
    }
  }

  return null;
}

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

async function sha256Base64(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return bytesToBase64(new Uint8Array(digest));
}

export async function onRequestGet(context) {
  try {
    const sessionToken = getCookie(context.request, "a365_session");

    if (!sessionToken) {
      return json(
        { ok: false, authenticated: false },
        401
      );
    }

    const tokenHash = await sha256Base64(sessionToken);

    const session = await context.env.DB
      .prepare(`
        SELECT
          sessions.id AS session_id,
          sessions.expires_at,
          users.id,
          users.name,
          users.local_login,
          users.role,
          users.status
        FROM sessions
        INNER JOIN users
          ON users.id = sessions.user_id
        WHERE sessions.token_hash = ?
          AND sessions.revoked_at IS NULL
          AND sessions.expires_at > ?
          AND users.status = 'active'
        LIMIT 1
      `)
      .bind(tokenHash, new Date().toISOString())
      .first();

    if (!session) {
      return json(
        { ok: false, authenticated: false },
        401
      );
    }

    await context.env.DB
      .prepare(`
        UPDATE sessions
        SET last_seen_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(session.session_id)
      .run();

    return json({
      ok: true,
      authenticated: true,
      user: {
        id: session.id,
        name: session.name,
        login: session.local_login,
        role: session.role
      }
    });
  } catch (error) {
    return json(
      {
        ok: false,
        authenticated: false,
        message: error instanceof Error
          ? error.message
          : "Error interno de autenticación."
      },
      500
    );
  }
}