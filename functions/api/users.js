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

async function currentUser(context) {
  const sessionToken = getCookie(context.request, "a365_session");

  if (!sessionToken) {
    return null;
  }

  const tokenHash = await sha256Base64(sessionToken);

  return context.env.DB
    .prepare(`
      SELECT
        users.id,
        users.name,
        users.local_login,
        users.cloud_email,
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
}

export async function onRequestGet(context) {
  try {
    const user = await currentUser(context);

    if (!user) {
      return json(
        { ok: false, message: "Sesión no válida." },
        401
      );
    }

    if (user.role !== "admin") {
      return json(
        { ok: false, message: "Acceso reservado al administrador." },
        403
      );
    }

    const result = await context.env.DB
      .prepare(`
        SELECT
          id,
          name,
          local_login AS localLogin,
          cloud_email AS cloudEmail,
          role,
          status,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM users
        ORDER BY name COLLATE NOCASE, local_login COLLATE NOCASE
      `)
      .all();

    return json({
      ok: true,
      users: result.results || []
    });
  } catch (error) {
    return json(
      {
        ok: false,
        message: error instanceof Error
          ? error.message
          : "Error al consultar usuarios."
      },
      500
    );
  }
}