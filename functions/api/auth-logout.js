function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...headers
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

export async function onRequestPost(context) {
  try {
    const sessionToken = getCookie(context.request, "a365_session");

    if (sessionToken) {
      const tokenHash = await sha256Base64(sessionToken);

      await context.env.DB
        .prepare(`
          UPDATE sessions
          SET revoked_at = CURRENT_TIMESTAMP
          WHERE token_hash = ?
            AND revoked_at IS NULL
        `)
        .bind(tokenHash)
        .run();
    }

    return json(
      { ok: true },
      200,
      {
        "Set-Cookie": [
          "a365_session=",
          "; Path=/",
          "; HttpOnly",
          "; SameSite=Strict",
          "; Max-Age=0"
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