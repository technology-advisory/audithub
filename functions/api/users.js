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


function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isAllowedRole(role) {
  return [
    "admin",
    "lead-auditor",
    "auditor",
    "client",
    "read-only"
  ].includes(role);
}

function validatePassword(password) {
  return (
    password.length >= 10 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password)
  );
}

async function createPasswordHash(password) {
  const iterations = 210000;
  const salt = crypto.getRandomValues(new Uint8Array(16));

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
      salt,
      iterations
    },
    keyMaterial,
    256
  );

  return [
    "pbkdf2-sha256",
    iterations,
    bytesToBase64(salt),
    bytesToBase64(new Uint8Array(derivedBits))
  ].join("$");
}

async function currentUser(context) {
  const sessionToken = getCookie(context.request, "a365_session");

  if (!sessionToken) {
    const accessEmail = normalizeEmail(context.request.headers.get("Cf-Access-Authenticated-User-Email"));
    if (!accessEmail) return null;
    return context.env.DB.prepare(`
      SELECT id, name, local_login, cloud_email, role, status
      FROM users WHERE LOWER(cloud_email) = ? AND status = 'active' LIMIT 1
    `).bind(accessEmail).first();
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
          all_clients AS allClients,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM users
        ORDER BY name COLLATE NOCASE, local_login COLLATE NOCASE
      `)
      .all();

    const users = result.results || [];
    const assignments = await context.env.DB
      .prepare(`SELECT user_id AS userId, client_id AS clientId FROM user_clients ORDER BY user_id, client_id`)
      .all();
    const byUser = new Map();
    for (const row of assignments.results || []) {
      if (!byUser.has(row.userId)) byUser.set(row.userId, []);
      byUser.get(row.userId).push(row.clientId);
    }
    for (const item of users) {
      item.clientIds = item.allClients ? ["*"] : (byUser.get(item.id) || []);
      delete item.allClients;
    }
    return json({ ok: true, users });
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

export async function onRequestPost(context) {
  try {
    const current = await currentUser(context);

    if (!current) {
      return json(
        { ok: false, message: "Sesión no válida." },
        401
      );
    }

    if (current.role !== "admin") {
      return json(
        { ok: false, message: "Acceso reservado al administrador." },
        403
      );
    }

    const contentType = context.request.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      return json(
        { ok: false, message: "El contenido debe enviarse como JSON." },
        415
      );
    }

    const body = await context.request.json();

    const name = String(body?.name || "").trim();
    const cloudEmail = normalizeEmail(body?.cloudEmail);
    const localLogin = normalizeEmail(body?.localLogin);
    const role = String(body?.role || "").trim();
    const password = String(body?.password || "");
    const clientIds = Array.isArray(body?.clientIds) ? [...new Set(body.clientIds.map(String).filter(Boolean))] : ["*"];
    const allClients = clientIds.length === 0 || clientIds.includes("*");

    if (!name || !cloudEmail || !localLogin || !role || !password) {
      return json(
        { ok: false, message: "Faltan campos obligatorios." },
        400
      );
    }

    if (!isAllowedRole(role)) {
      return json(
        { ok: false, message: "Rol no válido." },
        400
      );
    }

    if (!validatePassword(password)) {
      return json(
        {
          ok: false,
          message: "La contraseña debe tener al menos 10 caracteres, con mayúsculas, minúsculas y números."
        },
        400
      );
    }

    const duplicate = await context.env.DB
      .prepare(`
        SELECT
          CASE
            WHEN LOWER(local_login) = ? THEN 'local_login'
            WHEN LOWER(cloud_email) = ? THEN 'cloud_email'
          END AS duplicate_field
        FROM users
        WHERE LOWER(local_login) = ?
           OR LOWER(cloud_email) = ?
        LIMIT 1
      `)
      .bind(localLogin, cloudEmail, localLogin, cloudEmail)
      .first();

    if (duplicate?.duplicate_field === "local_login") {
      return json(
        { ok: false, message: "El login local ya está dado de alta." },
        409
      );
    }

    if (duplicate?.duplicate_field === "cloud_email") {
      return json(
        { ok: false, message: "El correo Cloudflare ya está dado de alta." },
        409
      );
    }

    const id = crypto.randomUUID();
    const passwordHash = await createPasswordHash(password);

    await context.env.DB
      .prepare(`
        INSERT INTO users (
          id,
          name,
          local_login,
          cloud_email,
          role,
          status,
          password_hash,
          all_clients
        )
        VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
      `)
      .bind(
        id,
        name,
        localLogin,
        cloudEmail,
        role,
        passwordHash,
        allClients ? 1 : 0
      )
      .run();

    if (!allClients && clientIds.length) {
      const statements = clientIds.map(clientId => context.env.DB
        .prepare(`INSERT OR IGNORE INTO user_clients (user_id, client_id) VALUES (?, ?)`)
        .bind(id, clientId));
      await context.env.DB.batch(statements);
    }

    return json(
      {
        ok: true,
        user: {
          id,
          name,
          localLogin,
          cloudEmail,
          role,
          status: "active",
          clientIds: allClients ? ["*"] : clientIds
        }
      },
      201
    );
  } catch (error) {
    return json(
      {
        ok: false,
        message: error instanceof Error
          ? error.message
          : "Error al crear el usuario."
      },
      500
    );
  }
}

export async function onRequestPut(context) {
  try {
    const current = await currentUser(context);

    if (!current) {
      return json(
        { ok: false, message: "Sesión no válida." },
        401
      );
    }

    if (current.role !== "admin") {
      return json(
        { ok: false, message: "Acceso reservado al administrador." },
        403
      );
    }

    const contentType = context.request.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      return json(
        { ok: false, message: "El contenido debe enviarse como JSON." },
        415
      );
    }

    const body = await context.request.json();

    const id = String(body?.id || "").trim();
    const name = String(body?.name || "").trim();
    const cloudEmail = normalizeEmail(body?.cloudEmail);
    const localLogin = normalizeEmail(body?.localLogin);
    const role = String(body?.role || "").trim();
    const status = String(body?.status || "").trim();
    const clientIds = Array.isArray(body?.clientIds) ? [...new Set(body.clientIds.map(String).filter(Boolean))] : ["*"];
    const allClients = clientIds.length === 0 || clientIds.includes("*");

    if (!id || !name || !cloudEmail || !localLogin || !role || !status) {
      return json(
        { ok: false, message: "Faltan campos obligatorios." },
        400
      );
    }

    if (!isAllowedRole(role)) {
      return json(
        { ok: false, message: "Rol no válido." },
        400
      );
    }

    if (!["active", "disabled"].includes(status)) {
      return json(
        { ok: false, message: "Estado no válido." },
        400
      );
    }

    const target = await context.env.DB
      .prepare(`
        SELECT id, role, status
        FROM users
        WHERE id = ?
        LIMIT 1
      `)
      .bind(id)
      .first();

    if (!target) {
      return json(
        { ok: false, message: "Usuario no encontrado." },
        404
      );
    }

    if (id === current.id && status === "disabled") {
      return json(
        { ok: false, message: "No puedes desactivar tu propia cuenta." },
        409
      );
    }

    const duplicate = await context.env.DB
      .prepare(`
        SELECT
          CASE
            WHEN LOWER(local_login) = ? THEN 'local_login'
            WHEN LOWER(cloud_email) = ? THEN 'cloud_email'
          END AS duplicate_field
        FROM users
        WHERE id <> ?
          AND (
            LOWER(local_login) = ?
            OR LOWER(cloud_email) = ?
          )
        LIMIT 1
      `)
      .bind(localLogin, cloudEmail, id, localLogin, cloudEmail)
      .first();

    if (duplicate?.duplicate_field === "local_login") {
      return json(
        { ok: false, message: "El login local ya está dado de alta." },
        409
      );
    }

    if (duplicate?.duplicate_field === "cloud_email") {
      return json(
        { ok: false, message: "El correo Cloudflare ya está dado de alta." },
        409
      );
    }

    await context.env.DB
      .prepare(`
        UPDATE users
        SET
          name = ?,
          local_login = ?,
          cloud_email = ?,
          role = ?,
          status = ?,
          all_clients = ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        name,
        localLogin,
        cloudEmail,
        role,
        status,
        allClients ? 1 : 0,
        id
      )
      .run();

    await context.env.DB.prepare(`DELETE FROM user_clients WHERE user_id = ?`).bind(id).run();
    if (!allClients && clientIds.length) {
      const statements = clientIds.map(clientId => context.env.DB
        .prepare(`INSERT OR IGNORE INTO user_clients (user_id, client_id) VALUES (?, ?)`)
        .bind(id, clientId));
      await context.env.DB.batch(statements);
    }

    if (status === "disabled") {
      await context.env.DB
        .prepare(`
          UPDATE sessions
          SET revoked_at = CURRENT_TIMESTAMP
          WHERE user_id = ?
            AND revoked_at IS NULL
        `)
        .bind(id)
        .run();
    }

    return json({
      ok: true,
      user: {
        id,
        name,
        localLogin,
        cloudEmail,
        role,
        status,
        clientIds: allClients ? ["*"] : clientIds
      }
    });
  } catch (error) {
    return json(
      {
        ok: false,
        message: error instanceof Error
          ? error.message
          : "Error al actualizar el usuario."
      },
      500
    );
  }
}
