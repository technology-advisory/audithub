function json(data, status = 200) {
  return Response.json(data, { status, headers: { "Cache-Control": "no-store" } });
}
function getCookie(request, name) {
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return value.join("=");
  }
  return null;
}
function bytesToBase64(bytes) { let value = ""; for (const byte of bytes) value += String.fromCharCode(byte); return btoa(value); }
async function sha256Base64(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64(new Uint8Array(digest));
}
async function currentUser(context) {
  const token = getCookie(context.request, "a365_session");
  if (!token) {
    const email = String(context.request.headers.get("Cf-Access-Authenticated-User-Email") || "").trim().toLowerCase();
    if (!email) return null;
    return context.env.DB.prepare(`SELECT id,name,local_login,cloud_email,role,status,phone,title,photo FROM users WHERE LOWER(cloud_email)=? AND status='active' LIMIT 1`).bind(email).first();
  }
  return context.env.DB.prepare(`
    SELECT users.id, users.name, users.local_login, users.cloud_email, users.role,
           users.status, users.phone, users.title, users.photo
    FROM sessions INNER JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.revoked_at IS NULL
      AND sessions.expires_at > ? AND users.status = 'active' LIMIT 1
  `).bind(await sha256Base64(token), new Date().toISOString()).first();
}
export async function onRequestGet(context) {
  try {
    const user = await currentUser(context);
    if (!user) return json({ ok:false, message:"Sesión no válida." }, 401);
    return json({ ok:true, user:{ id:user.id, name:user.name, localLogin:user.local_login,
      cloudEmail:user.cloud_email || "", role:user.role, status:user.status,
      phone:user.phone || "", title:user.title || "", photo:user.photo || "" } });
  } catch (error) { return json({ ok:false, message:error?.message || "Error al consultar el perfil." }, 500); }
}
export async function onRequestPut(context) {
  try {
    const user = await currentUser(context);
    if (!user) return json({ ok:false, message:"Sesión no válida." }, 401);
    const body = await context.request.json();
    const name = String(body?.name || "").trim();
    const phone = String(body?.phone || "").trim().slice(0,100);
    const title = String(body?.title || "").trim().slice(0,150);
    const photo = String(body?.photo || "");
    if (!name) return json({ ok:false, message:"El nombre es obligatorio." }, 400);
    if (photo.length > 1500000) return json({ ok:false, message:"La fotografía es demasiado grande." }, 413);
    await context.env.DB.prepare(`UPDATE users SET name=?, phone=?, title=?, photo=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`)
      .bind(name, phone, title, photo, user.id).run();
    return json({ ok:true, user:{ id:user.id, name, phone, title, photo } });
  } catch (error) { return json({ ok:false, message:error?.message || "Error al actualizar el perfil." }, 500); }
}
