export async function onRequestGet(context) {
  try {
    const result = await context.env.DB
      .prepare(`
        SELECT
          COUNT(*) AS users,
          SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_users
        FROM users
      `)
      .first();

    return Response.json({
      ok: true,
      environment: "development",
      database: "connected",
      users: Number(result?.users || 0),
      activeUsers: Number(result?.active_users || 0)
    });
  } catch (error) {
    return Response.json(
      {
        ok: false,
        database: "error",
        message: error instanceof Error ? error.message : "Unknown error"
      },
      { status: 500 }
    );
  }
}