// setup-admin: one-time creation of the portal's first admin.
// Works only while no admin exists, only for the email that has a setup code, and only with that code.
// The admin picks their own password here; the code is single-use and deleted afterwards.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const ALLOWED_ORIGINS = ["https://cards.saafprod.com", "https://saafprod101.github.io"];

function corsHeaders(origin: string) {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

async function sha256(text: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req: Request) => {
  const headers = corsHeaders(req.headers.get("origin") || "");
  if (req.method === "OPTIONS") return new Response("ok", { headers });
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { ...headers, "Content-Type": "application/json" } });

  try {
    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
      auth: { persistSession: false, autoRefreshToken: false },
      db: { schema: "public" },
    });
    const { count } = await db.from("members").select("email", { count: "exact", head: true }).eq("role", "admin");
    const needsSetup = (count || 0) === 0;

    const body = await req.json().catch(() => ({}));
    if (body.action === "status") return json({ needsSetup });
    if (body.action !== "setup") return json({ error: "bad_action" }, 400);
    if (!needsSetup) return json({ error: "already_set_up" }, 409);

    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim().toUpperCase();
    const password = String(body.password || "");
    if (password.length < 8) return json({ error: "weak_password" }, 400);

    const { data: ok } = await db.rpc("setup_code_matches", { p_email: email, p_hash: await sha256(code) });
    if (ok !== true) return json({ error: "bad_code" }, 403);

    const { error: mErr } = await db.from("members").upsert({ email, role: "admin" });
    if (mErr) throw mErr;
    const { data: list } = await db.auth.admin.listUsers({ page: 1, perPage: 1000 });
    const existing = list?.users.find((u) => String(u.email || "").toLowerCase() === email);
    const res = existing
      ? await db.auth.admin.updateUserById(existing.id, { password, email_confirm: true })
      : await db.auth.admin.createUser({ email, password, email_confirm: true });
    if (res.error) {
      await db.from("members").delete().eq("email", email);
      throw res.error;
    }
    await db.rpc("setup_code_consume", { p_email: email });
    return json({ ok: true });
  } catch (_e) {
    return json({ error: "server_error" }, 500);
  }
});
