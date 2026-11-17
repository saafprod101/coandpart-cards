// manage-team: lets a portal admin issue and manage team logins.
// The portal admin sets each person's email + password; nobody can sign themselves up.
// Runs with the service role (server-side only). Every call checks that the caller is an admin in public.members.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const ALLOWED_ORIGINS = ["https://cards.saafprod.com", "https://saafprod101.github.io"];
const ROLES = ["admin", "editor", "viewer"];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function corsHeaders(origin: string) {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

Deno.serve(async (req: Request) => {
  const headers = corsHeaders(req.headers.get("origin") || "");
  if (req.method === "OPTIONS") return new Response("ok", { headers });
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { ...headers, "Content-Type": "application/json" } });

  try {
    const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    // who is calling?
    const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
    const { data: who, error: whoErr } = await admin.auth.getUser(token);
    if (whoErr || !who?.user?.email) return json({ error: "not_signed_in" }, 401);
    const me = who.user.email.toLowerCase();
    const { data: myRow } = await admin.from("members").select("role").eq("email", me).maybeSingle();
    if (myRow?.role !== "admin") return json({ error: "not_admin" }, 403);

    const body = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const role = String(body.role || "");

    const listUsers = async () => {
      const { data, error } = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 });
      if (error) throw error;
      return data.users;
    };
    const findUser = async (e: string) => (await listUsers()).find((u) => String(u.email || "").toLowerCase() === e);

    switch (body.action) {
      case "list": {
        const [{ data: members, error }, users] = await Promise.all([
          admin.from("members").select("email, role, created_at").order("created_at"),
          listUsers(),
        ]);
        if (error) throw error;
        const byEmail = new Map(users.map((u) => [String(u.email || "").toLowerCase(), u]));
        return json({
          me,
          members: (members || []).map((m) => ({
            email: m.email,
            role: m.role,
            hasAccount: byEmail.has(m.email),
            lastSignIn: byEmail.get(m.email)?.last_sign_in_at || null,
          })),
        });
      }

      case "create": {
        if (!EMAIL_RE.test(email)) return json({ error: "bad_email" }, 400);
        if (password.length < 8) return json({ error: "weak_password" }, 400);
        if (!ROLES.includes(role)) return json({ error: "bad_role" }, 400);
        const { data: existingMember } = await admin.from("members").select("email").eq("email", email).maybeSingle();
        if (existingMember) return json({ error: "exists" }, 409);
        const existingUser = await findUser(email);
        if (existingUser) {
          const { error } = await admin.auth.admin.updateUserById(existingUser.id, { password, email_confirm: true });
          if (error) throw error;
        } else {
          const { error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
          if (error) throw error;
        }
        const { error: insErr } = await admin.from("members").insert({ email, role });
        if (insErr) throw insErr;
        return json({ ok: true });
      }

      case "role": {
        if (!ROLES.includes(role)) return json({ error: "bad_role" }, 400);
        if (email === me && role !== "admin") return json({ error: "self_demote" }, 400);
        const { error } = await admin.from("members").update({ role }).eq("email", email);
        if (error) throw error;
        return json({ ok: true });
      }

      case "password": {
        if (password.length < 8) return json({ error: "weak_password" }, 400);
        const user = await findUser(email);
        if (!user) return json({ error: "no_account" }, 404);
        const { error } = await admin.auth.admin.updateUserById(user.id, { password });
        if (error) throw error;
        return json({ ok: true });
      }

      case "remove": {
        if (email === me) return json({ error: "self_remove" }, 400);
        const { error } = await admin.from("members").delete().eq("email", email);
        if (error) throw error;
        const user = await findUser(email);
        if (user) await admin.auth.admin.deleteUser(user.id);
        return json({ ok: true });
      }

      default:
        return json({ error: "bad_action" }, 400);
    }
  } catch (_e) {
    return json({ error: "server_error" }, 500);
  }
});
