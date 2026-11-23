import { createClient } from "npm:@supabase/supabase-js@2";

Deno.serve(async (req) => {
  const client = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: req.headers.get("Authorization")! } },
  });
  const { data: { user } } = await client.auth.getUser();
  if (!user) return new Response("no", { status: 401 });
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const { data } = await admin.from("profiles").select("role").eq("id", user.id);
  return new Response(JSON.stringify(data), { headers: { "Access-Control-Allow-Origin": "https://example.com" } });
});
