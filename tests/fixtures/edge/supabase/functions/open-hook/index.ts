import { createClient } from "npm:@supabase/supabase-js@2";

// TODO: check supabase.auth.getUser() here
Deno.serve(async (req) => {
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const body = await req.json();
  await admin.from("orders").update({ paid: true }).eq("id", body.id);
  return new Response("ok");
});
