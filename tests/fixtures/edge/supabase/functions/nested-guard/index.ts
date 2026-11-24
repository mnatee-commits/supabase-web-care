import { createClient } from "npm:@supabase/supabase-js@2";
import { requireSignedIn } from "../_shared/nested.ts";

Deno.serve(async (req) => {
  const user = await requireSignedIn(req);
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const { data } = await admin.from("profiles").select("role").eq("id", user.id);
  return new Response(JSON.stringify(data));
});
