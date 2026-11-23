import { createClient } from "npm:@supabase/supabase-js@2";
import { corsHeaders } from "../_shared/cors.ts";

Deno.serve(async (req) => {
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const { user_id } = await req.json();
  const { data } = await admin.from("profiles").select("*").eq("id", user_id);
  return new Response(JSON.stringify(data), { headers: corsHeaders });
});
