import { createClient } from "npm:@supabase/supabase-js@2";
import { corsHeaders, requireUser as mustBeSignedIn } from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const user = await mustBeSignedIn(req);
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const { data } = await admin.from("profiles").select("role").eq("id", user.id);
  return new Response(JSON.stringify(data), { headers: corsHeaders });
});
