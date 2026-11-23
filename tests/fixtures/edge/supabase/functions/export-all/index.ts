import { createClient } from "npm:@supabase/supabase-js@2";
import { corsHeaders } from "../_shared/helpers.ts";

// requireUser() lives in the same helper file, but this function never calls it.
Deno.serve(async () => {
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const { data } = await admin.from("profiles").select("*");
  return new Response(JSON.stringify(data), { headers: corsHeaders });
});
