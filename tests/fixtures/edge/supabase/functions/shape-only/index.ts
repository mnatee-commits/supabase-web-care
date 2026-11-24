import { createClient } from "npm:@supabase/supabase-js@2";
import { verify } from "../_shared/nested.ts";

// verify() here checks the shape of the body, not who is calling.
Deno.serve(async (req) => {
  const body = await req.json();
  if (!verify({}, body)) return new Response("bad", { status: 400 });
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const { data } = await admin.from("profiles").select("*");
  return new Response(JSON.stringify(data));
});
