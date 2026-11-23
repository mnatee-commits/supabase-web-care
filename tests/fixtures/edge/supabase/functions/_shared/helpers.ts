import { createClient } from "npm:@supabase/supabase-js@2";

export const corsHeaders = { "Access-Control-Allow-Origin": "https://example.com" };

export async function requireUser(req: Request) {
  const client = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: req.headers.get("Authorization")! } },
  });
  const { data: { user } } = await client.auth.getUser();
  if (!user) throw new Error("not signed in");
  return user;
}
