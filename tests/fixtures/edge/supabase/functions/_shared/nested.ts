import { createClient } from "npm:@supabase/supabase-js@2";

async function userFromRequest(req: Request) {
  const client = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: req.headers.get("Authorization")! } },
  });
  const { data: { user } } = await client.auth.getUser();
  return user;
}

export async function requireSignedIn(req: Request) {
  const user = await userFromRequest(req);
  if (!user) throw new Error("not signed in");
  return user;
}

export function verify(schema: unknown, value: unknown) {
  return schema !== undefined && value !== undefined;
}
