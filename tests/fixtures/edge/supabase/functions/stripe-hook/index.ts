import Stripe from "npm:stripe@17";

const stripe = new Stripe(Deno.env.get("STRIPE_KEY")!);
Deno.serve(async (req) => {
  const signature = req.headers.get("stripe-signature")!;
  const event = await stripe.webhooks.constructEventAsync(await req.text(), signature, Deno.env.get("HOOK_SECRET")!);
  return new Response(event.type);
});
