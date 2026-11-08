const crypto = require("crypto");

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method Not Allowed");
  }

  const clientId = process.env.DISCORD_CLIENT_ID;
  const redirectUri = process.env.DISCORD_REDIRECT_URI;
  const stateSecret = process.env.STATE_SECRET;

  if (!clientId || !redirectUri || !stateSecret) {
    return res.status(500).send("Falta configurar una variable de entorno en Vercel.");
  }

  const state = crypto.randomBytes(32).toString("hex");
  const signature = crypto
    .createHmac("sha256", stateSecret)
    .update(state)
    .digest("hex");

  res.setHeader(
    "Set-Cookie",
    `oauth_state=${state}.${signature}; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=600`
  );

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: redirectUri,
    scope: "identify",
    state
  });

  return res.redirect(302, `https://discord.com/oauth2/authorize?${params.toString()}`);
};
