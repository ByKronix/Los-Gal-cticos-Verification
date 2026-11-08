const crypto = require("crypto");

function readCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";
  const cookies = cookieHeader.split(";").map((part) => part.trim());
  const entry = cookies.find((part) => part.startsWith(`${name}=`));
  return entry ? decodeURIComponent(entry.slice(name.length + 1)) : "";
}

function safeEqual(a, b) {
  const left = Buffer.from(a || "", "utf8");
  const right = Buffer.from(b || "", "utf8");
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function goHome(res, status) {
  return res.redirect(302, `/?status=${encodeURIComponent(status)}`);
}

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method Not Allowed");
  }

  const stateSecret = process.env.STATE_SECRET;
  const cookieValue = readCookie(req, "oauth_state");
  res.setHeader(
    "Set-Cookie",
    "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=0"
  );

  if (req.query.error) {
    return goHome(res, "cancelled");
  }

  const code = req.query.code;
  const returnedState = req.query.state;
  if (!stateSecret || !code || !returnedState || !cookieValue) {
    return goHome(res, "oauth_error");
  }

  const [cookieState, cookieSignature] = cookieValue.split(".");
  const expectedSignature = crypto
    .createHmac("sha256", stateSecret)
    .update(cookieState || "")
    .digest("hex");

  if (
    !cookieState ||
    !cookieSignature ||
    !safeEqual(returnedState, cookieState) ||
    !safeEqual(cookieSignature, expectedSignature)
  ) {
    return goHome(res, "oauth_error");
  }

  const clientId = process.env.DISCORD_CLIENT_ID;
  const clientSecret = process.env.DISCORD_CLIENT_SECRET;
  const redirectUri = process.env.DISCORD_REDIRECT_URI;
  const botToken = process.env.DISCORD_BOT_TOKEN;
  const guildId = process.env.DISCORD_GUILD_ID;
  const verifiedRoleId = process.env.DISCORD_ROLE_VERIFIED_ID;
  const unverifiedRoleId = process.env.DISCORD_ROLE_UNVERIFIED_ID;

  if (
    !clientId || !clientSecret || !redirectUri || !botToken ||
    !guildId || !verifiedRoleId || !unverifiedRoleId
  ) {
    return goHome(res, "server_error");
  }

  if (verifiedRoleId === unverifiedRoleId) {
    return goHome(res, "server_error");
  }

  try {
    const tokenResponse = await fetch("https://discord.com/api/v10/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri
      })
    });

    if (!tokenResponse.ok) {
      return goHome(res, "oauth_error");
    }

    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) {
      return goHome(res, "oauth_error");
    }

    const userResponse = await fetch("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    if (!userResponse.ok) {
      return goHome(res, "oauth_error");
    }

    const user = await userResponse.json();

    const memberResponse = await fetch(
      `https://discord.com/api/v10/guilds/${encodeURIComponent(guildId)}/members/${encodeURIComponent(user.id)}`,
      { headers: { Authorization: `Bot ${botToken}` } }
    );

    if (memberResponse.status === 404) {
      return goHome(res, "not_member");
    }
    if (!memberResponse.ok) {
      return goHome(res, "server_error");
    }

    const addRoleResponse = await fetch(
      `https://discord.com/api/v10/guilds/${encodeURIComponent(guildId)}/members/${encodeURIComponent(user.id)}/roles/${encodeURIComponent(verifiedRoleId)}`,
      { method: "PUT", headers: { Authorization: `Bot ${botToken}` } }
    );

    if (!addRoleResponse.ok) {
      return goHome(res, "server_error");
    }

    const removeRoleResponse = await fetch(
      `https://discord.com/api/v10/guilds/${encodeURIComponent(guildId)}/members/${encodeURIComponent(user.id)}/roles/${encodeURIComponent(unverifiedRoleId)}`,
      { method: "DELETE", headers: { Authorization: `Bot ${botToken}` } }
    );

    if (!removeRoleResponse.ok) {
      return goHome(res, "server_error");
    }

    return goHome(res, "verified");
  } catch (_error) {
    return goHome(res, "server_error");
  }
};
