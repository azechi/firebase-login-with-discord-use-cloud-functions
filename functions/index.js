const functions = require("firebase-functions");
const admin = require("firebase-admin");

const qs = require("qs");
const url = require("url");

const config = functions.config();

const https = require("https");
const agent = new https.Agent({ keepAlive: true });
const fetch = require("node-fetch");

const cookie = require("cookie");

admin.initializeApp();

const { randomString, Hmac } = require("./crypto");
const hmac = new Hmac("sha256", Buffer.from(config.keys[0], "base64"));

const noop = () => {};

exports.login = functions.https.onRequest(async (req, res) => {
  if (req.method != "GET") {
    res.sendStatus(400);
    return;
  }

  if (!req.query.code_challenge) {
    res.sendStatus(400);
    return;
  }

  fromLocalhost(req, null, noop);
  serverUrlRoot(req, res, noop);

  const state = randomString(24);
  res.cookie(
    "__session",
    qs.stringify(
      hmac.sign({
        value: state,
        expires: Date.now() + 10 * 60 * 1000,
      })
    ),
    getCookieOption(!req.fromLocalhost)
  );

  res.redirect(
    302,
    "https://discord.com/api/oauth2/authorize?" +
      qs.stringify({
        client_id: config.discord.azechify.client_id,
        response_type: "code",
        scope: "identify",
        prompt: "none",
        state: state,
        redirect_uri: req.serverUrlRoot.href,
        code_challenge: req.query.code_challenge,
      })
  );
});

exports.token = functions.https.onRequest(async (req, res) => {
  if (req.method != "POST") {
    res.sendStatus(400);
    return;
  }

  if (!(req.body.code && req.body.state && req.body.code_verifier)) {
    res.sendStatus(400);
    return;
  }

  const signedSession = qs.parse(
    cookie.parse(req.headers.cookie)["__session"] || ""
  );
  if (!verifySession(signedSession, new Date())) {
    res.sendStatus(400);
    return;
  }

  const session = signedSession.value;
  if (req.body.state !== session.value) {
    res.sendStatus(400);
    return;
  }

  fromLocalhost(req, null, noop);
  serverUrlRoot(req, res, noop);

  const tokens = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    agent: agent,
    body: new url.URLSearchParams({
      client_id: config.discord.azechify.client_id,
      //client_secret: config.discord.azechify.client_secret,
      redirect_uri: req.serverUrlRoot.href,
      grant_type: "authorization_code",
      scope: "identify",
      code_verifier: req.body.code_verifier,
      code: req.body.code,
    }),
  }).then((res) => res.json());

  const user = await fetch("https://discord.com/api/users/@me", {
    agent: agent,
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  }).then((res) => res.json());

  const uid = `discord:${user.id}`;
  await createOrUpdateUser(
    uid,
    `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.jpeg`,
    user.username
  );

  const customToken = await admin.auth().createCustomToken(uid);
  res.status(200).send(customToken);
});

async function createOrUpdateUser(uid, photoURL, displayName) {
  try {
    const userRecord = await admin.auth().getUser(uid);
    await admin.auth().updateUser(uid, {
      photoURL,
      displayName,
    });
  } catch (e) {
    if (e.code != "auth/user-not-found") {
      throw e;
    }
    await admin.auth().createUser({
      uid: uid,
      photoURL,
      displayName,
    });
  }
}

function getCookieOption(secure) {
  return {
    path: "/token",
    secure: secure,
    httpOnly: true,
    sameSite: "Strict",
  };
}

function fromLocalhost(req, res, next) {
  req.fromLocalhost =
    req.headers["x-forwarded-host"].split(":")[0].toLowerCase() === "localhost";
  next();
}

function serverUrlRoot(req, res, next) {
  req.serverUrlRoot = new url.URL(
    "/",
    (req.fromLocalhost ? "http" : "https") +
      "://" +
      req.headers["x-forwarded-host"]
  );
  next();
}

function verifySession(session, now) {
  if (!hmac.verify(session)) {
    return false;
  }

  if (+session.expires <= now.getTime()) {
    return false;
  }

  return true;
}
