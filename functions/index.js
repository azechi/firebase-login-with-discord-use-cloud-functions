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
const session = new Session(hmac);

const noop = () => {};

class SessionInvalidSignatureError extends Error {
  constructor(msg) {
    super(msg);
    this.name = msg;
  }
}

class SessionExpiredError extends Error {
  constructor(msg) {
    super(msg);
    this.name = msg;
  }
}

function Session(hmac) {
  let hmac = hmac;

  const separator = ".";

  this.signAndStringify = function (value, expires) {
    const exp = String(expires.getTime());

    const str =
      typeof value == "string"
        ? value
        : encodeURIComponent(JSON.stringify(value));

    const data = exp + separator + str;

    return hmac.sign(data) + separator + data;
  };

  this.parseAndVerify = function (string, now) {
    now = String(now.getTime());

    const { sign, data } = splitN(string, separator, 2);

    if (!hmac.verify(sign, data)) {
      return new SessionInvalidSignatureError();
    }

    const { exp, value } = splitN(data, separator, 2);

    if (new Date(exp) <= now) {
      return new SessionExpiredError();
    }

    return JSON.parse(decodeURIComponent(value));
  };
}

function splitN(s, sep, c) {
  const acm = [];
  let i = 0;
  let j;
  while (--c) {
    j = s.indexOf(sep, i);
    if (j === -1) {
      break;
    }
    acm.push(s.substring(i, j));
    i = j + sep.length;
  }
  acm.push(s.substring(i));
  return acm;
}

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
    session.signAndStringify(state, new Date(Date.now() + 10 * 60 * 1000)),
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

  const sessionCookieValue = cookie.parse(
    req.headers.cookie["__session"] || ""
  );

  const state = session.parseAndVerify(sessionCookieValue, new Date());
  if (state instanceof Error) {
    res.sendStatus(400);
    return;
  }

  if (req.body.state !== state) {
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
