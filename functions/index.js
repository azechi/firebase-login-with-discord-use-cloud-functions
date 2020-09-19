const functions = require("firebase-functions");
const admin = require("firebase-admin");

const crypto = require("crypto");
const cookie = require("cookie");

const compare = require("tsscmp");

const qs = require("qs");
const url = require("url");

const config = functions.config();

admin.initializeApp();

exports.login = functions.https.onRequest((req, res) => {
  if (req.method != "GET") {
    res.sendStatus(400);
    return;
  }

  if (!req.query.code_challenge) {
    res.sendStatus(400);
    return;
  }

  const isLocalhost =
    req.headers["x-forwarded-host"].split(":")[0] == "localhost";

  const state = crypto
    .randomBytes(24)
    .toString("base64")
    .replace(/\/|\+|=/g, (x) => ({ "/": "_", "+": "-", "=": "" }[x]));

  const cookieValue = {
    state,
    expires: Date.now() + 10 * 60 * 1000,
  };

  // __session=signedValue+value+expires;
  //   Path=/token; Secure; HttpOnly; SameSite=Strict
  res.cookie(
    "__session",
    qs.stringify({
      sign: sign(qs.stringify(cookieValue)),
      value: cookieValue,
    }),
    {
      path: "/token",
      secure: !isLocalhost,
      httpOnly: true,
      sameSite: "Strict",
    }
  );

  //const redirect_uri = new url.URL("/", `https://${req.headers["x-forwarded-host"]}`);
  const redirect_uri = new url.URL(
    "/",
    `http${isLocalhost ? "" : "s"}://${req.headers["x-forwarded-host"]}`
  );
  res.redirect(
    302,
    buildAuthorizeRequest(
      state,
      redirect_uri.toString(),
      req.query.code_challenge
    )
  );
});

function buildAuthorizeRequest(state, redirect_uri, code_challenge) {
  const baseUrl = "https://discord.com/api/oauth2/authorize";
  const p = {
    client_id: config.discord.azechify.client_id,
    response_type: "code",
    scope: "identify",
    prompt: "none",

    state: state,
    redirect_uri: redirect_uri,
    code_challenge: code_challenge,
  };
  return `${baseUrl}?${qs.stringify(p)}`;
}

exports.token = functions.https.onRequest((req, res) => {
  if (req.method != "POST") {
    res.sendStatus(400);
    return;
  }

  if (!(req.body.code && req.body.state && req.body.code_verifier)) {
    res.sendStatus(400);
    return;
  }

  const cookies = cookie.parse(req.headers.cookie || "");
  if (!cookies.__session) {
    res.sendStatus(400);
    return;
  }

  const { sign: s, value: session } = qs.parse(cookies.__session);
  if (!compare(s, sign(qs.stringify(session)))) {
    res.sendStatus(400);
    return;
  }

  // debug 1日
  const _d = 1000 * 60 * 60 * 24 * 1;
  if (+session.expires + _d <= Date.now()) {
    res.sendStatus(400);
    return;
  }

  if (req.body.state !== session.state) {
    res.sendStatus(400);
    return;
  }

  // __session cookie
  // destroy __session cookie

  // checks session expired
  // verify state parameter

  // post token requiest
  // {
  //    client_id: config.discord.azechify.client_id,
  //    client_secret: config.discord.azechify.client_secret,
  //    redirect_uri,
  //    grant_type:"authorization_code"
  //    scope:"identify"
  //
  //    code_verifier: code_verifier,
  //    code: code
  // }

  // gets user id with access token from the discord profile api
  // stores refresh_token with uid key

  // response json object {firebase customToken}

  res.status(200).json({ status: "OK" });
});

/**
 * Hmac sha256 digest base64url
 * @param {string | Buffer | TypedArray | DataView} data
 * @return {string} - Base64url encoded string
 */
function sign(data) {
  return crypto
    .createHmac("sha256", Buffer.from(config.keys[0], "base64"))
    .update(data) // string | Buffer | TypedArray | DataView
    .digest("base64")
    .replace(/\/|\+|=/g, (x) => ({ "/": "_", "+": "-", "=": "" }[x]));
}
