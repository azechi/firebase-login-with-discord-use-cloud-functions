
import "./init.js";

import { getAuth, connectAuthEmulator, signInWithCustomToken, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/9.8.2/firebase-auth.js";

const auth = getAuth();
connectAuthEmulator(auth, "http://127.0.0.1:9099");

const STORAGE_KEY = "code_verifier";
const storage = window.sessionStorage;

const url = new URL(window.location);
if (
  ["code", "state"].every(Array.prototype.includes, [
    ...url.searchParams.keys(),
  ])
) {
  handleRedirectCallback();
  url.searchParams.delete("code");
  url.searchParams.delete("state");
  window.history.replaceState({}, document.title, url.href);
}
function handleRedirectCallback() {
  console.log(
    "handleRedirectCallback",
    "code:",
    url.searchParams.get("code"),
    "state:",
    url.searchParams.get("state")
  );

  fetch("/token", {
    method: "POST",
    credentials: "same-origin",
    body: new URLSearchParams({
      code_verifier: storage.getItem(STORAGE_KEY),
      code: url.searchParams.get("code"),
      state: url.searchParams.get("state"),
    }),
  })
    .then((res) => res.text())
    .then((token) => {
      signInWithCustomToken(auth,token).then(console.log);
    });

  console.log("post token endpoint");
}

onAuthStateChanged(auth, (user) => {
  if (!user) {
    //loginWithRedirect();
    console.log("singed out");
    return;
  }

  console.log(user);
});

const loaded = new Promise(result => {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', result, {once: true})
  } else {
    result();
  }
});

await loaded;
const button = document.getElementById("login");
button.disabled = false;

button.addEventListener("click", async () => {
  console.log("click");
  // screen lock on

  await loginWithRedirect();
});

async function loginWithRedirect() {
  const code_verifier = btoa(
    String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))
  ).replace(/\/|\+|=/g, (x) => ({ "/": "_", "+": "-", "=": "" }[x]));

  storage.setItem(STORAGE_KEY, code_verifier);

  const hash = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array([...code_verifier].map((e) => e.charCodeAt(0)))
  );
  const code_challenge = btoa(
    String.fromCharCode(...new Uint8Array(hash))
  ).replace(/\/|\+|=/g, (x) => ({ "/": "_", "+": "-", "=": "" }[x]));

  const p = {
    code_challenge: code_challenge,
    code_challenge_method: "sha256",
  };

  self.location.assign("/login?" + new URLSearchParams(p).toString());
}
