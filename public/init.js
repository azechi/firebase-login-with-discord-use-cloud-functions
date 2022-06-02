import { initializeApp } from "https://www.gstatic.com/firebasejs/9.8.2/firebase-app.js";

globalThis.firebase = { initializeApp };

// create [default] app instance.
await import("./__/firebase/init.js");
