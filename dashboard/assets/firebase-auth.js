// dashboard/assets/firebase-auth.js
// Firebase email/password auth — writes token directly to dcc.Store via
// dash_clientside.set_props (no relay input; that hop was the bug).
import { initializeApp } from "https://www.gstatic.com/firebasejs/12.13.0/firebase-app.js";
import {
  getAuth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  setPersistence,
  browserSessionPersistence,
} from "https://www.gstatic.com/firebasejs/12.13.0/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyCYuwpkNOHR50HGVvtRpW7G4t3Ulc8xYvY",
  authDomain: "astra-cyber.firebaseapp.com",
  projectId: "astra-cyber",
  storageBucket: "astra-cyber.firebasestorage.app",
  messagingSenderId: "790303580957",
  appId: "1:790303580957:web:8eaccc58e68d49dc9977f4",
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

setPersistence(auth, browserSessionPersistence).catch((e) =>
  console.error("[astra-auth] setPersistence failed:", e)
);

function setToken(token) {
  try {
    if (window.dash_clientside && typeof window.dash_clientside.set_props === "function") {
      window.dash_clientside.set_props("auth-token", { data: token || null });
    } else {
      console.warn("[astra-auth] dash_clientside not ready, retrying...");
      setTimeout(function () { setToken(token); }, 120);
    }
  } catch (e) {
    console.error("[astra-auth] setToken failed:", e);
  }
}

function showError(msg) {
  var el = document.getElementById("auth-error");
  if (el) el.textContent = msg || "";
}

function friendly(code, fallback) {
  switch (code) {
    case "auth/invalid-email": return "That email address is invalid.";
    case "auth/missing-password": return "Enter a password.";
    case "auth/weak-password": return "Password is too weak - use at least 6 characters.";
    case "auth/email-already-in-use": return "An account with that email already exists. Try signing in.";
    case "auth/invalid-credential":
    case "auth/wrong-password":
    case "auth/user-not-found": return "Incorrect email or password.";
    case "auth/too-many-requests": return "Too many attempts. Wait a moment and try again.";
    case "auth/network-request-failed": return "Network error reaching Firebase. Check your connection.";
    default: return fallback || "Authentication failed. Please try again.";
  }
}

onAuthStateChanged(auth, async (user) => {
  if (user) {
    try { setToken(await user.getIdToken(false)); }
    catch (e) { console.error("[astra-auth] getIdToken failed:", e); setToken(""); }
  } else {
    setToken("");
  }
});

async function doSignIn() {
  showError("");
  var email = (document.getElementById("login-email") || {}).value || "";
  var password = (document.getElementById("login-password") || {}).value || "";
  if (!email || !password) { showError("Enter both email and password."); return; }
  try {
    var cred = await signInWithEmailAndPassword(auth, email, password);
    setToken(await cred.user.getIdToken(false));
  } catch (e) {
    showError(friendly(e && e.code, "Sign-in failed."));
    console.error("[astra-auth] signIn:", e && e.code, e);
  }
}

async function doSignUp() {
  showError("");
  var email = (document.getElementById("signup-email") || {}).value || "";
  var password = (document.getElementById("signup-password") || {}).value || "";
  if (!email || !password) { showError("Enter an email and a password."); return; }
  if (password.length < 6) { showError("Password must be at least 6 characters."); return; }
  try {
    var cred = await createUserWithEmailAndPassword(auth, email, password);
    setToken(await cred.user.getIdToken(false));
  } catch (e) {
    showError(friendly(e && e.code, "Could not create account."));
    console.error("[astra-auth] signUp:", e && e.code, e);
  }
}

document.addEventListener("click", async (ev) => {
  if (ev.target.closest("#login-submit")) { ev.preventDefault(); await doSignIn(); return; }
  if (ev.target.closest("#signup-submit")) { ev.preventDefault(); await doSignUp(); return; }
  if (ev.target.closest("#logout-btn")) {
    ev.preventDefault();
    try { await signOut(auth); } catch (e) { console.error("[astra-auth] signOut:", e); }
    setToken("");
    return;
  }
  var tab = ev.target.closest(".auth-tab");
  if (tab) {
    ev.preventDefault();
    var mode = tab.getAttribute("data-mode");
    document.querySelectorAll(".auth-tab").forEach(function (t) {
      t.classList.toggle("is-active", t.getAttribute("data-mode") === mode);
    });
    var si = document.getElementById("auth-panel-signin");
    var su = document.getElementById("auth-panel-signup");
    if (si) si.style.display = mode === "signin" ? "" : "none";
    if (su) su.style.display = mode === "signup" ? "" : "none";
    showError("");
  }
});

document.addEventListener("keydown", (ev) => {
  if (ev.key !== "Enter") return;
  if (ev.target.closest("#auth-panel-signin")) { ev.preventDefault(); doSignIn(); }
  else if (ev.target.closest("#auth-panel-signup")) { ev.preventDefault(); doSignUp(); }
});
