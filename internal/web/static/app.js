"use strict";

const b64u = {
  decode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(s + "===".slice((s.length + 3) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  },
  encode(buf) {
    const bin = String.fromCharCode(...new Uint8Array(buf));
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

const status = (msg) => { document.getElementById("status").textContent = msg; };

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { status: res.status });
  return data;
}

// takeFragment returns what the link carries after "#" and drops it from the address bar and
// history at once. Token links keep their secret there because browsers never send the fragment:
// not with the page request, not in a Referer, so no proxy log records it.
function takeFragment() {
  const frag = location.hash.slice(1);
  if (frag) history.replaceState(null, "", location.pathname);
  return frag;
}

function decodeFragment(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return "";
  }
}

// showInvalid replaces the page with the invalid-link message the server rendered into it, the
// page the server itself answers a dead link with.
function showInvalid(tpl) {
  document.querySelector("main").replaceChildren(tpl.content.cloneNode(true));
  document.title = tpl.dataset.title;
}

function creationOptions(o) {
  const pk = o.publicKey;
  pk.challenge = b64u.decode(pk.challenge);
  pk.user.id = b64u.decode(pk.user.id);
  (pk.excludeCredentials || []).forEach((c) => { c.id = b64u.decode(c.id); });
  return { publicKey: pk };
}

function requestOptions(o) {
  const pk = o.publicKey;
  pk.challenge = b64u.decode(pk.challenge);
  (pk.allowCredentials || []).forEach((c) => { c.id = b64u.decode(c.id); });
  return { publicKey: pk };
}

function attestationJSON(cred) {
  return {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: b64u.encode(cred.response.clientDataJSON),
      attestationObject: b64u.encode(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
  };
}

function assertionJSON(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: b64u.encode(r.clientDataJSON),
      authenticatorData: b64u.encode(r.authenticatorData),
      signature: b64u.encode(r.signature),
      userHandle: r.userHandle ? b64u.encode(r.userHandle) : null,
    },
  };
}

const enrollForm = document.getElementById("enroll");
// Only the /token page carries the invalid-link message: its code comes from the fragment.
const invalidLink = document.getElementById("invalid");
const enrollCode = invalidLink ? decodeFragment(takeFragment()) : "";
if (invalidLink && !enrollCode) {
  showInvalid(invalidLink);
} else if (enrollForm) {
  enrollForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = enrollForm.querySelector("button");
    button.disabled = true;
    try {
      status("Creating passkey…");
      const name = enrollForm.elements.name.value;
      // /enroll routes carry the proxy's identity; /token routes carry the enrollment code.
      const base = enrollForm.dataset.base;
      let begin;
      try {
        begin = await postJSON(base + "/begin", { name, code: enrollCode });
      } catch (err) {
        // begin answers 410 only for a code that is unknown, used or expired: the link is dead.
        if (invalidLink && err.status === 410) return showInvalid(invalidLink);
        throw err;
      }
      const cred = await navigator.credentials.create(creationOptions(begin.options));
      status("Registering…");
      const done = await postJSON(base + "/finish?token=" + encodeURIComponent(begin.token), attestationJSON(cred));
      enrollForm.hidden = true;
      status("Passkey saved.");
      showResult(done);
      wireResult(done.result_token);
    } catch (err) {
      status("Enrollment failed: " + err.message);
      button.disabled = false;
    }
  });
}

// showResult fills in the result section the page rendered for this browser's platform.
function showResult(done) {
  const fill = (cls, set) => document.querySelectorAll("." + cls).forEach(set);
  fill("ntfy-link", (el) => { el.href = done.intent_link; });
  fill("ntfy-server", (el) => { el.textContent = done.server; });
  fill("ntfy-topic", (el) => { el.textContent = done.topic; });
  fill("ntfy-user", (el) => { el.textContent = done.username; });
  const qr = document.getElementById("qr");
  if (qr) qr.src = done.qr;
  document.getElementById("done").hidden = false;
}

// wireResult enables the result page's resend button for the enrolled device.
function wireResult(token) {
  document.getElementById("resend-btn").addEventListener("click", async () => {
    try {
      await postJSON("/token/resend", { token });
      status("Setup notification sent again.");
    } catch (err) {
      status(err.message);
    }
  });
}

// Copy buttons copy the server URL or topic the page shows, filled in by the server or showResult.
document.querySelectorAll("[data-copy]").forEach((b) => {
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(document.querySelector(".ntfy-" + b.dataset.copy).textContent);
      status("Copied.");
    } catch (err) {
      status("Copy failed: " + err.message);
    }
  });
});

const verifyForm = document.getElementById("verify");
if (verifyForm) {
  // The setup push carries the verify token as "#t=<token>"; the Activate form posts it.
  verifyForm.elements.t.value = new URLSearchParams(takeFragment()).get("t") || "";
}

const approve = document.getElementById("approve");
if (approve) {
  const id = approve.dataset.id;
  const buttons = approve.querySelectorAll("button");
  const finish = (msg) => { buttons.forEach((b) => { b.disabled = true; }); status(msg); };

  document.getElementById("approve-btn").addEventListener("click", async () => {
    try {
      status("Waiting for passkey…");
      const res = await fetch("/challenge/" + encodeURIComponent(id) + "/options", { credentials: "same-origin" });
      const opts = await res.json();
      if (!res.ok) throw new Error(opts.error || res.statusText);
      const cred = await navigator.credentials.get(requestOptions(opts));
      await postJSON("/challenge/" + encodeURIComponent(id) + "/assert", assertionJSON(cred));
      finish("Approved. You can close this page.");
    } catch (err) {
      status("Not approved: " + err.message);
    }
  });

  document.getElementById("fraud-btn").addEventListener("click", async () => {
    try {
      await postJSON("/challenge/" + encodeURIComponent(id) + "/fraud", {});
      finish("Reported and denied.");
    } catch (err) {
      status(err.message);
    }
  });
}
