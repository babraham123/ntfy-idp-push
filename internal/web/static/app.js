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
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
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
if (enrollForm) {
  enrollForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = enrollForm.querySelector("button");
    button.disabled = true;
    try {
      status("Creating passkey…");
      const name = enrollForm.elements.name.value;
      const begin = await postJSON("/enroll/begin", { name, code: enrollForm.dataset.code });
      const cred = await navigator.credentials.create(creationOptions(begin.options));
      status("Registering…");
      const done = await postJSON("/enroll/finish?token=" + encodeURIComponent(begin.token), attestationJSON(cred));
      enrollForm.hidden = true;
      status("Passkey saved.");
      document.getElementById("ntfy-link").href = done.ntfy_link;
      document.getElementById("qr").src = done.qr;
      document.getElementById("no-code").hidden = done.has_code;
      if (done.code_expires) {
        const expiry = document.getElementById("code-expiry");
        expiry.querySelector("time").textContent = new Date(done.code_expires * 1000).toLocaleTimeString();
        expiry.hidden = false;
      }
      document.getElementById("done").hidden = false;
      wireResult(done.result_token);
    } catch (err) {
      status("Enrollment failed: " + err.message);
      button.disabled = false;
    }
  });
}

// wireResult enables the result page's manual sign-in and resend buttons for the enrolled device.
function wireResult(token) {
  document.getElementById("password-btn").addEventListener("click", async (e) => {
    try {
      const out = await postJSON("/enroll/password", { token });
      document.getElementById("password-user").textContent = out.username;
      document.getElementById("password-value").textContent = out.password;
      document.getElementById("password").hidden = false;
      e.target.disabled = true;
      status("Add this user in ntfy → Settings → Manage users. It replaced your previous ntfy password.");
    } catch (err) {
      status(err.message);
    }
  });
  document.getElementById("resend-btn").addEventListener("click", async () => {
    try {
      await postJSON("/enroll/resend", { token });
      status("Setup notification sent again.");
    } catch (err) {
      status(err.message);
    }
  });
}

const approve = document.getElementById("approve");
if (approve) {
  const id = approve.dataset.id;
  const buttons = approve.querySelectorAll("button");
  const finish = (msg) => { buttons.forEach((b) => { b.disabled = true; }); status(msg); };

  document.getElementById("approve-btn").addEventListener("click", async () => {
    try {
      status("Waiting for passkey…");
      const res = await fetch("/c/" + encodeURIComponent(id) + "/options", { credentials: "same-origin" });
      const opts = await res.json();
      if (!res.ok) throw new Error(opts.error || res.statusText);
      const cred = await navigator.credentials.get(requestOptions(opts));
      await postJSON("/c/" + encodeURIComponent(id) + "/assert", assertionJSON(cred));
      finish("Approved. You can close this page.");
    } catch (err) {
      status("Not approved: " + err.message);
    }
  });

  document.getElementById("fraud-btn").addEventListener("click", async () => {
    try {
      await postJSON("/c/" + encodeURIComponent(id) + "/fraud", {});
      finish("Reported and denied.");
    } catch (err) {
      status(err.message);
    }
  });
}
