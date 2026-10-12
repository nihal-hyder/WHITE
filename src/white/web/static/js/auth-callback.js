// Reads Supabase tokens from the URL fragment (never sent to servers by the browser) and hands
// them to the WHITE server over a same-origin, CSRF-protected request. The fragment is cleared
// immediately so tokens do not remain in the address bar or history.
(function () {
  "use strict";
  var status = document.getElementById("callback-status");
  var hash = window.location.hash.replace(/^#/, "");
  var query = new URLSearchParams(window.location.search);
  var params = new URLSearchParams(hash);
  history.replaceState(null, "", window.location.pathname);

  function fail(message) {
    status.textContent = message;
    status.className = "alert alert-error";
  }

  if (query.get("token_hash")) {
    window.location.replace("/auth/confirm?token_hash=" + encodeURIComponent(query.get("token_hash")) +
      "&type=" + encodeURIComponent(query.get("type") || "signup"));
    return;
  }
  var error = params.get("error_description") || query.get("error_description");
  if (error) {
    fail("This link could not be used: " + error + ". Please request a new one.");
    return;
  }
  var access = params.get("access_token");
  var refresh = params.get("refresh_token");
  if (!access || !refresh) {
    fail("This link is incomplete or has already been used. Please request a new one.");
    return;
  }
  var csrf = document.querySelector('meta[name="csrf-token"]').getAttribute("content");
  fetch("/auth/session", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify({
      access_token: access,
      refresh_token: refresh,
      expires_at: params.get("expires_at") ? parseInt(params.get("expires_at"), 10) : null,
      type: params.get("type")
    })
  }).then(function (response) {
    return response.json().then(function (body) { return { ok: response.ok, body: body }; });
  }).then(function (result) {
    if (result.ok && result.body.redirect && result.body.redirect.charAt(0) === "/") {
      window.location.replace(result.body.redirect);
    } else {
      fail(result.body.detail || "This link is invalid or has expired.");
    }
  }).catch(function () {
    fail("The server could not be reached. Please try again.");
  });
})();
