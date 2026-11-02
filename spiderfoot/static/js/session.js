/* Tell the user when their sign-in has expired.
 *
 * Behind an SSO proxy (oauth2-proxy + Dex) an expired session makes every API call answer with a
 * redirect to the login page. fetch() follows it and the caller then fails on "Unexpected token <",
 * which looks like the action simply "didn't take". This wraps fetch and htmx so the redirect is
 * recognised and a clear banner is shown instead. Calls still fail as before; nothing is retried.
 */
(function () {
  'use strict';
  var LOGIN = /\/(dex|oauth2)\/|\/sign_in\b|\/login\b/i;

  function banner() {
    if (document.getElementById('sf-session-expired')) return;
    var el = document.createElement('div');
    el.id = 'sf-session-expired';
    el.setAttribute('role', 'alert');
    el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:99999;padding:10px 16px;background:#b45309;' +
      'color:#fff;font:14px system-ui,sans-serif;display:flex;gap:12px;align-items:center;justify-content:center;flex-wrap:wrap';
    el.innerHTML = '<span><strong>Your sign-in expired,</strong> so nothing you just did was saved.</span>';
    var b = document.createElement('button');
    b.textContent = 'Sign in again';
    b.style.cssText = 'padding:4px 12px;border-radius:6px;border:1px solid #fff;background:transparent;color:#fff;cursor:pointer';
    b.onclick = function () { window.location.reload(); };
    el.appendChild(b);
    document.body.appendChild(el);
  }

  function expired(url, redirected) {
    return !!redirected && LOGIN.test(String(url || ''));
  }

  var realFetch = window.fetch;
  if (realFetch) {
    window.fetch = function () {
      return realFetch.apply(this, arguments).then(function (res) {
        try { if (expired(res.url, res.redirected)) banner(); } catch (e) { /* never break a request */ }
        return res;
      });
    };
  }

  document.addEventListener('htmx:afterRequest', function (ev) {
    try {
      var xhr = ev.detail && ev.detail.xhr;
      if (xhr && xhr.responseURL && xhr.responseURL !== ev.detail.pathInfo.finalRequestPath &&
          LOGIN.test(xhr.responseURL)) banner();
    } catch (e) { /* ignore */ }
  });

  window.__sfSessionExpired = expired;  // exposed for tests
})();
