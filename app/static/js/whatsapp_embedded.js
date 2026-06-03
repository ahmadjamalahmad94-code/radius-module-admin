/* WhatsApp Embedded Signup — customer-portal launcher.
 *
 * Flow:
 *   1. GET  /portal/whatsapp/embedded/config  → decide availability (authoritative).
 *   2. (click) POST /portal/whatsapp/embedded/start → one-time {state, nonce}.
 *   3. FB.login(config_id, state) → Meta Embedded Signup popup.
 *   4. popup posts {waba_id, phone_number_id}; FB.login callback returns the code.
 *   5. POST /portal/whatsapp/embedded/complete {code, waba_id, phone_number_id,
 *      state, nonce} → update the card UI.
 *
 * Design: CSP-clean (external file, no inline). Secrets never touched. Only
 * Meta's canonical secure origins are trusted for postMessage (strict equality,
 * never substring). When embedded signup is unavailable the launcher does
 * nothing beyond wiring the advanced-section toggle, so the manual/advanced
 * path remains a graceful fallback.
 */
(function () {
  "use strict";

  var boot = {};
  try {
    boot = JSON.parse(document.querySelector('[data-wa-embedded-boot]').textContent || '{}');
  } catch (e) { boot = {}; }

  var EP = boot.endpoints || {};
  var MESSAGE_TYPE = boot.message_type || 'WA_EMBEDDED_SIGNUP';
  // Trust ONLY Meta's canonical secure origins — strict equality, not substring.
  var META_ORIGINS = ['https://www.facebook.com', 'https://web.facebook.com'];

  var card = document.querySelector('[data-wa-card]');
  var selected = {};   // {waba_id, phone_number_id} captured from the popup
  var session = {};    // {state, nonce} issued by /embedded/start
  var sdkReady = false;

  function csrf() {
    if (boot.csrf) return boot.csrf;
    var n = document.querySelector('input[name="_csrf_token"]');
    return n ? n.value : '';
  }

  function setState(s) { if (card) card.setAttribute('data-wa-state', s); }

  function showConnecting(on) {
    var el = document.querySelector('[data-wa-connecting]');
    if (el) el.hidden = !on;
  }

  function setStatus(msg, ok) {
    var el = document.querySelector('[data-wa-embedded-status]');
    if (!el) return;
    el.hidden = false;
    el.textContent = msg;
    el.className = 'wa-connect-status' + (ok === true ? ' is-ok' : ok === false ? ' is-err' : '');
  }

  function loadSdk(cfg) {
    window.fbAsyncInit = function () {
      FB.init({ appId: cfg.app_id, autoLogAppEvents: true, xfbml: false, version: cfg.graph_version || 'v21.0' });
      sdkReady = true;
    };
    (function (d, s, id) {
      if (d.getElementById(id)) { sdkReady = (typeof FB !== 'undefined'); return; }
      var js = d.createElement(s);
      js.id = id;
      js.src = 'https://connect.facebook.net/en_US/sdk.js';
      var fjs = d.getElementsByTagName(s)[0];
      fjs.parentNode.insertBefore(js, fjs);
    }(document, 'script', 'facebook-jssdk'));
  }

  // Capture the assets the Embedded Signup popup posts back.
  window.addEventListener('message', function (ev) {
    if (META_ORIGINS.indexOf(ev.origin) === -1) return;   // strict origin equality
    var data;
    try { data = (typeof ev.data === 'string') ? JSON.parse(ev.data) : ev.data; } catch (e) { return; }
    if (!data || data.type !== MESSAGE_TYPE) return;
    if (data.data) {
      selected.waba_id = data.data.waba_id || selected.waba_id;
      selected.phone_number_id = data.data.phone_number_id || selected.phone_number_id;
    }
  });

  function postJSON(url, body) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrf(),
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json'
      },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.text().then(function (t) {
        var j = null;
        try { j = JSON.parse(t); } catch (e) { j = null; }
        return { ok: r.ok, j: j, status: r.status };
      });
    });
  }

  function complete(code) {
    setStatus('جارٍ إكمال الربط…');
    postJSON(EP.complete, {
      code: code,
      waba_id: selected.waba_id || '',
      phone_number_id: selected.phone_number_id || '',
      // Passed through now; the server enforces state/nonce in a later phase.
      state: session.state || '',
      nonce: session.nonce || ''
    }).then(function (res) {
      if (res.ok && res.j && res.j.ok) {
        setState('connected');
        setStatus('تم الربط بنجاح ✅ — جارٍ التحديث…', true);
        setTimeout(function () { location.href = (res.j && res.j.redirect) || location.href; }, 700);
      } else {
        setState('error');
        showConnecting(false);
        setStatus((res.j && res.j.message) || ('تعذّر إكمال الربط (رمز ' + res.status + ').'), false);
      }
    }).catch(function () {
      showConnecting(false);
      setStatus('تعذّر الاتصال بالخادم. حاول مرة أخرى.', false);
    });
  }

  function launch() {
    if (typeof FB === 'undefined' || !sdkReady) {
      setStatus('جارٍ تحميل أدوات Meta… أعد المحاولة بعد لحظات.', false);
      return;
    }
    selected = {};
    session = {};
    setStatus('جارٍ تجهيز جلسة الربط…');
    // 1) server-issued, single-use state/nonce session
    postJSON(EP.start, {}).then(function (res) {
      if (!(res.ok && res.j && res.j.ok)) {
        setStatus((res.j && res.j.message) || 'تعذّر بدء جلسة الربط. أعد المحاولة.', false);
        return;
      }
      session.state = res.j.state;
      session.nonce = res.j.nonce;
      var cfg = res.j.config || {};
      setState('connecting');
      showConnecting(true);
      setStatus('بانتظار إكمال نافذة Meta…');
      // 2) Meta Embedded Signup popup, carrying our state
      FB.login(function (resp) {
        var code = resp && resp.authResponse && resp.authResponse.code;
        if (code) {
          complete(code);
        } else {
          showConnecting(false);
          setState('not_connected');
          setStatus('تم إلغاء الربط أو لم تُمنح الصلاحيات.', false);
        }
      }, {
        config_id: cfg.config_id,
        response_type: 'code',
        override_default_response_type: true,
        extras: { setup: {}, sessionInfoVersion: '2', state: session.state }
      });
    }).catch(function () {
      setStatus('تعذّر الاتصال بالخادم. حاول مرة أخرى.', false);
    });
  }

  function bindLaunch() {
    var btns = document.querySelectorAll('[data-wa-embedded-launch]');
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener('click', launch);
    }
  }

  function bindAdvancedToggle() {
    var advLink = document.querySelector('[data-wa-toggle-advanced]');
    if (!advLink) return;
    advLink.addEventListener('click', function (e) {
      e.preventDefault();
      var d = document.getElementById('wa-advanced');
      if (d) { d.open = true; d.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
    });
  }

  // The advanced-section toggle always works, regardless of embedded availability.
  bindAdvancedToggle();

  function init(cfg) {
    // Graceful: when unavailable, leave the manual/advanced section as the path.
    if (!cfg || !cfg.enabled || !cfg.app_id || !cfg.config_id) return;
    loadSdk(cfg);
    bindLaunch();
  }

  function inlineFallback() {
    var c = boot.config;
    if (c && c.app_id && c.config_id) {
      init({ enabled: true, app_id: c.app_id, config_id: c.config_id, graph_version: c.graph_version });
    }
  }

  // Ask the server (authoritative) whether embedded signup is available.
  if (EP.config && window.fetch) {
    fetch(EP.config, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (j) { init(j && j.ok ? j : null); })
      .catch(inlineFallback);
  } else {
    inlineFallback();
  }
})();
