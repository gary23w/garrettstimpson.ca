const ENGAGED_MS = 45_000;
const COOLDOWN_MS = 24 * 60 * 60 * 1000;
const COOLDOWN_KEY = 'garrett-data-removal-popup-until';

function buildDialog(document, window, logo, href) {
  const dialog = document.createElement('dialog');
  dialog.className = 'garrett-removal-popup';
  dialog.setAttribute('aria-labelledby', 'garrett-removal-popup-title');
  dialog.setAttribute('aria-describedby', 'garrett-removal-popup-description');
  dialog.innerHTML = `
    <form method="dialog">
      <div class="garrett-removal-popup-top">
        <div class="garrett-removal-popup-brand">
          <img width="36" height="36" alt="">
          <span><strong>Agent Garrett</strong><small>Ad · Data removal</small></span>
        </div>
        <button class="garrett-removal-popup-close" aria-label="Close data removal offer" autofocus>×</button>
      </div>
      <div class="garrett-removal-popup-content">
        <h2 id="garrett-removal-popup-title">Did you know that your data is for sale?</h2>
        <p id="garrett-removal-popup-description">Right now, data brokers are buying and selling everything about you.</p>
        <div class="garrett-removal-popup-actions">
          <a class="garrett-removal-popup-start" rel="sponsored">Get help today</a>
          <button>Keep browsing</button>
        </div>
      </div>
    </form>`;

  const close = () => dialog.close();
  const action = dialog.querySelector('.garrett-removal-popup-start');
  action.href = href;
  action.addEventListener('click', close);
  dialog.querySelector('img').src = logo;
  dialog.addEventListener('click', event => {
    if (event.target === dialog) close();
  });
  window.addEventListener('pagehide', close);
  dialog.addEventListener('close', () => {
    window.removeEventListener('pagehide', close);
    dialog.remove();
  }, {once: true});
  document.body.append(dialog);
  return dialog;
}

export function createDataRemovalPopup({document, window, logo, href, canShow = () => true}) {
  if (window.top !== window || !window.HTMLDialogElement?.prototype.showModal) return () => {};

  let stopWaiting, dialog;
  const foreground = () => document.visibilityState === 'visible' && document.hasFocus() && !document.prerendering;
  const busy = () => document.fullscreenElement
    || document.activeElement?.closest('input, textarea, select, [contenteditable]:not([contenteditable="false"]), iframe')
    || document.querySelector('dialog[open], [aria-modal="true"], .d-modal, #reply-control.open, #reply-control.draft')
    || Array.from(document.querySelectorAll('video[controls], audio[controls]')).some(media => !media.paused && !media.ended);

  function cooldownElapsed() {
    try { return !(Number(window.localStorage.getItem(COOLDOWN_KEY)) > Date.now()); }
    catch { return false; }
  }

  return function setEligible(eligible) {
    if (!eligible) {
      stopWaiting?.();
      if (dialog?.open) dialog.close();
      return;
    }
    if (stopWaiting || dialog?.open || !cooldownElapsed()) return;

    const controller = new AbortController();
    const {signal} = controller;
    let engaged = false, remaining = ENGAGED_MS, timer = null, startedAt = 0;

    function pause() {
      if (timer === null) return;
      window.clearTimeout(timer);
      timer = null;
      remaining = Math.max(0, remaining - (window.performance.now() - startedAt));
    }

    function resume() {
      if (!engaged || timer !== null || !foreground()) return;
      startedAt = window.performance.now();
      timer = window.setTimeout(check, Math.ceil(remaining) || 750);
    }

    function check() {
      pause();
      if (!foreground()) return;
      if (remaining > 0) { resume(); return; }
      if (!canShow() || busy()) return;
      stopWaiting();
      // Recheck in case another tab showed the offer while this page waited.
      if (!cooldownElapsed()) return;
      try { window.localStorage.setItem(COOLDOWN_KEY, String(Date.now() + COOLDOWN_MS)); }
      catch { return; }
      dialog = buildDialog(document, window, logo, href);
      dialog.showModal();
    }

    stopWaiting = () => {
      pause();
      controller.abort();
      stopWaiting = null;
    };
    const engage = event => {
      if (!event.isTrusted || !foreground()) return;
      engaged = true;
      resume();
    };
    for (const type of ['pointerdown', 'keydown', 'wheel']) {
      window.addEventListener(type, engage, {signal, passive: true});
    }
    window.addEventListener('focus', resume, {signal});
    window.addEventListener('blur', pause, {signal});
    window.addEventListener('pageshow', resume, {signal});
    window.addEventListener('pagehide', pause, {signal});
    document.addEventListener('visibilitychange', () => {
      if (foreground()) resume();
      else pause();
    }, {signal});
  };
}

const blogPopup = typeof document !== 'undefined' && document.querySelector('script[data-agent-garrett-popup-logo]');
if (blogPopup) {
  createDataRemovalPopup({
    document,
    window,
    logo: blogPopup.dataset.agentGarrettPopupLogo,
    href: 'https://agent.garrettstimpson.ca/remove',
  })(true);
}
