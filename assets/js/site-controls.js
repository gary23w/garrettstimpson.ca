export function canonicalShareURL(current, canonical) {
  const fallback = new URL(current);
  fallback.search = '';
  fallback.hash = '';
  try {
    const target = new URL(canonical || fallback.href, current);
    if (!['https:', 'http:'].includes(target.protocol)) return fallback.href;
    target.hash = '';
    return target.href;
  } catch { return fallback.href; }
}

export async function copyText(text, clipboard) {
  if (!clipboard || typeof clipboard.writeText !== 'function') return false;
  try { await clipboard.writeText(text); return true; }
  catch { return false; }
}

if (typeof document !== 'undefined') {
  const feedback = document.getElementById('site-feedback');
  const dialog = document.getElementById('copy-dialog');
  const copyField = document.getElementById('copy-dialog-text');
  let feedbackTimer, copyTrigger;

  function announce(message) {
    if (!feedback) return;
    clearTimeout(feedbackTimer);
    feedback.textContent = message;
    feedbackTimer = setTimeout(() => { feedback.textContent = ''; }, 3500);
  }

  async function copy(text, trigger, kind) {
    if (trigger.disabled) return;
    const original = trigger.textContent;
    trigger.disabled = true;
    let clipboard;
    try { clipboard = navigator.clipboard; } catch { /* Use the manual copy dialog. */ }
    const copied = await copyText(text, clipboard);
    trigger.disabled = false;
    if (copied) {
      trigger.textContent = 'Copied ✓';
      announce(kind + ' copied.');
      setTimeout(() => { trigger.textContent = original; }, 1800);
    } else if (dialog && copyField) {
      copyTrigger = trigger;
      copyField.value = text;
      if (!dialog.open) dialog.showModal();
      copyField.focus();
      copyField.select();
    } else {
      announce('Clipboard access is unavailable. Select the text to copy it manually.');
    }
  }

  if (dialog) {
    dialog.addEventListener('close', () => { if (copyTrigger?.isConnected) copyTrigger.focus({preventScroll:true}); });
    dialog.querySelector('[data-select-copy]')?.addEventListener('click', () => { copyField.focus(); copyField.select(); });
  }

  document.querySelectorAll('div.highlight, figure.highlight, pre.highlight').forEach(block => {
    if (block.querySelector('.code-copy') || block.parentElement?.closest('div.highlight, figure.highlight')) return;
    const code = block.querySelector('td.rouge-code pre') || block.querySelector('code') || block.querySelector('pre') || block;
    const text = code.textContent || '';
    const button = document.createElement('button');
    button.className = 'code-copy';
    button.type = 'button';
    button.textContent = 'Copy code';
    button.setAttribute('aria-label', 'Copy code block');
    button.addEventListener('click', () => copy(text, button, 'Code'));
    block.append(button);
  });

  const shareCopy = document.getElementById('share-copy');
  const shareNative = document.getElementById('share-native');
  const shareURL = canonicalShareURL(location.href, document.querySelector('link[rel="canonical"]')?.href);
  shareCopy?.addEventListener('click', () => copy(shareURL, shareCopy, 'Article link'));
  if (shareNative && typeof navigator.share === 'function') {
    shareNative.hidden = false;
    shareNative.addEventListener('click', async () => {
      shareNative.disabled = true;
      try { await navigator.share({title:document.querySelector('h1')?.textContent || document.title, url:shareURL}); }
      catch (error) { if (error.name !== 'AbortError') { shareNative.disabled = false; await copy(shareURL, shareCopy || shareNative, 'Article link'); } }
      finally { shareNative.disabled = false; }
    });
  }

  const nav = document.querySelector('.site-nav');
  const toggle = nav?.querySelector('.nav-toggle');
  if (nav && toggle) {
    function close(restoreFocus = false) {
      nav.classList.remove('nav-open');
      toggle.setAttribute('aria-expanded', 'false');
      toggle.setAttribute('aria-label', 'Open navigation');
      if (restoreFocus) toggle.focus({preventScroll:true});
    }
    toggle.addEventListener('click', () => {
      const open = nav.classList.toggle('nav-open');
      toggle.setAttribute('aria-expanded', String(open));
      toggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    });
    document.addEventListener('click', event => { if (!nav.contains(event.target)) close(); });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && nav.classList.contains('nav-open')) { event.preventDefault(); close(nav.contains(document.activeElement)); }
    });
    nav.addEventListener('focusout', event => { if (!nav.contains(event.relatedTarget)) close(); });
    nav.querySelectorAll('.trigger a').forEach(link => link.addEventListener('click', () => close()));
    const mobile = matchMedia('(max-width: 800px)');
    mobile.addEventListener('change', () => close(mobile.matches && nav.contains(document.activeElement)));
  }
}
