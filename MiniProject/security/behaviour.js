(function () {
  const ev = [];
  const max = 150;

  function push(type, data) {
    if (ev.length >= max) return;
    ev.push({ t: Date.now(), type, data });
  }

  // Track keyboard and mouse
  document.addEventListener('keydown', e => push('k', { key: e.key }));
  document.addEventListener('mousemove', e => push('m', { x: e.clientX, y: e.clientY }));

  // Disable copy, paste, cut, and right-click
  ['copy', 'paste', 'cut', 'contextmenu'].forEach(evt =>
    document.addEventListener(evt, e => e.preventDefault())
  );

  // Optional: Disable text selection (extra protection)
  document.addEventListener('selectstart', e => e.preventDefault());

  // Send collected events to server
  window.zeroBankSec = {
    send: () => fetch('/behavior', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: ev })
    }).catch(() => {})
  };
})();
