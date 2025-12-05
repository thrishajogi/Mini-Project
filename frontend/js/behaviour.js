(function () {
  const ev = [];
  const max = 150;
  function push(type, data) {
    if (ev.length >= max) return;
    ev.push({ t: Date.now(), type, data });
  }
  document.addEventListener('keydown', e => push('k', { key: e.key }));
  document.addEventListener('mousemove', e => push('m', { x: e.clientX, y: e.clientY }));
  window.zeroBankSec = {
    send: () => fetch('/behavior', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: ev })
    }).catch(() => {})
  };
})();