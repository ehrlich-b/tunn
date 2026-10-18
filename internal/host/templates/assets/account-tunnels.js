(() => {
  const list = document.getElementById('live-tunnel-list');
  const summary = document.getElementById('live-tunnels-summary');
  const stale = document.getElementById('live-tunnels-stale');
  const empty = document.getElementById('live-tunnels-empty');
  const more = document.getElementById('live-tunnels-more');
  if (!list || !summary || !stale || !empty || !more) return;
  let timer, controller, stopped = false, expanded = false, updated = Date.now();
  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  function relative(value, ago = false) {
    const minutes = Math.max(0, Math.floor((Date.now() - new Date(value)) / 60000));
    const label = minutes < 1 ? 'now' : minutes < 60 ? minutes + 'm' : minutes < 1440 ? Math.floor(minutes / 60) + 'h' : Math.floor(minutes / 1440) + 'd';
    return ago && label !== 'now' ? label + ' ago' : label;
  }
  function age() {
    const seconds = (Date.now() - updated) / 1000;
    stale.hidden = seconds <= 60;
    stale.textContent = seconds > 60 ? `last updated ${Math.floor(seconds / 60)} min ago` : '';
    for (const node of list.querySelectorAll('.live-tunnel-duration')) node.textContent = relative(node.dateTime);
  }
  function limit() {
    Array.from(list.children).forEach((row, i) => { row.hidden = !expanded && i >= 5; });
    more.hidden = list.children.length <= 5;
    more.textContent = expanded ? 'Show fewer' : `+${list.children.length - 5} more`;
    more.setAttribute('aria-expanded', String(expanded));
  }
  more.addEventListener('click', () => { expanded = !expanded; limit(); });
  function render(data) {
    if (!data.complete || !Array.isArray(data.tunnels)) return;
    // Validate the entire response before changing the last good view.
    const tunnels = data.tunnels.map(tunnel => {
      const url = new URL(tunnel.public_url);
      if (url.protocol !== 'https:') throw new Error('Invalid public URL');
      return tunnel;
    }).sort((a, b) => (Date.parse(b.last_request) || 0) - (Date.parse(a.last_request) || 0) || a.name.localeCompare(b.name) || a.public_url.localeCompare(b.public_url));
    const existing = new Map(Array.from(list.children, node => [node.dataset.key, node]));
    tunnels.forEach((tunnel, i) => {
      let item = existing.get(tunnel.public_url);
      if (!item) {
        item = element('li', undefined, 'live-tunnel');
        item.dataset.key = tunnel.public_url;
        const details = element('details'), row = element('summary');
        const led = element('span', undefined, 'led on'); led.setAttribute('aria-hidden', 'true');
        const link = element('a', undefined, 'live-tunnel-url');
        link.target = '_blank'; link.rel = 'noopener noreferrer'; link.append(element('span'), element('span'));
        row.append(led, element('span', undefined, 'live-tunnel-name'), link, element('span', undefined, 'plan-badge'), element('time', undefined, 'live-tunnel-duration'));
        details.append(row, element('p', undefined, 'live-tunnel-details')); item.append(details);
      }
      existing.delete(tunnel.public_url);
      item.querySelector('.live-tunnel-name').textContent = tunnel.name;
      const link = item.querySelector('a'), chars = Array.from(tunnel.public_url);
      link.href = tunnel.public_url; link.title = tunnel.public_url;
      link.firstChild.textContent = chars.slice(0, -20).join('');
      link.lastChild.textContent = chars.slice(-20).join('');
      item.querySelector('.plan-badge').textContent = tunnel.kind;
      const duration = item.querySelector('time'); duration.dateTime = tunnel.connected_since;
      duration.title = 'Connected ' + new Date(tunnel.connected_since).toUTCString();
      item.querySelector('.live-tunnel-details').textContent = `Client ${tunnel.client_version || 'unknown'} · ${tunnel.client_host || 'Host unknown'} · ${tunnel.last_request ? 'Last request ' + relative(tunnel.last_request, true) : 'No recorded requests'}`;
      if (list.children[i] !== item) list.insertBefore(item, list.children[i] || null);
    });
    for (const item of existing.values()) item.remove();
    const label = tunnels.length ? `${tunnels.length} online` : 'None online';
    if (summary.textContent !== label) {
      summary.replaceChildren();
      if (tunnels.length) {
        const led = element('span', undefined, 'led on'); led.setAttribute('aria-hidden', 'true');
        summary.append(led, document.createTextNode(label));
      } else summary.textContent = label;
    }
    empty.hidden = tunnels.length > 0;
    updated = Date.now(); limit(); age();
  }
  async function refresh() {
    age();
    if (stopped || document.hidden || controller) return;
    const request = new AbortController(); controller = request;
    const timeout = setTimeout(() => request.abort(), 4500);
    try {
      const response = await fetch('/api/account/tunnels', {cache:'no-store', credentials:'same-origin', redirect:'error', signal:request.signal});
      if (!response.ok) throw new Error('Unavailable');
      const data = await response.json();
      if (!request.signal.aborted) render(data);
    } catch (_) {
      // Keep the last good view through a temporary outage.
    } finally {
      clearTimeout(timeout); controller = undefined; age();
      if (!document.hidden && !stopped) timer = setTimeout(refresh, 5000);
    }
  }
  function pause() { clearTimeout(timer); if (controller) controller.abort(); }
  document.addEventListener('visibilitychange', () => {
    pause(); age();
    if (!document.hidden) refresh();
  });
  window.addEventListener('pagehide', () => { stopped = true; pause(); });
  window.addEventListener('pageshow', () => { stopped = false; refresh(); });
  limit(); age(); refresh();
})();
