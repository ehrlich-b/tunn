(() => {
  const list = document.getElementById('live-tunnel-list');
  const message = document.getElementById('live-tunnels-status');
  const empty = document.getElementById('live-tunnels-empty');
  if (!list || !message || !empty) return;
  let timer, controller, previous, stopped = false;
  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  function time(value) {
    const node = element('time', new Date(value).toLocaleString(undefined, {timeZone:'UTC'}) + ' UTC');
    node.dateTime = value;
    return node;
  }
  function render(data) {
    const signature = JSON.stringify(data);
    if (signature === previous) return;
    previous = signature;
    if (data.tunnels.length > 0) document.getElementById('start-tunnel')?.remove();
    const fragment = document.createDocumentFragment();
    for (const tunnel of data.tunnels) {
      const item = element('li', undefined, 'glass live-tunnel');
      const heading = element('h3');
      const led = element('span', undefined, 'led on'); led.setAttribute('aria-hidden', 'true');
      heading.append(led, element('span', tunnel.name), element('span', tunnel.kind, 'plan-badge'));
      const link = element('a', tunnel.public_url);
      const url = new URL(tunnel.public_url);
      if (url.protocol !== 'https:') throw new Error('Invalid public URL');
      link.href = url.href; link.target = '_blank'; link.rel = 'noopener noreferrer';
      const details = element('dl');
      for (const [label, value] of [
        ['Connected since', time(tunnel.connected_since)],
        ['Client version', tunnel.client_version || 'Not provided'],
        ['Client host', tunnel.client_host || 'Not provided'],
        ['Last request', tunnel.last_request ? time(tunnel.last_request) : 'No recorded requests']
      ]) {
        const description = element('dd'); description.append(value);
        details.append(element('dt', label), description);
      }
      item.append(heading, link, details); fragment.append(item);
    }
    list.replaceChildren(fragment);
    empty.hidden = data.tunnels.length > 0 || !data.complete;
    message.textContent = data.complete
      ? 'Currently connected. Updates every 5 seconds while this tab is visible.'
      : 'Some relays are unavailable. This list may be incomplete; retrying automatically.';
  }
  async function refresh() {
    if (stopped || document.hidden || controller) return;
    const request = new AbortController(); controller = request;
    const timeout = setTimeout(() => request.abort(), 4500);
    try {
      const response = await fetch('/api/account/tunnels', {cache:'no-store', credentials:'same-origin', redirect:'error', signal:request.signal});
      if (!response.ok) throw new Error('Unavailable');
      const data = await response.json();
      if (!request.signal.aborted) render(data);
    } catch (_) {
      if (!document.hidden && !stopped) {
        previous = undefined; list.replaceChildren(); empty.hidden = true;
        message.textContent = "Can't refresh active tunnels. Retrying automatically; sign in again if this continues.";
      }
    } finally {
      clearTimeout(timeout); controller = undefined;
      if (!document.hidden && !stopped) timer = setTimeout(refresh, 5000);
    }
  }
  function pause() { clearTimeout(timer); if (controller) controller.abort(); }
  document.addEventListener('visibilitychange', () => {
    pause();
    if (!document.hidden) refresh();
  });
  window.addEventListener('pagehide', () => { stopped = true; pause(); });
  window.addEventListener('pageshow', () => { stopped = false; refresh(); });
  refresh();
})();
