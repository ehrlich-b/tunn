(() => {
'use strict';
const menu = document.querySelector('.menu');
if (menu) {
  document.addEventListener('keydown', event => { if (event.key === 'Escape' && menu.open) { menu.open = false; menu.querySelector('summary').focus(); } });
  document.addEventListener('click', event => { if (menu.open && !menu.contains(event.target)) menu.open = false; });
}
document.querySelectorAll('[data-copy]').forEach(button => {
  const label = button.textContent;
  const item = button.dataset.copyKind === 'link' ? 'Link' : 'Command';
  button.addEventListener('click', async () => {
    let message;
    try { await navigator.clipboard.writeText(button.dataset.copy); button.textContent = 'Copied'; message = item + ' copied'; }
    catch (_) { button.textContent = 'Copy failed'; message = 'Copy failed. Select the ' + item.toLowerCase() + ' and copy it.'; }
    const status = document.getElementById(button.getAttribute('aria-describedby') || '');
    if (status) status.textContent = message;
    setTimeout(() => { button.textContent = label; }, 2500);
  });
});
})();
