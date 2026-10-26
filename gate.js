const form = document.querySelector('#unlock-form');
const password = document.querySelector('#password');
const button = document.querySelector('#unlock');
const status = document.querySelector('#status');
const gate = document.querySelector('#gate');
const lock = document.querySelector('#lock');
const reveal = document.querySelector('#reveal');
const encoder = new TextEncoder();
let frame = null;
let documentUrl = null;
let busy = false;
const bytes = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));

reveal.addEventListener('click', () => {
  const shown = password.type === 'password';
  password.type = shown ? 'text' : 'password';
  reveal.textContent = shown ? 'Скрыть' : 'Показать';
  reveal.setAttribute('aria-label', shown ? 'Скрыть пароль' : 'Показать пароль');
  reveal.setAttribute('aria-pressed', String(shown));
});

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy) return;
  if (!window.isSecureContext || !crypto.subtle) {
    status.textContent = 'Открой эту ссылку по HTTPS в современном браузере.';
    return;
  }
  busy = true;
  button.disabled = true;
  status.textContent = 'Открываю наш маленький мир…';
  try {
    // На сервер уходит только запрос шифротекста; пароль не отправляется.
    const response = await fetch(new URL('./payload.json', location.href), { cache: 'no-store', credentials: 'omit' });
    if (!response.ok) throw new Error('network');
    const payload = await response.json();
    if (payload.version !== 1 || payload.iterations !== 600000) throw new Error('format');
    const salt = bytes(payload.salt), iv = bytes(payload.iv);
    if (salt.length !== 16 || iv.length !== 12) throw new Error('format');
    const material = await crypto.subtle.importKey('raw', encoder.encode(password.value), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: payload.iterations }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    let plaintext;
    try { plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, bytes(payload.data)); }
    catch { throw new Error('password'); }
    documentUrl = URL.createObjectURL(new Blob([plaintext], { type: 'text/html;charset=utf-8' }));
    frame = document.createElement('iframe');
    frame.title = 'Наша открытка';
    frame.allow = 'autoplay';
    frame.src = documentUrl;
    document.body.append(frame);
    gate.hidden = true;
    lock.hidden = false;
    password.value = '';
    status.textContent = '';
    frame.focus();
  } catch (error) {
    status.textContent = error.message === 'password' ? 'Пароль не подошёл. Попробуй ещё раз.' : 'Не получилось загрузить открытку. Проверь интернет и попробуй ещё раз.';
    password.focus();
    password.select();
  } finally {
    busy = false;
    button.disabled = false;
  }
});

lock.addEventListener('click', () => {
  frame?.remove(); // Удаление документа также останавливает музыку.
  frame = null;
  if (documentUrl) URL.revokeObjectURL(documentUrl);
  documentUrl = null;
  lock.hidden = true;
  gate.hidden = false;
  password.value = '';
  password.type = 'password';
  reveal.textContent = 'Показать';
  reveal.setAttribute('aria-label', 'Показать пароль');
  reveal.setAttribute('aria-pressed', 'false');
  password.focus();
});
