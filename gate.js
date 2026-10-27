const form = document.querySelector('#unlock-form');
const password = document.querySelector('#password');
const button = document.querySelector('#unlock');
const status = document.querySelector('#status');
const gate = document.querySelector('#gate');
const reveal = document.querySelector('#reveal');
const day = document.querySelector('#day');
for (let value = 1; value <= 30; value++) day.add(new Option(String(value), String(value)));
const encoder = new TextEncoder();
let frame = null;
let documentUrl = null;
let busy = false;
let mediaController = null;
let mediaUrls = [];
let generation = 0;
const bytes = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
// Обычное текстовое поле не включает системный режим ввода только ASCII.
// В поддерживающих браузерах символы скрываются CSS, включая повторный вход.
const canMaskText = CSS.supports('-webkit-text-security', 'disc');
let passwordVisible = false;
function setPasswordVisible(visible) {
  passwordVisible = visible;
  password.type = canMaskText || visible ? 'text' : 'password';
  password.classList.toggle('is-masked', !visible);
  reveal.textContent = visible ? 'Скрыть' : 'Показать';
  reveal.setAttribute('aria-label', visible ? 'Скрыть пароль' : 'Показать пароль');
  reveal.setAttribute('aria-pressed', String(visible));
}
setPasswordVisible(false);

reveal.addEventListener('click', () => {
  setPasswordVisible(!passwordVisible);
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  const selectedDay = Number(day.value);
  if (!Number.isInteger(selectedDay) || selectedDay < 1 || selectedDay > 30) {
    status.textContent = 'Выбери день сентября.';
    day.focus();
    return;
  }
  if (!window.isSecureContext || !crypto.subtle) {
    status.textContent = 'Открой эту ссылку по HTTPS в современном браузере.';
    return;
  }
  busy = true;
  button.disabled = true;
  status.textContent = 'Открываю наш маленький мир…';
  try {
    // На сервер уходит только запрос шифротекста; пароль не отправляется.
    const response = await fetch(new URL('./payload.json', location.href), {
      cache: 'no-store',
      credentials: 'omit',
    });
    if (!response.ok) throw new Error('network');
    const payload = await response.json();
    if (payload.version !== 2 || payload.iterations !== 600000) throw new Error('format');
    const salt = bytes(payload.salt),
      iv = bytes(payload.iv);
    if (salt.length !== 16 || iv.length !== 12) throw new Error('format');
    const credential = JSON.stringify([password.value.normalize('NFC'), 9, selectedDay]);
    const material = await crypto.subtle.importKey(
      'raw',
      encoder.encode(credential),
      'PBKDF2',
      false,
      ['deriveKey'],
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: payload.iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    let plaintext;
    try {
      plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, bytes(payload.data));
    } catch {
      throw new Error('password');
    }
    const currentGeneration = ++generation;
    mediaController = new AbortController();
    const signal = mediaController.signal;
    const mediaCache = new Map();
    window.__PRIVATE_LOAD_ASSET__ = (path) => {
      const item = payload.media?.[path];
      if (!item || !/^media\/[a-f0-9]{64}\.enc$/.test(item.file) || item.mime !== 'video/mp4')
        return Promise.reject(new Error('media'));
      if (!mediaCache.has(path)) {
        const pending = (async () => {
          const response = await fetch(new URL(item.file, location.href), {
            signal,
            credentials: 'omit',
          });
          if (!response.ok) throw new Error('network');
          const plain = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: bytes(item.iv) },
            key,
            await response.arrayBuffer(),
          );
          if (generation !== currentGeneration) throw new Error('locked');
          const url = URL.createObjectURL(new Blob([plain], { type: item.mime }));
          mediaUrls.push(url);
          return url;
        })().catch((error) => {
          mediaCache.delete(path);
          throw error;
        });
        mediaCache.set(path, pending);
      }
      return mediaCache.get(path);
    };
    documentUrl = URL.createObjectURL(new Blob([plaintext], { type: 'text/html;charset=utf-8' }));
    frame = document.createElement('iframe');
    frame.title = 'Остров нашей истории';
    frame.allow = 'autoplay';
    frame.src = documentUrl;
    document.body.append(frame);
    gate.hidden = true;
    password.value = '';
    day.value = '';
    status.textContent = '';
    frame.focus();
  } catch (error) {
    status.textContent =
      error.message === 'password'
        ? 'Дата или пароль не совпали. Попробуй ещё раз.'
        : 'Не получилось загрузить остров. Проверь интернет и попробуй ещё раз.';
    password.focus();
    password.select();
  } finally {
    busy = false;
    button.disabled = false;
  }
});

function clearSession() {
  generation++;
  mediaController?.abort();
  mediaController = null;
  window.__PRIVATE_LOAD_ASSET__ = undefined;
  frame?.remove(); // Удаление документа также останавливает видео.
  frame = null;
  if (documentUrl) URL.revokeObjectURL(documentUrl);
  documentUrl = null;
  mediaUrls.forEach((url) => URL.revokeObjectURL(url));
  mediaUrls = [];
  gate.hidden = false;
  password.value = '';
  day.value = '';
  setPasswordVisible(false);
}
window.addEventListener('pagehide', clearSession);
