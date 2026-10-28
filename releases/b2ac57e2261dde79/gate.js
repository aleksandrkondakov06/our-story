const form = document.querySelector('#unlock-form');
const password = document.querySelector('#password');
const button = document.querySelector('#unlock');
const status = document.querySelector('#status');
const gate = document.querySelector('#gate');
const reveal = document.querySelector('#reveal');
const day = document.querySelector('#day');
const remember = document.querySelector('#remember');
const retry = document.querySelector('#retry-access');
const loaderUrl = new URL(document.currentScript.src);
const siteRoot = new URL(document.currentScript.dataset.siteRoot || './', location.href);
const payloadUrl = new URL('./payload.json', loaderUrl);
window.__PRIVATE_PROTOCOL__ = 3;
window.__PRIVATE_SITE_ROOT__ = siteRoot.href;
for (let value = 1; value <= 30; value++) day.add(new Option(String(value), String(value)));
const encoder = new TextEncoder();
let frame = null;
let busy = false;
let mediaController = null;
let mediaUrls = [];
let generation = 0;
let payloadRequest = null;
let cancelStartup = null;
const sessionLifetime = 30 * 24 * 60 * 60 * 1000;
let sessionExpiresAt = 0;
let expiryTimer = null;

// Сохраняем только готовый AES-ключ, без пароля и исходного материала PBKDF2.
// Соль сайта постоянна между выпусками; каждый шифротекст получает новый IV.
function sessionStore(action, value) {
  return new Promise((resolve, reject) => {
    let db,
      transaction,
      finished = false;
    const finish = (error, result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (error) {
        try {
          transaction?.abort();
        } catch {}
      }
      db?.close();
      if (error) reject(error);
      else resolve(result);
    };
    const timer = setTimeout(() => finish(new Error('storage')), 2000);
    try {
      const request = indexedDB.open('our-story-access', 1);
      request.onupgradeneeded = () => {
        if (finished) return request.transaction.abort();
        request.result.createObjectStore('sessions');
      };
      request.onerror = () => finish(new Error('storage'));
      request.onblocked = () => finish(new Error('storage'));
      request.onsuccess = () => {
        db = request.result;
        if (finished) return db.close();
        db.onversionchange = () => db.close();
        try {
          transaction = db.transaction('sessions', action === 'get' ? 'readonly' : 'readwrite');
          const store = transaction.objectStore('sessions');
          const operation =
            action === 'put'
              ? store.put(value, siteRoot.pathname)
              : action === 'delete' && !value
                ? store.delete(siteRoot.pathname)
                : store.get(siteRoot.pathname);
          if (action === 'delete' && value) {
            operation.onsuccess = () => {
              // Старая вкладка не удаляет более свежий вход другой вкладки.
              if (operation.result?.expiresAt === value.expiresAt) store.delete(siteRoot.pathname);
            };
          }
          transaction.oncomplete = () => finish(null, operation.result);
          transaction.onerror = transaction.onabort = () => finish(new Error('storage'));
        } catch (error) {
          finish(error);
        }
      };
    } catch (error) {
      finish(error);
    }
  });
}
function validSession(session) {
  const now = Date.now();
  return (
    session?.version === 2 &&
    Number.isSafeInteger(session.issuedAt) &&
    Number.isSafeInteger(session.expiresAt) &&
    session.issuedAt <= now &&
    session.expiresAt - session.issuedAt === sessionLifetime &&
    session.expiresAt > now &&
    session.key instanceof CryptoKey &&
    session.key.algorithm.name === 'AES-GCM' &&
    session.key.algorithm.length === 256 &&
    !session.key.extractable &&
    session.key.usages.length === 1 &&
    session.key.usages[0] === 'decrypt'
  );
}
function checkExpiry() {
  clearTimeout(expiryTimer);
  if (!sessionExpiresAt) return;
  if (Date.now() >= sessionExpiresAt) {
    sessionStore('delete', { expiresAt: sessionExpiresAt }).catch(() => {});
    clearSession();
    status.textContent = 'Прошло 30 дней. Вспомни нашу дату и введи пароль ещё раз.';
  } else {
    // setTimeout ограничен 2^31−1 мс; дополнительно проверяем возврат в браузер.
    expiryTimer = setTimeout(checkExpiry, Math.min(sessionExpiresAt - Date.now(), 60 * 60 * 1000));
  }
}
async function restoreAccess() {
  if (busy || frame || !window.isSecureContext || !window.crypto?.subtle) return;
  busy = true;
  button.disabled = true;
  retry.hidden = true;
  const currentGeneration = ++generation;
  let saved;
  try {
    saved = await sessionStore('get');
    if (saved && !validSession(saved)) {
      await sessionStore('delete', saved);
      saved = null;
    }
  } catch {
    saved = null;
  }
  if (generation !== currentGeneration) return;
  busy = false;
  button.disabled = false;
  if (saved) await openIsland({ saved });
}
function loadPayload() {
  if (!payloadRequest) {
    payloadRequest = fetch(payloadUrl, {
      cache: 'no-cache',
      credentials: 'omit',
    })
      .then(async (response) => {
        if (!response.ok) throw new Error('network');
        return response.json();
      })
      .catch((error) => {
        payloadRequest = null;
        throw error;
      });
  }
  return payloadRequest;
}
// Небольшой шифротекст скачивается, пока вводят дату и пароль. Ключа ещё нет.
loadPayload().catch(() => {});
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
  await openIsland({ selectedDay, save: remember.checked });
});

async function openIsland({ selectedDay, save = false, saved = null }) {
  if (busy) return;
  if (!window.isSecureContext || !window.crypto?.subtle) {
    status.textContent = 'Открой эту ссылку по HTTPS в современном браузере.';
    return;
  }
  busy = true;
  button.disabled = true;
  retry.hidden = true;
  status.textContent = 'Открываю наш маленький мир…';
  const currentGeneration = ++generation;
  try {
    // На сервер уходит только запрос шифротекста; пароль не отправляется.
    const payload = await loadPayload();
    if (payload.version !== 2 || payload.iterations !== 600000) throw new Error('format');
    const salt = bytes(payload.salt),
      iv = bytes(payload.iv);
    if (salt.length !== 16 || iv.length !== 12) throw new Error('format');
    if (saved && !validSession(saved)) throw new Error('expired');
    let key = saved?.key;
    if (!key) {
      const credential = JSON.stringify([password.value.normalize('NFC'), 9, selectedDay]);
      const material = await crypto.subtle.importKey(
        'raw',
        encoder.encode(credential),
        'PBKDF2',
        false,
        ['deriveKey'],
      );
      key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: payload.iterations },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt'],
      );
    }
    let plaintext;
    try {
      plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, bytes(payload.data));
    } catch {
      throw new Error('password');
    }
    if (generation !== currentGeneration) throw new Error('locked');
    if (saved && !validSession(saved)) throw new Error('expired');
    mediaController = new AbortController();
    const signal = mediaController.signal;
    const mediaCache = new Map();
    const queue = [];
    const jobs = new Map();
    let active = 0;
    function pump() {
      while (!signal.aborted && active < 3) {
        let index = queue.findIndex((job) => !job.background);
        if (index < 0 && active < 2 && !document.hidden) index = queue.length ? 0 : -1;
        if (index < 0) return;
        const job = queue.splice(index, 1)[0];
        active++;
        job
          .run()
          .then(job.resolve, job.reject)
          .finally(() => {
            active--;
            pump();
          });
      }
    }
    document.addEventListener('visibilitychange', pump);
    signal.addEventListener(
      'abort',
      () => {
        document.removeEventListener('visibilitychange', pump);
        queue.splice(0).forEach((job) => job.reject(new Error('locked')));
      },
      { once: true },
    );
    async function download(item) {
      for (let attempt = 0; attempt < 3; attempt++) {
        if (signal.aborted) throw new Error('locked');
        const controller = new AbortController();
        const cancel = () => controller.abort();
        signal.addEventListener('abort', cancel, { once: true });
        const timer = setTimeout(cancel, 20000);
        try {
          const response = await fetch(new URL(item.file, siteRoot), {
            signal: controller.signal,
            credentials: 'omit',
          });
          if (!response.ok) throw new Error(`network:${response.status}`);
          return await response.arrayBuffer();
        } catch (error) {
          if (signal.aborted || attempt === 2 || /network:4(?!08|29)/.test(error.message))
            throw error;
        } finally {
          clearTimeout(timer);
          signal.removeEventListener('abort', cancel);
        }
        await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
      }
    }
    window.__PRIVATE_LOAD_ASSET__ = (path, { background = false } = {}) => {
      const item = payload.media?.[path];
      if (
        !item ||
        !/^media\/[a-f0-9]{64}\.enc$/.test(item.file) ||
        !['video/mp4', 'image/webp', 'image/jpeg', 'image/png', 'image/avif'].includes(item.mime)
      )
        return Promise.reject(new Error('media'));
      if (!mediaCache.has(path)) {
        const run = async () => {
          const plain = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: bytes(item.iv) },
            key,
            await download(item),
          );
          if (generation !== currentGeneration) throw new Error('locked');
          const url = URL.createObjectURL(new Blob([plain], { type: item.mime }));
          mediaUrls.push(url);
          return url;
        };
        const pending = new Promise((resolve, reject) => {
          const job = { run, resolve, reject, background };
          jobs.set(path, job);
          queue.push(job);
        })
          .catch((error) => {
            mediaCache.delete(path);
            throw error;
          })
          .finally(() => jobs.delete(path));
        mediaCache.set(path, pending);
      }
      if (!background && jobs.has(path)) jobs.get(path).background = false;
      pump();
      return mediaCache.get(path);
    };
    const font = Array.from(document.styleSheets)
      .flatMap((sheet) => {
        // Встроенный браузер может добавить сторонний CSS с закрытым CSSOM.
        try {
          return Array.from(sheet.cssRules);
        } catch {
          return [];
        }
      })
      .find(
        (rule) => rule.type === CSSRule.FONT_FACE_RULE && rule.style.fontFamily.includes('Araboto'),
      )
      ?.style.getPropertyValue('src')
      .match(/data:font\/ttf;base64,[A-Za-z0-9+/=]+/)?.[0];
    if (!font) throw new Error('font');
    const html = new TextDecoder().decode(plaintext).replaceAll('__PRIVATE_ARABOTO_FONT__', font);
    frame = document.createElement('iframe');
    frame.title = 'Остров нашей истории';
    frame.allow = 'autoplay';
    frame.style.opacity = '0';
    frame.style.pointerEvents = 'none';
    let readyTimer;
    const ready = new Promise((resolve, reject) => {
      window.__PRIVATE_READY__ = resolve;
      cancelStartup = () => reject(new Error('locked'));
      readyTimer = setTimeout(() => reject(new Error('startup')), 30000);
    });
    // Telegram iOS отклоняет навигацию на blob:, но разрешает about:srcdoc.
    // HTML уже проверен AES-GCM и остаётся только в памяти текущего сеанса.
    frame.srcdoc = html;
    password.blur();
    document.body.append(frame);
    try {
      await ready;
    } finally {
      clearTimeout(readyTimer);
      window.__PRIVATE_READY__ = undefined;
      cancelStartup = null;
    }
    if (generation !== currentGeneration) throw new Error('locked');
    if (saved && !validSession(saved)) throw new Error('expired');
    if (!saved) {
      const issuedAt = Date.now();
      const session = {
        version: 2,
        key,
        issuedAt,
        expiresAt: issuedAt + sessionLifetime,
      };
      try {
        await sessionStore(save ? 'put' : 'delete', save ? session : undefined);
        if (save) saved = session;
      } catch {
        /* Запрет хранилища не блокирует обычный вход. */
      }
    }
    if (generation !== currentGeneration) throw new Error('locked');
    sessionExpiresAt = saved?.expiresAt || 0;
    checkExpiry();
    if (generation !== currentGeneration) throw new Error('locked');
    frame.style.opacity = '';
    frame.style.pointerEvents = '';
    gate.hidden = true;
    password.value = '';
    day.value = '';
    status.textContent = '';
    frame.focus();
  } catch (error) {
    if (error.message === 'locked' || generation !== currentGeneration) return;
    payloadRequest = null;
    clearSession();
    const errorGeneration = generation;
    if (saved && ['password', 'expired'].includes(error.message)) {
      await sessionStore('delete', saved).catch(() => {});
    }
    if (generation !== errorGeneration) return;
    status.textContent =
      error.message === 'expired'
        ? 'Прошло 30 дней. Введи дату и пароль ещё раз.'
        : saved && error.message === 'password'
          ? 'Сохранённый вход больше не подходит. Введи дату и пароль ещё раз.'
          : error.message === 'password'
            ? 'Дата или пароль не совпали. Попробуй ещё раз.'
            : error.message === 'startup'
              ? 'Браузер не смог открыть остров. Обнови страницу и попробуй ещё раз.'
              : 'Не получилось загрузить остров. Проверь интернет и попробуй ещё раз.';
    retry.hidden = !saved || ['password', 'expired'].includes(error.message);
    if (!saved) {
      password.focus();
      password.select();
    }
  } finally {
    if (generation === currentGeneration) {
      busy = false;
      button.disabled = false;
    }
  }
}

function clearSession() {
  clearTimeout(expiryTimer);
  sessionExpiresAt = 0;
  generation++;
  cancelStartup?.();
  cancelStartup = null;
  window.__PRIVATE_READY__ = undefined;
  busy = false;
  button.disabled = false;
  status.textContent = '';
  mediaController?.abort();
  mediaController = null;
  window.__PRIVATE_LOAD_ASSET__ = undefined;
  frame?.remove(); // Удаление документа также останавливает видео.
  frame = null;
  mediaUrls.forEach((url) => URL.revokeObjectURL(url));
  mediaUrls = [];
  gate.hidden = false;
  password.value = '';
  day.value = '';
  setPasswordVisible(false);
}
window.addEventListener('pagehide', clearSession);
window.addEventListener('pageshow', (event) => {
  if (event.persisted) restoreAccess();
});
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) checkExpiry();
});
retry.addEventListener('click', restoreAccess);
restoreAccess();
