/*
 * config.js
 * 引き継ぎ連絡票クラウド化（V2）設定集約ファイル。
 * GAS WebApp URL・PINハッシュ値・タイムアウト定数・共通ヘルパー関数をここにまとめる。
 * index.html / pin.html / home.html / hikitsugi_app.html / finish.html から読み込む。
 *
 * PIN_HASH_HELPER / PIN_HASH_OWNER は GAS_URL 未設定時のフォールバック用の初期値。
 * GAS_URL 設定後は GAS側 PropertiesService に保存された値が正となり、
 * ここでのPIN変更（設定画面の「PINを変更」）はそちらを更新する。
 * 平文のPINはこのファイルに一切書かないこと。
 */

const CONFIG = {
  // GAS WebAppのデプロイURL（Step 1で取得後に設定する。現時点は未設定）
  GAS_URL: 'https://script.google.com/macros/s/AKfycbwWTlpMvPELqcVu7V7AIg9AxnxelvsgvGqsIg3eUtdWYRdlK4BSgtfAejIGT4GX8Y35/exec',

  // PINハッシュ値（SHA-256・16進数）。仮の初期値：ヘルパー用 1234 / オーナー用 5678
  // 運用開始前に必ず設定画面から変更すること。
  PIN_HASH_HELPER: '03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4',
  PIN_HASH_OWNER:  'f8638b979b2f4f793ddb6dbd197e0ee25a7a6ea32b0ae22f5e3c5d119d839e75',

  // PIN認証：連続失敗の許容回数とロック時間
  PIN_MAX_ATTEMPTS: 3,
  PIN_LOCKOUT_MS: 5 * 60 * 1000, // 5分

  // 無操作による自動ログアウトまでの時間
  SESSION_TIMEOUT_MS: 30 * 60 * 1000, // 30分

  // 送信失敗時の一時保存データを自動削除するまでの時間
  UNSENT_EXPIRY_MS: 30 * 60 * 1000 // 30分
};

/* ─── PINハッシュ化（SubtleCrypto / SHA-256） ─────────────────── */
async function sha256Hex(text) {
  const enc = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/* ─── GAS WebAppへのPOST呼び出し（共通） ───────────────────────
 * GASはContent-Type: application/jsonのPOSTだとCORSプリフライトで失敗するため、
 * Content-Typeを指定せず（ブラウザ既定のtext/plainで）本文にJSON文字列を送る。
 * doPost側は e.postData.contents を JSON.parse して読み取ること。
 * GAS_URL未設定時は呼び出し元でフォールバック処理をすること。
 */
async function callGas(payload) {
  if (!CONFIG.GAS_URL) throw new Error('GAS_URL_NOT_SET');
  const res = await fetch(CONFIG.GAS_URL, {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

/* ─── セッション（ロール保持） ───────────────────────────────
 * sessionStorageを使用：タブ／ブラウザを閉じると自動的に破棄される。
 * finish.html遷移時・タイムアウト時にも明示的にclearSession()を呼ぶこと。
 */
const SESSION_KEY = 'hikitsugi_session';

function setSession(role) {
  try {
    sessionStorage.setItem(SESSION_KEY, JSON.stringify({
      role: role,
      loginAt: Date.now()
    }));
  } catch (e) {}
}

function getSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) { return null; }
}

function clearSession() {
  try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
}

/* ─── PINロックアウト（連続失敗の記録） ───────────────────────
 * ブラウザを閉じてもロックを回避できないよう localStorage を使用する。
 */
const LOCKOUT_KEY = 'hikitsugi_pin_lockout';

function getLockoutState() {
  try {
    const raw = localStorage.getItem(LOCKOUT_KEY);
    return raw ? JSON.parse(raw) : { attempts: 0, lockedUntil: 0 };
  } catch (e) { return { attempts: 0, lockedUntil: 0 }; }
}

function recordFailedAttempt() {
  const state = getLockoutState();
  state.attempts = (state.attempts || 0) + 1;
  if (state.attempts >= CONFIG.PIN_MAX_ATTEMPTS) {
    state.lockedUntil = Date.now() + CONFIG.PIN_LOCKOUT_MS;
    state.attempts = 0;
  }
  try { localStorage.setItem(LOCKOUT_KEY, JSON.stringify(state)); } catch (e) {}
  return state;
}

function isLockedOut() {
  const state = getLockoutState();
  return !!(state.lockedUntil && state.lockedUntil > Date.now());
}

function getLockoutRemainingMs() {
  const state = getLockoutState();
  return Math.max(0, (state.lockedUntil || 0) - Date.now());
}

function clearLockout() {
  try { localStorage.removeItem(LOCKOUT_KEY); } catch (e) {}
}

/* ─── 無操作タイマー（自動ログアウト） ───────────────────────
 * home.html・記録入力画面（hikitsugi_app.html）から共通利用する。
 * 呼び出し側は onTimeout に「finish.htmlへ遷移する処理」を渡す。
 */
function startInactivityTimer(onTimeout) {
  let timer = null;
  const reset = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(onTimeout, CONFIG.SESSION_TIMEOUT_MS);
  };
  ['click', 'keydown', 'touchstart', 'input', 'scroll'].forEach(evt => {
    document.addEventListener(evt, reset, { passive: true });
  });
  reset();
  return () => { if (timer) clearTimeout(timer); };
}

/* ─── 未送信データキュー（送信失敗時の一時保存・再送信） ─────────
 * V2個人情報保護方針：GAS送信に失敗した記録は、再送信できるよう
 * localStorageに一時保存する（＝恒久保存ではなく一時保存）。
 * 保存から UNSENT_EXPIRY_MS（既定30分）を過ぎた項目は、次回参照時に
 * 自動的に取り除かれる（=自動削除。取りこぼし防止のためのタイムスタンプ管理）。
 * 各項目の payload は callGas() にそのまま渡せる形（doPostへ送るJSON）で保持する。
 */
const UNSENT_KEY = 'hikitsugi_unsent_queue';

function getUnsentQueue() {
  let list;
  try {
    const raw = localStorage.getItem(UNSENT_KEY);
    list = raw ? JSON.parse(raw) : [];
  } catch (e) { return []; }

  const cutoff = Date.now() - CONFIG.UNSENT_EXPIRY_MS;
  const kept = list.filter(item => (item.queuedAt || 0) >= cutoff);
  if (kept.length !== list.length) saveUnsentQueue(kept); // 期限切れ分を削除
  return kept;
}

function saveUnsentQueue(list) {
  try { localStorage.setItem(UNSENT_KEY, JSON.stringify(list)); } catch (e) {}
}

function addUnsentItem(payload, label) {
  const list = getUnsentQueue();
  list.push({ queuedAt: Date.now(), label: label || '', payload: payload });
  saveUnsentQueue(list);
}

function removeUnsentItem(queuedAt) {
  saveUnsentQueue(getUnsentQueue().filter(i => i.queuedAt !== queuedAt));
}

function clearUnsentQueue() {
  try { localStorage.removeItem(UNSENT_KEY); } catch (e) {}
}

/* すべての未送信項目の再送信を試みる。
 * 戻り値: { successCount, failCount }
 * 成功した項目はキューから取り除く。失敗した項目はキューに残る
 * （30分経過後は次回参照時に自動的に取り除かれる）。
 */
async function resendUnsentQueue() {
  const list = getUnsentQueue();
  let successCount = 0, failCount = 0;
  for (const item of list) {
    try {
      const result = await callGas(item.payload);
      if (result && result.ok) {
        removeUnsentItem(item.queuedAt);
        successCount++;
      } else {
        failCount++;
      }
    } catch (e) {
      failCount++;
    }
  }
  return { successCount, failCount };
}

/* ─── クラウド設定データ（スケジュール・事業所・担当者） ─────────
 * V2データ一元管理方針：取得のたびに最新データをフェッチする
 * （明示的な更新ボタンを設けない代わりに、参照のたびに再取得する設計）。
 * GAS_URL未設定・通信失敗時はnullを返し、呼び出し元でローカルの
 * キャッシュ値やハードコードのデフォルト値へフォールバックすること。
 */
async function fetchCloudSettings() {
  if (!CONFIG.GAS_URL) return null;
  try {
    const res = await fetch(CONFIG.GAS_URL + '?action=settings');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return await res.json();
  } catch (e) {
    return null;
  }
}

/* key: 'schedule' | 'offices' | 'staff' */
async function saveCloudSetting(key, value) {
  return callGas({ action: 'saveSettings', key: key, value: value });
}

/* ─── クラウド過去ログ（過去ログのクラウド化） ────────────────────
 * 記録データ（要配慮個人情報）は端末に恒久保存しないというV2個人情報保護方針に
 * 従い、過去ログは常にここでクラウドから取得する。取得に失敗した場合は
 * （オフライン用のローカルキャッシュには意図的にフォールバックせず）nullを返す。
 * 呼び出し元は「取得できませんでした」というエラー状態を表示すること。
 */
async function fetchCloudLog() {
  if (!CONFIG.GAS_URL) return null;
  try {
    const res = await fetch(CONFIG.GAS_URL + '?action=log');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    return Array.isArray(data.records) ? data.records : null;
  } catch (e) {
    return null;
  }
}

/* ─── クラウド（GAS）への送信共通処理 ─────────────────────────
 * home.html（削除）・hikitsugi_app.html（新規保存・編集）の両方から使う。
 * GAS_URL未設定時：クラウド未接続として何もせず終了。
 * 送信成功時：{ sent: true }
 * 送信失敗時：未送信キューに積んで再送信できるようにし、
 *             { sent: false, message: '…' } を返す
 *             （ホーム画面の「未送信データが残っています」バナーから
 *             resendUnsentQueue() で再送信できる）。
 */
async function submitToCloud(payload, label) {
  if (!CONFIG.GAS_URL) return { sent: false, message: '' };
  try {
    const result = await callGas(payload);
    if (result && result.ok) return { sent: true, message: '' };
    throw new Error((result && result.error) || '送信に失敗しました');
  } catch (e) {
    addUnsentItem(payload, label || '');
    return {
      sent: false,
      message: 'クラウドへの送信に失敗したため、この端末に一時保存しました。ホーム画面から再送信してください。'
    };
  }
}
