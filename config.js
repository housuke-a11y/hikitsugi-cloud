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
  // （写真付きの記録を翌日の訪問時にも再送信できるよう、30分から延長）
  UNSENT_EXPIRY_MS: 24 * 60 * 60 * 1000, // 24時間

  // 記録の保存（submitToCloud）の制限時間。GASの応答が止まったまま
  // 「保存しています…」から進まず、待ちきれずに画面を閉じられるのを防ぐ。
  // 写真付きの送信・GAS側の待ち（実測で最大35秒程度）を見込んだ長さにする。
  SAVE_TIMEOUT_MS: 90 * 1000 // 90秒
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
 *
 * timeoutMs（任意）を指定すると、その時間内に応答が届かなければ打ち切り、
 * err.name === 'TimeoutError' のエラーを投げる。POSTは再試行しないため、
 * この場合「GAS側で保存されたかどうかは分からない」ことに注意する。
 */
async function callGas(payload, timeoutMs) {
  if (!CONFIG.GAS_URL) throw new Error('GAS_URL_NOT_SET');
  const ctrl  = timeoutMs ? new AbortController() : null;
  const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
  try {
    const res = await fetch(CONFIG.GAS_URL, {
      method: 'POST',
      body: JSON.stringify(payload),
      signal: ctrl ? ctrl.signal : undefined
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return await res.json();
  } catch (e) {
    if (ctrl && ctrl.signal.aborted) {
      const err = new Error('TIMEOUT');
      err.name = 'TimeoutError';
      throw err;
    }
    throw e;
  } finally {
    if (timer) clearTimeout(timer);
  }
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
 * 保存から UNSENT_EXPIRY_MS（既定24時間）を過ぎた項目は、次回参照時に
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

// 戻り値：保存できたかどうか（true/false）。
// 【写真添付機能】添付写真（base64）が乗ることでpayloadが数MBになり得るため、
// localStorageの容量上限（QuotaExceededError）で保存に失敗するケースが
// 出てくる。呼び出し元（submitToCloud）はこの戻り値を見て、キューにも
// 積めなかった＝この端末のどこにも残っていないことを利用者に伝える。
function saveUnsentQueue(list) {
  try {
    localStorage.setItem(UNSENT_KEY, JSON.stringify(list));
    return true;
  } catch (e) {
    return false;
  }
}

function addUnsentItem(payload, label) {
  const list = getUnsentQueue();
  list.push({ queuedAt: Date.now(), label: label || '', payload: payload });
  return saveUnsentQueue(list);
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
 * （UNSENT_EXPIRY_MS経過後は次回参照時に自動的に取り除かれる）。
 */
async function resendUnsentQueue() {
  const list = getUnsentQueue();
  let successCount = 0, failCount = 0;
  for (const item of list) {
    try {
      const result = await callGas(item.payload, CONFIG.SAVE_TIMEOUT_MS);
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

/* ─── GAS WebAppへのGET呼び出し（共通・キャッシュ回避） ───────────────
 * V2データ一元管理方針は「取得のたびに最新データをフェッチする」だが、
 * 同一URL（?action=xxx）へのGETはブラウザ（特にiOS Safari）や経路上の
 * プロキシにキャッシュされ、再編集直後でも古いレスポンスが返り続けることが
 * ある（例：ピン留めを解除して保存しても、ホーム画面に古い状態が
 * 残り続けて見える）。呼び出しのたびに変わるクエリパラメータを付与することで
 * URL自体を毎回ユニークにし、キャッシュを回避する。
 *
 * 【注意】以前はここに fetch() の cache: 'no-store' オプションも
 * 指定していたが、GAS WebApp（script.google.com/macros/s/…/exec）は
 * 実体のscript.googleusercontent.comへ302リダイレクトする構成になっており、
 * この組み合わせで「クラウドからのデータ取得に失敗しました」（fetch自体が
 * 失敗）という重大な回帰を引き起こした（2026-09-22に発生・即日revert）。
 * クエリパラメータによるURLのユニーク化だけで目的（キャッシュ回避）は
 * 達成できるため、cacheオプションは指定しないこと。
 *
 * 【自動再試行（2026-09-29）】
 * GASの実行結果は別ドメイン（script.googleusercontent.com）から配信されるが、
 * この配信段階が不安定で、スクリプト自体は数秒で完了しているのに
 * 「404 Not Found」が返る／script.google.comへ差し戻されて応答が止まる、
 * ということが確率的に起きる（実測で確認済み。応答が大きいほど起きやすい）。
 * 再度リクエストすればたいてい成功するので、GET（読み取り専用で何度実行しても
 * 安全）に限り、1回ごとに制限時間を設けたうえで自動的に再試行する。
 * ※POST（callGas：記録の保存）は二重登録の恐れがあるため再試行しないこと。
 *
 *
 * 【先回りの取り直し（2026-09-29）】
 * 再測定したところ、ホーム（1KB弱）のような小さい応答でも1回あたりの成功率は
 * 4〜5割しかなく、失敗の多くは「差し戻されたまま応答が止まる」形だった。
 * 制限時間まで待ってから次を出すと、失敗が続くと1分以上待たされるうえ、
 * 3回とも失敗して取得できないことが6回に1回程度起きていた。そこで：
 *   ・応答がないまま GAS_GET_HEDGE_MS 経過したら、最初の通信は待ち続けたまま
 *     もう1本同時に出し、先に届いた方を使う（同時に出すのは最大2本まで）
 *   ・404などですぐ失敗した場合は GAS_GET_RETRY_WAIT_MS 後に取り直す
 *   ・最大 GAS_GET_MAX_ATTEMPTS 本・全体で GAS_GET_TOTAL_MS まで粘る
 * 1本届いた時点で残りの通信は打ち切る。
 *
 * onRetry(attempt, max) … 2本目以降を出すときに呼ばれる（画面に「再試行中」を出すため・任意）
 * query … action以外のパラメータ（例：'&id=xxx&as=base64'・任意）
 */
const GAS_GET_TIMEOUT_MS    = 40000; // 1本あたりの制限時間（止まったままの応答を打ち切る）
const GAS_GET_HEDGE_MS      = 15000; // 応答がないままこの時間が過ぎたら、待ちながらもう1本出す
const GAS_GET_RETRY_WAIT_MS = 1000;  // 失敗（404等）が返ってから次を出すまでの間隔
const GAS_GET_MAX_CONCURRENT = 2;    // 同時に出す通信の上限
const GAS_GET_MAX_ATTEMPTS  = 5;
const GAS_GET_TOTAL_MS      = 90000; // 全体の上限

async function fetchGasOnce(action, query, ctrl) {
  const url = CONFIG.GAS_URL + '?action=' + encodeURIComponent(action) + (query || '') +
    '&_=' + Date.now() + Math.random().toString(36).slice(2, 6); // 同時に出す2本もURLを別にする
  const timer = ctrl ? setTimeout(() => ctrl.abort(), GAS_GET_TIMEOUT_MS) : null;
  try {
    const res = await fetch(url, ctrl ? { signal: ctrl.signal } : undefined);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return await res.json(); // JSONでない応答（エラー画面等）もここで例外になり再試行対象
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function fetchGas(action, onRetry, query) {
  return new Promise((resolve, reject) => {
    const controllers = [];
    let started = 0, inFlight = 0, finished = false, lastErr = null;
    let nextTimer = null, totalTimer = null;

    const finish = (ok, value) => {
      if (finished) return;
      finished = true;
      clearTimeout(nextTimer);
      clearTimeout(totalTimer);
      controllers.forEach(c => { try { c.abort(); } catch (e) {} }); // 残りの通信を打ち切る
      if (ok) resolve(value); else reject(value);
    };

    const scheduleNext = (ms) => {
      clearTimeout(nextTimer);
      nextTimer = setTimeout(launch, ms);
    };

    function launch() {
      if (finished || started >= GAS_GET_MAX_ATTEMPTS) return;
      if (inFlight >= GAS_GET_MAX_CONCURRENT) { scheduleNext(1000); return; } // 空くまで待つ
      started++;
      if (started > 1 && typeof onRetry === 'function') {
        try { onRetry(started, GAS_GET_MAX_ATTEMPTS); } catch (e) {}
      }
      const ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
      if (ctrl) controllers.push(ctrl);
      inFlight++;
      scheduleNext(GAS_GET_HEDGE_MS); // 応答がなければ先回りしてもう1本
      fetchGasOnce(action, query, ctrl).then(
        data => finish(true, data),
        err => {
          inFlight--;
          lastErr = err;
          if (finished) return;
          if (started >= GAS_GET_MAX_ATTEMPTS) {
            if (inFlight === 0) finish(false, lastErr); // 全部失敗
            return;
          }
          if (inFlight === 0) scheduleNext(GAS_GET_RETRY_WAIT_MS); // すぐ取り直す
          // 他の通信が進行中なら、その先回りタイマーに任せる
        }
      );
    }

    totalTimer = setTimeout(() => finish(false, lastErr || new Error('timeout')), GAS_GET_TOTAL_MS);
    launch();
  });
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
    return await fetchGas('settings');
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
async function fetchCloudLog(onRetry) {
  if (!CONFIG.GAS_URL) return null;
  try {
    const data = await fetchGas('log', onRetry);
    if (!Array.isArray(data.records)) return null;
    return data.fields ? data.records.map(r => expandLogRecord(r, data.fields)) : data.records;
  } catch (e) {
    return null;
  }
}

/* GAS側（handleGetLog）は応答サイズを抑えるため空欄の項目を省いて返す
 * （2026-09-29〜）。画面側のコードがこれまでと全く同じ形のデータを扱えるよう、
 * 省かれた項目を元の既定値で復元する。
 *   配列の項目 → []、svcTimes → {}、真偽値の項目 → false、それ以外 → ''
 * savedAt / editedAt は従来から「空なら項目なし」なので復元しない。
 * fields が無い応答（GAS側が旧版のまま）の場合は、そのまま返す。 */
const LOG_ARRAY_FIELDS  = ['svctype', 'done', 'photos'];
const LOG_OBJECT_FIELDS = ['svcTimes'];
const LOG_BOOL_FIELDS   = ['pinned', 'iop_r_na', 'iop_l_na'];

function expandLogRecord(r, fields) {
  const rec = Object.assign({}, r);
  if (!('is_self_report' in rec)) rec.is_self_report = false; // falseは省かれて届く
  const list = rec.is_self_report ? (fields.self || []) : (fields.main || []);
  list.forEach(k => {
    if (k in rec) return;
    if (LOG_ARRAY_FIELDS.indexOf(k) !== -1)       rec[k] = [];
    else if (LOG_OBJECT_FIELDS.indexOf(k) !== -1) rec[k] = {};
    else if (LOG_BOOL_FIELDS.indexOf(k) !== -1)   rec[k] = false;
    else                                          rec[k] = '';
  });
  // svctype・done・svcTimes は本人・家族申告にも従来から付いていた（項目一覧には無い）
  if (!('svctype' in rec))  rec.svctype = [];
  if (!('done' in rec))     rec.done = [];
  if (!('svcTimes' in rec)) rec.svcTimes = {};
  return rec;
}

/* ─── 添付写真の表示（共通） ───────────────────────────────────
 * 写真はGAS経由（?action=photo&id=…）で配信する。ただしGASのURLは実体の
 * ドメインへリダイレクトされ、応答が「ダウンロード用ファイル」として返るため、
 * ブラウザによっては<img>として描画されないことがある（2026-09-27、
 * ヘルパーさんのiOS Chromeで「説明文だけ表示され写真が出ない」症状が発生）。
 *
 * そこで、画像の読み込みに失敗したときだけ ?as=base64 で取り直し、
 * data URLとして表示し直す。今写真が正しく表示できている環境（オーナーの端末・
 * PC等）の挙動は一切変わらないため、副作用なく対応できる。
 * 写真の<img>には data-photo-id と onerror="loadPhotoFallback(this)" を付ける。
 */
function photoUrl(id) {
  return CONFIG.GAS_URL + '?action=photo&id=' + encodeURIComponent(id);
}

async function loadPhotoFallback(img) {
  if (!img || img.dataset.photoFallbackTried) return; // 無限ループ防止（1回だけ試す）
  img.dataset.photoFallbackTried = '1';
  const id = img.dataset.photoId;
  if (!id || !CONFIG.GAS_URL) return;
  try {
    const data = await fetchGas('photo', null, '&id=' + encodeURIComponent(id) + '&as=base64'); // 取得失敗時は自動で取り直す
    if (data && data.ok && data.dataUrl) img.src = data.dataUrl;
  } catch (e) {
    // 取得できなければ画像は表示されないままにする（説明文・記録本文の表示は妨げない）
  }
}

/* ─── クラウド（GAS）への送信共通処理 ─────────────────────────
 * home.html（削除）・hikitsugi_app.html（新規保存・編集）の両方から使う。
 * GAS_URL未設定時：クラウド未接続として何もせず終了。
 * 送信成功時：{ sent: true, queued: false }
 * 送信失敗時：未送信キューに積んで再送信できるようにし、
 *             { sent: false, queued: true, message: '…' } を返す
 *             （ホーム画面の「未送信データが残っています」バナーから
 *             resendUnsentQueue() で再送信できる）。
 *             キューにも積めなかった場合は queued: false。呼び出し元は
 *             入力内容を画面に残し、その場で保存し直せるようにすること。
 *
 * 制限時間（CONFIG.SAVE_TIMEOUT_MS）を過ぎた場合も失敗として扱う。
 * GAS側では保存済みの可能性があるが、同じ記録IDで再送信すれば
 * 過去ログでは1件にまとまる（GAS側で同一idの行は最新の1件だけを返す）。
 */
async function submitToCloud(payload, label) {
  if (!CONFIG.GAS_URL) return { sent: false, queued: false, message: '' };
  try {
    const result = await callGas(payload, CONFIG.SAVE_TIMEOUT_MS);
    if (result && result.ok) return { sent: true, queued: false, message: '' };
    throw new Error((result && result.error) || '送信に失敗しました');
  } catch (e) {
    const reason = (e && e.name === 'TimeoutError')
      ? 'クラウドからの応答がなく、送信できたか確認できませんでした'
      : 'クラウドへの送信に失敗しました';
    const queued = addUnsentItem(payload, label || '');
    if (queued) {
      return {
        sent: false,
        queued: true,
        message: reason + '。この端末に一時保存したので、ホーム画面から再送信してください。'
      };
    }
    // 【写真添付機能】未送信キューへの一時保存自体に失敗した場合
    // （主に添付写真でlocalStorageの容量上限を超えた場合）は、
    // この端末のどこにも記録が残っていない＝再送信もできないことを
    // はっきり伝える（黙って消えたと誤解されないように）。
    return {
      sent: false,
      queued: false,
      message: reason + '。写真データが大きいため、この端末への一時保存もできませんでした。入力内容はこの画面に残してあります。電波の良い場所で、もう一度「保存」を押してください。'
    };
  }
}
