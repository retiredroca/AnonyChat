'use strict';

// ═══════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════
const state = {
  me: null,       // { handle, publicKeyPem, signingKey, fingerprint, algo }
  channel: 'general',
  messages: {},   // channel -> [msg]
  generatedPrivPem: null,
  generatedPubPem:  null,
  generatedCryptoKeys: null,
  generatedAlgo: null,
};

const CHANNEL_DESCS = {
  general: 'Public broadcast channel — messages signed with your key',
  random:  'Off-topic discussion',
  tech:    'Technical talk',
};

// ═══════════════════════════════════════════════════════
// CRYPTO
// ═══════════════════════════════════════════════════════

async function generateECDSA(namedCurve) {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign', 'verify']);
}

async function generateRSAPSS() {
  return crypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
    true, ['sign', 'verify']
  );
}

async function exportPrivPem(key) { return toPem(await crypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY'); }
async function exportPubPem(key)  { return toPem(await crypto.subtle.exportKey('spki',  key), 'PUBLIC KEY'); }

function toPem(buffer, label) {
  const b64   = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function fromPem(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

async function importPrivateKey(pem) {
  const der  = fromPem(pem);
  const algos = [
    { name: 'ECDSA', namedCurve: 'P-256' },
    { name: 'ECDSA', namedCurve: 'P-384' },
    { name: 'RSA-PSS', hash: 'SHA-256' },
  ];
  for (const alg of algos) {
    try {
      const key = await crypto.subtle.importKey('pkcs8', der, alg, true, ['sign']);
      const pub = await derivePublicFromPrivate(key, alg);
      return { privateKey: key, publicKey: pub, algorithm: alg };
    } catch { /* try next */ }
  }
  throw new Error('Unrecognised key format');
}

async function derivePublicFromPrivate(privateKey, alg) {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  delete jwk.d;
  const pubAlg = alg.name === 'ECDSA'
    ? { name: 'ECDSA', namedCurve: alg.namedCurve }
    : { name: 'RSA-PSS', hash: 'SHA-256' };
  return crypto.subtle.importKey('jwk', jwk, pubAlg, true, ['verify']);
}

async function fingerprint(pubKeyPem) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pubKeyPem));
  return Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function signMessage(text, privateKey, alg) {
  const enc    = new TextEncoder().encode(text);
  const sigAlg = alg.name === 'ECDSA' ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSA-PSS', saltLength: 32 };
  const sig    = await crypto.subtle.sign(sigAlg, privateKey, enc);
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function verifyMessage(text, sigB64, pubKeyPem, alg) {
  try {
    const enc    = new TextEncoder().encode(text);
    const sig    = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
    const pubAlg = alg.name === 'ECDSA' ? { name: 'ECDSA', namedCurve: alg.namedCurve } : { name: 'RSA-PSS', hash: 'SHA-256' };
    const key    = await crypto.subtle.importKey('spki', fromPem(pubKeyPem), pubAlg, false, ['verify']);
    const verAlg = alg.name === 'ECDSA' ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSA-PSS', saltLength: 32 };
    return crypto.subtle.verify(verAlg, key, sig, enc);
  } catch { return false; }
}

// ═══════════════════════════════════════════════════════
// KEY GENERATION
// ═══════════════════════════════════════════════════════

async function generateKeys() {
  const username = $('reg-username').value.trim();
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
    toast('Handle must be 3–32 chars: letters, numbers, underscores');
    return;
  }

  const algo = $('reg-algo').value;
  const btn  = $('btn-gen');
  btn.disabled   = true;
  btn.innerHTML  = '<span class="spinner"></span>GENERATING...';

  $('key-gen-area').classList.remove('hidden');
  animateProgress(0, 40, 600);

  let keys;
  try {
    if      (algo === 'ECDSA-P256') keys = await generateECDSA('P-256');
    else if (algo === 'ECDSA-P384') keys = await generateECDSA('P-384');
    else                            keys = await generateRSAPSS();
  } catch (e) {
    toast('Key generation failed: ' + e.message);
    btn.disabled  = false;
    btn.innerHTML = 'GENERATE KEYPAIR';
    return;
  }

  animateProgress(40, 80, 400);
  const privPem = await exportPrivPem(keys.privateKey);
  const pubPem  = await exportPubPem(keys.publicKey);
  animateProgress(80, 100, 300);

  state.generatedPrivPem    = privPem;
  state.generatedPubPem     = pubPem;
  state.generatedCryptoKeys = keys;
  state.generatedAlgo = algo.startsWith('ECDSA')
    ? { name: 'ECDSA', namedCurve: algo === 'ECDSA-P256' ? 'P-256' : 'P-384' }
    : { name: 'RSA-PSS', hash: 'SHA-256' };

  $('priv-key-display').textContent = privPem;
  $('pub-key-display').textContent  = pubPem;

  btn.classList.add('hidden');
  const activateBtn = $('btn-activate');
  activateBtn.classList.remove('hidden');
  activateBtn.disabled = true;

  $('confirm-saved').onchange = function () {
    activateBtn.disabled = !this.checked;
  };
}

function animateProgress(from, to, ms) {
  const fill  = $('gen-progress');
  const start = Date.now();
  const tick  = () => {
    const t = Math.min(1, (Date.now() - start) / ms);
    fill.style.width = (from + (to - from) * t) + '%';
    if (t < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

async function activateAccount() {
  const username = $('reg-username').value.trim();
  const fp       = await fingerprint(state.generatedPubPem);

  const userRecord = {
    handle: username, publicKeyPem: state.generatedPubPem,
    fingerprint: fp,  algo: state.generatedAlgo, registeredAt: Date.now(),
  };
  const users = getStoredUsers();
  users[fp]   = userRecord;
  localStorage.setItem('cipher_users', JSON.stringify(users));

  state.me = {
    handle: username, publicKeyPem: state.generatedPubPem,
    signingKey: state.generatedCryptoKeys.privateKey,
    fingerprint: fp,  algo: state.generatedAlgo,
  };

  // Discard private key from memory
  state.generatedPrivPem    = null;
  state.generatedCryptoKeys = null;

  closeModal();
  onAuthenticated();
  sysMsg(username + ' joined the network.');
  toast('Authenticated as ' + username);
}

// ═══════════════════════════════════════════════════════
// IMPORT KEY
// ═══════════════════════════════════════════════════════

async function importKey() {
  const privPem          = $('login-privkey').value.trim();
  const usernameOverride = $('login-username').value.trim();
  hideLoginError();

  if (!privPem) { showLoginError('Paste your private key.'); return; }

  let keyData;
  try {
    keyData = await importPrivateKey(privPem);
  } catch (e) {
    showLoginError('Could not parse key: ' + e.message);
    return;
  }

  const pubPem = await exportPubPem(keyData.publicKey);
  const fp     = await fingerprint(pubPem);
  const users  = getStoredUsers();
  const handle = usernameOverride || (users[fp] && users[fp].handle) || 'user_' + fp.slice(0, 6);

  users[fp] = { handle, publicKeyPem: pubPem, fingerprint: fp, algo: keyData.algorithm };
  localStorage.setItem('cipher_users', JSON.stringify(users));

  state.me = { handle, publicKeyPem: pubPem, signingKey: keyData.privateKey, fingerprint: fp, algo: keyData.algorithm };

  closeModal();
  onAuthenticated();
  sysMsg(handle + ' connected.');
  toast('Signed in as ' + handle);
}

function showLoginError(msg) {
  const el = $('login-error');
  el.textContent = '// ERROR: ' + msg;
  el.classList.remove('hidden');
}

function hideLoginError() { $('login-error').classList.add('hidden'); }

// ═══════════════════════════════════════════════════════
// MESSAGING
// ═══════════════════════════════════════════════════════

async function sendMessage() {
  if (!state.me) return;
  const input = $('msg-input');
  const text  = input.value.trim();
  if (!text) return;
  input.value = '';

  const ts      = Date.now();
  const payload = JSON.stringify({ text, channel: state.channel, author: state.me.fingerprint, ts });
  const sig     = await signMessage(payload, state.me.signingKey, state.me.algo);

  const msg = {
    text, author: state.me.handle, fingerprint: state.me.fingerprint,
    publicKeyPem: state.me.publicKeyPem, algo: state.me.algo,
    sig, payload, ts, channel: state.channel, verified: true,
  };

  if (!state.messages[state.channel]) state.messages[state.channel] = [];
  state.messages[state.channel].push(msg);

  renderMessage(msg);
  scrollToBottom();
  persistMessage(msg);
}

function persistMessage(msg) {
  try {
    const key    = 'cipher_msgs_' + msg.channel;
    const stored = JSON.parse(localStorage.getItem(key) || '[]');
    stored.push({
      text: msg.text, author: msg.author, fingerprint: msg.fingerprint,
      publicKeyPem: msg.publicKeyPem, algo: msg.algo,
      sig: msg.sig, payload: msg.payload, ts: msg.ts, channel: msg.channel,
    });
    if (stored.length > 200) stored.splice(0, stored.length - 200);
    localStorage.setItem(key, JSON.stringify(stored));
  } catch { /* storage full or unavailable */ }
}

async function loadChannelHistory(channel) {
  try {
    const stored = JSON.parse(localStorage.getItem('cipher_msgs_' + channel) || '[]');
    for (const msg of stored) {
      const verified = await verifyMessage(msg.payload, msg.sig, msg.publicKeyPem, msg.algo);
      renderMessage({ ...msg, verified });
    }
  } catch { /* corrupt history */ }
}

function renderMessage(msg) {
  const hint = document.getElementById('no-login-hint');
  if (hint) hint.remove();

  const isMe = state.me && msg.fingerprint === state.me.fingerprint;
  const time = new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const div = document.createElement('div');
  div.className = 'msg';

  const meta = document.createElement('div');
  meta.className = 'msg-meta';

  const author = document.createElement('span');
  author.className = 'msg-author' + (isMe ? ' me' : (msg.author === 'SYSTEM' ? ' system' : ''));
  author.title     = 'Fingerprint: ' + (msg.fingerprint || '');
  author.textContent = msg.author;

  const timeEl = document.createElement('span');
  timeEl.className   = 'msg-time';
  timeEl.textContent = time;

  meta.appendChild(author);
  meta.appendChild(timeEl);

  if (msg.verified !== undefined) {
    const sig = document.createElement('span');
    sig.className = 'msg-sig';
    const icon = document.createElement('span');
    icon.className   = 'verified-icon';
    icon.textContent = msg.verified ? '✓' : '✗';
    sig.appendChild(icon);
    sig.appendChild(document.createTextNode(msg.verified ? 'SIGNED' : 'INVALID'));
    meta.appendChild(sig);
  }

  const body = document.createElement('div');
  body.className   = 'msg-body' + (msg.author === 'SYSTEM' ? ' system' : '');
  body.textContent = msg.text;

  div.appendChild(meta);
  div.appendChild(body);
  $('messages').appendChild(div);
}

function sysMsg(text) {
  renderMessage({ text, author: 'SYSTEM', fingerprint: '', ts: Date.now(), channel: state.channel });
  scrollToBottom();
}

function scrollToBottom() {
  const m = $('messages');
  m.scrollTop = m.scrollHeight;
}

// ═══════════════════════════════════════════════════════
// IDENTITY EXPORT / IMPORT
// ═══════════════════════════════════════════════════════

function exportIdentity() {
  if (!state.me) { toast('Sign in first'); return; }
  downloadJSON({
    cipher_version: 1, type: 'public_identity',
    handle: state.me.handle, fingerprint: state.me.fingerprint,
    publicKeyPem: state.me.publicKeyPem, algo: state.me.algo,
    exportedAt: new Date().toISOString(),
    note: 'Public key only. Safe to share. Keep your private key secret.',
  }, 'cipher-identity-' + state.me.handle + '.json');
  toast('Public identity exported');
}

function exportFullBackup() {
  if (!state.me) { toast('Sign in first'); return; }
  const users    = getStoredUsers();
  const channels = ['general', 'random', 'tech'].reduce((acc, ch) => {
    try { acc[ch] = JSON.parse(localStorage.getItem('cipher_msgs_' + ch) || '[]'); } catch {}
    return acc;
  }, {});
  downloadJSON({
    cipher_version: 1, type: 'full_backup',
    myFingerprint: state.me.fingerprint,
    exportedAt: new Date().toISOString(),
    users, channels,
    note: 'Public keys + message history only. Private key NOT included.',
  }, 'cipher-backup-' + state.me.handle + '-' + Date.now() + '.json');
  toast('Full backup exported (' + Object.values(users).length + ' users)');
}

function downloadJSON(data, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a   = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ── Drag & drop ──

function handleDragOver(e) {
  e.preventDefault();
  $('drop-zone').classList.add('drag-over');
}

function handleDragLeave() {
  $('drop-zone').classList.remove('drag-over');
}

function handleDrop(e) {
  e.preventDefault();
  $('drop-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) readIdentityFile(file);
}

function readIdentityFile(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    try   { applyIdentityFile(JSON.parse(e.target.result)); }
    catch { showLoginError('Could not parse file — expected JSON.'); }
  };
  reader.readAsText(file);
}

function applyIdentityFile(data) {
  if (!data.cipher_version) { showLoginError('Not a CIPHER//NET identity file.'); return; }

  if (data.type === 'full_backup') {
    if (data.users) {
      localStorage.setItem('cipher_users', JSON.stringify({ ...getStoredUsers(), ...data.users }));
    }
    if (data.channels) {
      for (const [ch, msgs] of Object.entries(data.channels)) {
        if (Array.isArray(msgs) && msgs.length)
          localStorage.setItem('cipher_msgs_' + ch, JSON.stringify(msgs));
      }
    }
    updateUserList();
    toast('Backup restored — paste your private key to sign in');
    if (data.myFingerprint && data.users && data.users[data.myFingerprint])
      $('login-username').value = data.users[data.myFingerprint].handle;
    showIdentityPreview({ type: 'full_backup', userCount: Object.keys(data.users || {}).length });
    return;
  }

  if (data.handle)    $('login-username').value = data.handle;
  if (data.fingerprint && data.publicKeyPem) {
    const users = getStoredUsers();
    users[data.fingerprint] = { handle: data.handle, publicKeyPem: data.publicKeyPem, fingerprint: data.fingerprint, algo: data.algo };
    localStorage.setItem('cipher_users', JSON.stringify(users));
    updateUserList();
  }
  showIdentityPreview(data);
  toast('Identity file loaded — paste your private key to sign in');
}

function showIdentityPreview(data) {
  const el = $('identity-preview');
  el.classList.remove('hidden');
  el.innerHTML = '';

  const label = document.createElement('div');
  label.className   = 'ip-label';
  label.textContent = data.type === 'full_backup' ? '// FULL BACKUP LOADED' : '// IDENTITY FILE LOADED';
  el.appendChild(label);

  if (data.type === 'full_backup') {
    el.appendChild(document.createTextNode(data.userCount + ' user(s) restored. Paste your private key below to authenticate.'));
  } else {
    const handle = document.createElement('div');
    handle.textContent = 'Handle: ' + (data.handle || '?');
    const fp = document.createElement('div');
    fp.className   = 'ip-fp';
    fp.textContent = 'Fingerprint: ' + (data.fingerprint || '?');
    const note = document.createElement('div');
    note.textContent = 'Paste your private key below to complete sign-in.';
    el.appendChild(handle); el.appendChild(fp); el.appendChild(note);
  }
}

// ── Storage warning ──

function showStorageWarning() {
  if (sessionStorage.getItem('cipher_warn_dismissed')) return;
  $('storage-warning').classList.remove('hidden');
}

function dismissStorageWarning() {
  $('storage-warning').classList.add('hidden');
  sessionStorage.setItem('cipher_warn_dismissed', '1');
}

// ═══════════════════════════════════════════════════════
// CHANNEL & USER MANAGEMENT
// ═══════════════════════════════════════════════════════

function switchChannel(ch) {
  state.channel = ch;
  document.querySelectorAll('.channel-item').forEach(el => {
    el.classList.toggle('active', el.dataset.channel === ch);
  });
  $('channel-title').textContent = '# ' + ch;
  $('channel-desc').textContent  = CHANNEL_DESCS[ch] || '';
  $('messages').innerHTML = '';
  loadChannelHistory(ch);
  updateMsgInput();
}

function onAuthenticated() {
  updateMsgInput();
  updateUserBadge();
  updateUserList();
  $('messages').innerHTML = '';
  loadChannelHistory(state.channel);
  $('auth-btn').textContent = '[ ' + state.me.handle.toUpperCase() + ' // ONLINE ]';
  $('identity-actions').classList.remove('hidden');
  $('identity-actions').classList.add('visible');
  showStorageWarning();
}

function updateMsgInput() {
  const authed = !!state.me;
  $('msg-input').disabled  = !authed;
  $('btn-send').disabled   = !authed;
  $('msg-input').placeholder = authed
    ? 'Message #' + state.channel + ' — signed with your key'
    : 'You must be authenticated to send messages...';
  $('input-hint').textContent = authed
    ? '> AUTHENTICATED AS ' + state.me.handle.toUpperCase() + ' · MESSAGES CRYPTOGRAPHICALLY SIGNED · FINGERPRINT: ' + state.me.fingerprint
    : '> NOT AUTHENTICATED — MESSAGES ARE READ-ONLY';
}

function updateUserBadge() {
  if (!state.me) return;
  const badge = $('user-badge');
  badge.classList.remove('hidden');
  badge.classList.add('visible');
  badge.innerHTML = '';

  const dot = document.createElement('span');
  dot.className = 'dot active';
  const name = document.createTextNode(state.me.handle + ' ');
  const fp   = document.createElement('span');
  fp.className   = 'badge-fp';
  fp.textContent = state.me.fingerprint;

  badge.appendChild(dot);
  badge.appendChild(name);
  badge.appendChild(fp);
}

function updateUserList() {
  const users   = getStoredUsers();
  const list    = $('user-list');
  list.innerHTML = '';
  const entries = Object.values(users);

  if (!entries.length) {
    const empty = document.createElement('div');
    empty.className   = 'user-empty';
    empty.textContent = 'No users';
    list.appendChild(empty);
    return;
  }

  entries.forEach(u => {
    const isMe = state.me && u.fingerprint === state.me.fingerprint;
    const div  = document.createElement('div');
    div.className = 'user-item' + (isMe ? ' me' : '');
    div.title     = 'Fingerprint: ' + u.fingerprint;

    const dot = document.createElement('span');
    dot.className = 'user-dot' + (isMe ? ' online' : '');

    const name = document.createTextNode(u.handle);

    const fp = document.createElement('span');
    fp.className   = 'user-fp';
    fp.textContent = u.fingerprint.slice(0, 6);

    div.appendChild(dot);
    div.appendChild(name);
    div.appendChild(fp);
    list.appendChild(div);
  });

  document.querySelectorAll('.online-count').forEach(el => el.textContent = entries.length);
}

function getStoredUsers() {
  try { return JSON.parse(localStorage.getItem('cipher_users') || '{}'); }
  catch { return {}; }
}

// ═══════════════════════════════════════════════════════
// MODAL
// ═══════════════════════════════════════════════════════

function openAuthModal() { $('auth-modal').classList.remove('hidden'); }
function closeModal()    { $('auth-modal').classList.add('hidden'); }

function switchTab(tab) {
  $('tab-register').classList.toggle('active', tab === 'register');
  $('tab-login').classList.toggle('active',    tab === 'login');
  $('panel-register').classList.toggle('hidden', tab !== 'register');
  $('panel-login').classList.toggle('hidden',    tab === 'register');
}

function copyKey(which) {
  const text = which === 'priv' ? state.generatedPrivPem : state.generatedPubPem;
  if (!text) return;
  navigator.clipboard.writeText(text)
    .then(()  => toast('Copied to clipboard'))
    .catch(() => {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      toast('Copied');
    });
}

// ═══════════════════════════════════════════════════════
// TOAST
// ═══════════════════════════════════════════════════════

let toastTimer;
function toast(msg) {
  const el = $('toast');
  el.textContent = '// ' + msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2800);
}

// ═══════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════

function $(id) { return document.getElementById(id); }

// ═══════════════════════════════════════════════════════
// WIRE UP ALL EVENT LISTENERS
// ═══════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {

  // Header / auth
  $('auth-btn').addEventListener('click', openAuthModal);
  $('hint-auth-btn').addEventListener('click', openAuthModal);

  // Storage warning
  $('warn-export-btn').addEventListener('click', exportIdentity);
  $('dismiss-warn-btn').addEventListener('click', dismissStorageWarning);

  // Identity actions
  $('btn-export-identity').addEventListener('click', exportIdentity);
  $('btn-export-backup').addEventListener('click', exportFullBackup);

  // Channel switching
  document.querySelectorAll('.channel-item').forEach(el => {
    el.addEventListener('click', () => switchChannel(el.dataset.channel));
  });

  // Message input
  $('msg-input').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
  $('btn-send').addEventListener('click', sendMessage);

  // Modal tabs
  $('tab-register').addEventListener('click', () => switchTab('register'));
  $('tab-login').addEventListener('click',    () => switchTab('login'));

  // Register flow
  $('btn-gen').addEventListener('click', generateKeys);
  $('btn-activate').addEventListener('click', activateAccount);
  $('cancel-register-btn').addEventListener('click', closeModal);
  $('copy-priv-btn').addEventListener('click', () => copyKey('priv'));
  $('copy-pub-btn').addEventListener('click',  () => copyKey('pub'));

  // Login flow
  $('btn-import').addEventListener('click', importKey);
  $('cancel-login-btn').addEventListener('click', closeModal);

  // File drop zone
  const dz = $('drop-zone');
  dz.addEventListener('click',      () => $('identity-file-input').click());
  dz.addEventListener('dragover',   handleDragOver);
  dz.addEventListener('dragleave',  handleDragLeave);
  dz.addEventListener('drop',       handleDrop);
  $('identity-file-input').addEventListener('change', e => {
    if (e.target.files[0]) readIdentityFile(e.target.files[0]);
  });

  // Escape closes modal
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

  // ─── INIT ───
  if (!window.crypto || !window.crypto.subtle) {
    sysMsg('⚠ Web Crypto API not available. Use HTTPS, a .onion address, or localhost.');
    $('auth-btn').disabled = true;
  } else {
    loadChannelHistory(state.channel);
    updateUserList();
    sysMsg('CIPHER//NET initialised. Messages signed via Web Crypto API. Private keys never transmitted.');
  }
});
