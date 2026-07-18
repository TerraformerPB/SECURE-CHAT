const OTP_KEY_SIZE = 65536;
const OTP_RENEW_THRESHOLD = 0.8;

let ws = null;
let myUserId = null;
let myUsername = null;
let myKeyPair = null;
let activeUserId = null;
let activeUsername = null;
let userMap = {};
let otpExchangeInProgress = false;
const sharedKeys = {};
const otpSendStores = {};
const otpRecvStores = {};
const messageHistories = {};
const receivedNonces = {};
const storageKeys = {};
const storageEnabled = {};

const loginContainer = document.getElementById('login-container');
const chatContainer = document.getElementById('chat-container');
const usernameInput = document.getElementById('username-input');
const serverInput = document.getElementById('server-input');
const connectBtn = document.getElementById('connect-btn');
const loginStatus = document.getElementById('login-status');
const userList = document.getElementById('user-list');
const messagesContainer = document.getElementById('messages-container');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const chatStatus = document.getElementById('chat-status');
const chatPartnerName = document.getElementById('chat-partner-name');
const partnerStatus = document.getElementById('partner-status');
const emergencyDeleteBtn = document.getElementById('emergency-delete-btn');
const deleteModal = document.getElementById('delete-modal');
const deleteCancelBtn = document.getElementById('delete-cancel-btn');
const deleteConfirmBtn = document.getElementById('delete-confirm-btn');
const e2eBadge = document.getElementById('e2e-badge');
const storageToggleBtn = document.getElementById('storage-toggle-btn');
const storageConsentModal = document.getElementById('storage-consent-modal');
const storageConsentText = document.getElementById('storage-consent-text');
const storageConsentAccept = document.getElementById('storage-consent-accept');
const storageConsentDeny = document.getElementById('storage-consent-deny');
let pendingStorageConsentFrom = null;

let activeGroupId = null;
const groupKeys = {};
const groupHistories = {};
const myGroups = {};
const fileChunks = {};
const CHUNK_SIZE = 65536;

const fileInput = document.getElementById('file-input');
const fileBtn = document.getElementById('file-btn');

const createGroupBtn = document.getElementById('create-group-btn');
const groupModal = document.getElementById('group-modal');
const groupNameInput = document.getElementById('group-name-input');
const groupMemberList = document.getElementById('group-member-list');
const groupCancelBtn = document.getElementById('group-cancel-btn');
const groupCreateBtn = document.getElementById('group-create-btn');
const groupListEl = document.getElementById('group-list');

connectBtn.addEventListener('click', connect);
usernameInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') connect(); });

sendBtn.addEventListener('click', sendMessage);
messageInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});

emergencyDeleteBtn.addEventListener('click', () => {
  deleteModal.style.display = 'flex';
});

deleteCancelBtn.addEventListener('click', () => {
  deleteModal.style.display = 'none';
});

deleteConfirmBtn.addEventListener('click', () => {
  deleteModal.style.display = 'none';
  performEmergencyDelete();
});

storageToggleBtn.addEventListener('click', toggleStorage);
storageConsentAccept.addEventListener('click', acceptStorageConsent);
storageConsentDeny.addEventListener('click', denyStorageConsent);

createGroupBtn.addEventListener('click', openGroupModal);
groupCancelBtn.addEventListener('click', () => groupModal.style.display = 'none');
groupCreateBtn.addEventListener('click', createGroup);

fileBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', sendFiles);

async function connect() {
  const username = usernameInput.value.trim();
  const serverUrl = serverInput.value.trim();
  if (!username) { loginStatus.textContent = 'Bitte Benutzernamen eingeben'; return; }
  const wsUrl = serverUrl || `ws://${location.host}`;

  myUsername = username;
  loginStatus.textContent = 'Verbinde...';
  connectBtn.disabled = true;

  try {
    myKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true, ['deriveKey', 'deriveBits']
    );
    const myPublicKey = await exportPublicKey(myKeyPair);
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      ws.send(JSON.stringify({
        type: 'register',
        username: myUsername,
        publicKey: myPublicKey
      }));
    };

    ws.onmessage = async (event) => {
      const msg = JSON.parse(event.data);
      await handleServerMessage(msg);
    };

    ws.onclose = () => {
      loginContainer.style.display = 'flex';
      chatContainer.style.display = 'none';
      loginStatus.textContent = 'Verbindung getrennt.';
      connectBtn.disabled = false;
      setOfflineStatus();
    };

    ws.onerror = () => {
      loginStatus.textContent = 'Verbindungsfehler.';
      connectBtn.disabled = false;
    };

  } catch (e) {
    loginStatus.textContent = 'Fehler: ' + e.message;
    connectBtn.disabled = false;
  }
}

async function exportPublicKey(keyPair) {
  const exported = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return { x: exported.x, y: exported.y };
}

async function importPublicKey(jwk) {
  return await crypto.subtle.importKey(
    'jwk', { ...jwk, kty: 'EC', crv: 'P-384', ext: true },
    { name: 'ECDH', namedCurve: 'P-384' },
    false, []
  );
}

async function deriveSharedKey(publicKeyJwk) {
  const theirPublic = await importPublicKey(publicKeyJwk);
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: theirPublic },
    myKeyPair.privateKey, 384
  );
  const hash = await crypto.subtle.digest('SHA-256', sharedBits);
  return await crypto.subtle.importKey(
    'raw', hash, { name: 'AES-GCM' },
    false, ['encrypt', 'decrypt']
  );
}

function getSharedKey(userId) { return sharedKeys[userId] || null; }
function setSharedKey(userId, key) { sharedKeys[userId] = key; }
function deleteSharedKey(userId) { delete sharedKeys[userId]; }

function getOTPSendStore(userId) { return otpSendStores[userId] || null; }
function getOTPRecvStore(userId) { return otpRecvStores[userId] || null; }
function saveOTPSendStore(userId, store) { otpSendStores[userId] = store; }
function saveOTPRecvStore(userId, store) { otpRecvStores[userId] = store; }

let msgCounter = 0;

function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

async function aesEncryptOnly(userId, plaintext) {
  const key = getSharedKey(userId);
  if (!key) throw new Error('Kein shared key');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  return { iv: arrayBufferToBase64(iv), data: arrayBufferToBase64(ciphertext) };
}

async function aesDecryptOnly(userId, ivBase64, dataBase64) {
  const key = getSharedKey(userId);
  if (!key) throw new Error('Kein shared key');
  const iv = base64ToArrayBuffer(ivBase64);
  const data = base64ToArrayBuffer(dataBase64);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return new TextDecoder().decode(plaintext);
}

async function encryptMessageFor(userId, plaintext) {
  const key = getSharedKey(userId);
  if (!key) throw new Error('Kein shared key');

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const aesCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  const otpStore = getOTPSendStore(userId);
  if (!otpStore) throw new Error('OTP-Send fehlt');

  const aesBytes = new Uint8Array(aesCiphertext);
  if (otpStore.offset + aesBytes.length > otpStore.data.length)
    throw new Error('OTP-Send aufgebraucht');

  const otpChunk = new Uint8Array(otpStore.data.slice(otpStore.offset, otpStore.offset + aesBytes.length));
  const otpCiphertext = xorBytes(aesBytes, otpChunk);
  otpStore.offset += aesBytes.length;
  saveOTPSendStore(userId, otpStore);

  return { iv: arrayBufferToBase64(iv), data: arrayBufferToBase64(otpCiphertext) };
}

async function decryptMessageFrom(userId, ivBase64, dataBase64) {
  const key = getSharedKey(userId);
  if (!key) throw new Error('Kein shared key');

  const iv = base64ToArrayBuffer(ivBase64);
  const otpCiphertext = new Uint8Array(base64ToArrayBuffer(dataBase64));

  const otpStore = getOTPRecvStore(userId);
  if (!otpStore) throw new Error('OTP-Recv fehlt');

  if (otpStore.offset + otpCiphertext.length > otpStore.data.length)
    throw new Error('OTP-Recv aufgebraucht');

  const otpChunk = new Uint8Array(otpStore.data.slice(otpStore.offset, otpStore.offset + otpCiphertext.length));
  const aesCiphertext = xorBytes(otpCiphertext, otpChunk);
  otpStore.offset += otpCiphertext.length;
  saveOTPRecvStore(userId, otpStore);

  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, aesCiphertext);
  return new TextDecoder().decode(plaintext);
}

async function restoreStorageState(forUserId) {
  const raw = localStorage.getItem('schistory_' + forUserId);
  if (!raw) return;
  try {
    const sk = await deriveStorageKey(forUserId);
    if (!sk) return;
    const { iv, ct } = JSON.parse(raw);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToArrayBuffer(iv) }, sk, base64ToArrayBuffer(ct));
    const history = JSON.parse(new TextDecoder().decode(plaintext));
    messageHistories[forUserId] = history;
    storageEnabled[forUserId] = true;
    if (forUserId === activeUserId) {
      storageToggleBtn.classList.add('active');
      storageToggleBtn.title = 'Chat-Verlauf wird gespeichert';
    }
  } catch { }
}

async function initiateOTPExchange(forUserId) {
  const uid = forUserId || activeUserId;
  if (!uid || otpExchangeInProgress) return;
  otpExchangeInProgress = true;

  const existing = getOTPSendStore(uid);
  if (existing && existing.offset < existing.data.length) {
    otpExchangeInProgress = false;
    finalizeOTPSetup(uid);
    return;
  }

  chatStatus.textContent = 'Generiere OTP (64 KB)...';
  const otpBytes = crypto.getRandomValues(new Uint8Array(OTP_KEY_SIZE));
  saveOTPSendStore(uid, { data: Array.from(otpBytes), offset: 0 });

  const encrypted = await aesEncryptOnly(uid, JSON.stringify({ data: Array.from(otpBytes) }));
  ws.send(JSON.stringify({
    type: 'direct_message', targetUserId: uid,
    subType: 'otp_exchange',
    encryptedData: encrypted.data, iv: encrypted.iv, timestamp: Date.now()
  }));

  if (uid === activeUserId)
    chatStatus.textContent = 'OTP gesendet, warte auf Antwort...';
}

async function handleOTPExchange(msg) {
  const uid = msg.senderUserId;
  if (!uid) return;

  const existingRecv = getOTPRecvStore(uid);
  if (!existingRecv || existingRecv.offset >= existingRecv.data.length) {
    try {
      const decrypted = await aesDecryptOnly(uid, msg.iv, msg.encryptedData);
      const otpData = JSON.parse(decrypted);
      saveOTPRecvStore(uid, { data: otpData.data, offset: 0 });

      if (!getOTPSendStore(uid)) {
        const otpBytes = crypto.getRandomValues(new Uint8Array(OTP_KEY_SIZE));
        saveOTPSendStore(uid, { data: Array.from(otpBytes), offset: 0 });
        const encrypted = await aesEncryptOnly(uid, JSON.stringify({ data: Array.from(otpBytes) }));
        ws.send(JSON.stringify({
          type: 'direct_message', targetUserId: uid,
          subType: 'otp_exchange',
          encryptedData: encrypted.data, iv: encrypted.iv, timestamp: Date.now()
        }));
      }
    } catch (e) {
      if (uid === activeUserId)
        chatStatus.textContent = 'OTP-Exchange-Fehler: ' + e.message;
      return;
    }
  }

  if (getOTPSendStore(uid) && getOTPRecvStore(uid)) {
    otpExchangeInProgress = false;
    if (uid === activeUserId) finalizeOTPSetup(uid);
  }
}

function finalizeOTPSetup(uid) {
  if (uid !== activeUserId) return;
  e2eBadge.textContent = '🔒🔒 E2E + OTP';
  e2eBadge.style.color = '#3fb950';
  messageInput.disabled = false;
  sendBtn.disabled = false;
  fileBtn.disabled = false;
  const sendStore = getOTPSendStore(uid);
  const recvStore = getOTPRecvStore(uid);
  const sRem = sendStore ? ((sendStore.data.length - sendStore.offset) / 1024).toFixed(0) : 0;
  const rRem = recvStore ? ((recvStore.data.length - recvStore.offset) / 1024).toFixed(0) : 0;
  messagesContainer.innerHTML =
    `<div class="system-message">🔒🔥 AES-256-GCM + One-Time-Pad<br>OTP-Rest: ${sRem} KB Senden / ${rRem} KB Empfangen</div>`;
  chatStatus.textContent = '🔒🔥 Doppelt verschlüsselt';
  loadChatHistory();
}

async function checkOTPRenewal() {
  const uid = activeUserId;
  if (!uid) return;
  const sendStore = getOTPSendStore(uid);
  const recvStore = getOTPRecvStore(uid);
  const needRenew = (s) => s && (s.offset / s.data.length) > OTP_RENEW_THRESHOLD;
  if (needRenew(sendStore) || needRenew(recvStore)) {
    chatStatus.textContent = 'Erneuere OTP-Schlüssel...';
    await initiateOTPExchange(uid);
  }
}

async function deriveStorageKey(userId) {
  const ecdhKey = getSharedKey(userId);
  if (!ecdhKey) return null;
  const raw = await crypto.subtle.exportKey('raw', ecdhKey);
  const salt = new TextEncoder().encode('SecureChat-Storage-v1');
  const bits = await crypto.subtle.importKey('raw', new Uint8Array([...new Uint8Array(salt), ...new Uint8Array(raw)]),
    { name: 'PBKDF2' }, false, ['deriveBits']);
  const hash = await crypto.subtle.digest('SHA-256', new Uint8Array([...new Uint8Array(salt), ...new Uint8Array(raw)]));
  return await crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

function isStorageActive(forUserId) {
  return storageEnabled[forUserId] === true;
}

async function toggleStorage() {
  const uid = activeUserId;
  if (!uid) return;
  if (isStorageActive(uid)) {
    storageEnabled[uid] = false;
    localStorage.removeItem('schistory_' + uid);
    storageToggleBtn.classList.remove('active');
    storageToggleBtn.title = 'Chat-Verlauf speichern';
    chatStatus.textContent = 'Lokales Speichern deaktiviert.';
    ws.send(JSON.stringify({ type: 'storage_consent_revoke', targetUserId: uid }));
    return;
  }
  ws.send(JSON.stringify({ type: 'storage_consent_request', targetUserId: uid }));
  chatStatus.textContent = 'Warte auf Zustimmung des Partners...';
}

async function acceptStorageConsent() {
  const uid = pendingStorageConsentFrom;
  if (!uid) return;
  pendingStorageConsentFrom = null;
  storageConsentModal.style.display = 'none';
  storageEnabled[uid] = true;
  storageToggleBtn.classList.add('active');
  storageToggleBtn.title = 'Chat-Verlauf wird gespeichert';
  chatStatus.textContent = 'Speichern aktiviert (beide zugestimmt).';
  ws.send(JSON.stringify({ type: 'storage_consent_response', targetUserId: uid, accepted: true }));
  flushHistoryToStorage(uid);
}

function denyStorageConsent() {
  const uid = pendingStorageConsentFrom;
  if (uid) {
    ws.send(JSON.stringify({ type: 'storage_consent_response', targetUserId: uid, accepted: false }));
  }
  pendingStorageConsentFrom = null;
  storageConsentModal.style.display = 'none';
}

async function flushHistoryToStorage(forUserId) {
  if (!forUserId || !isStorageActive(forUserId)) return;
  const sk = await deriveStorageKey(forUserId);
  if (!sk) return;
  const history = messageHistories[forUserId] || [];
  const json = JSON.stringify(history);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(json);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sk, encoded);
  const data = { iv: arrayBufferToBase64(iv), ct: arrayBufferToBase64(ct) };
  localStorage.setItem('schistory_' + forUserId, JSON.stringify(data));
}

async function loadHistoryFromStorage(forUserId) {
  if (!forUserId) return;
  const raw = localStorage.getItem('schistory_' + forUserId);
  if (!raw) return;
  try {
    const { iv, ct } = JSON.parse(raw);
    const sk = await deriveStorageKey(forUserId);
    if (!sk) return;
    const ivB = base64ToArrayBuffer(iv);
    const ctB = base64ToArrayBuffer(ct);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivB }, sk, ctB);
    const history = JSON.parse(new TextDecoder().decode(plaintext));
    messageHistories[forUserId] = history;
  } catch { }
}

async function sendFiles() {
  const files = fileInput.files;
  if (!files.length) return;
  fileInput.value = '';
  const uid = activeUserId || activeGroupId;
  if (!uid) return;

  for (const file of files) {
    chatStatus.textContent = 'Verschlüssele ' + file.name + '...';
    const buffer = await file.arrayBuffer();
    const key = activeGroupId ? groupKeys[activeGroupId] : getSharedKey(uid);
    if (!key) { chatStatus.textContent = 'Kein Schlüssel für Datei.'; continue; }

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buffer);
    const totalChunks = Math.ceil(ct.byteLength / CHUNK_SIZE);

    const meta = JSON.stringify({ name: file.name, type: file.type || 'application/octet-stream', size: file.size });
    const metaIv = crypto.getRandomValues(new Uint8Array(12));
    const metaCt = await crypto.subtle.encrypt({ name: 'AES-GCM', metaIv }, key, new TextEncoder().encode(meta));

    const msgType = activeGroupId ? 'group_message' : 'file_message';
    const targetKey = activeGroupId ? 'groupId' : 'targetUserId';
    const targetVal = activeGroupId ? activeGroupId : activeUserId;

    ws.send(JSON.stringify({
      type: msgType === 'file_message' ? 'file_message' : 'group_file',
      [targetKey]: targetVal,
      fileName: arrayBufferToBase64(metaCt), fileIv: arrayBufferToBase64(metaIv),
      fileSize: file.size, totalChunks, chunkIndex: -1, encryptedData: '', iv: arrayBufferToBase64(iv)
    }));

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, ct.byteLength);
      const chunk = ct.slice(start, end);
      ws.send(JSON.stringify({
        type: msgType === 'file_message' ? 'file_message' : 'group_file',
        [targetKey]: targetVal,
        chunkIndex: i, totalChunks,
        encryptedData: arrayBufferToBase64(chunk), iv: '',
        fileName: '', fileIv: ''
      }));
    }

    appendFileMessage('Du', file.name, file.type, file.size, 'sent', new Date());
    chatStatus.textContent = file.name + ' gesendet.';
  }
}

async function handleFileMessage(msg) {
  const uid = msg.isGroup ? msg.groupId : msg.senderUserId;
  const key = msg.isGroup ? groupKeys[uid] : getSharedKey(uid);
  if (!key) return;

  if (msg.chunkIndex === -1) {
    try {
      const metaIv = base64ToArrayBuffer(msg.fileIv);
      const metaCt = base64ToArrayBuffer(msg.fileName);
      const metaPlain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: metaIv }, key, metaCt);
      const meta = JSON.parse(new TextDecoder().decode(metaPlain));
      const fileIv = base64ToArrayBuffer(msg.iv);
      fileChunks[uid] = { meta, chunks: [], totalChunks: msg.totalChunks, received: 0, fileIv };
    } catch { }
    return;
  }

  const fc = fileChunks[uid];
  if (!fc) return;
  const chunkData = base64ToArrayBuffer(msg.encryptedData);
  fc.chunks[msg.chunkIndex] = chunkData;
  fc.received++;

  if (fc.received === fc.totalChunks) {
    const full = new Uint8Array(fc.chunks.reduce((s, c) => s + c.byteLength, 0));
    let offset = 0;
    for (const c of fc.chunks) { full.set(new Uint8Array(c), offset); offset += c.byteLength; }
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fc.fileIv }, key, full
      );
      const blob = new Blob([plaintext], { type: fc.meta.type });
      const url = URL.createObjectURL(blob);
      appendFileMessage(msg.senderUsername, fc.meta.name, fc.meta.type, fc.meta.size, 'received', new Date(), url, blob);
      delete fileChunks[uid];
    } catch { }
  }
}

function appendFileMessage(sender, fileName, fileType, fileSize, type, timestamp, url, blob) {
  const div = document.createElement('div');
  div.className = 'message file-message ' + type;

  const s = document.createElement('div');
  s.className = 'msg-sender';
  s.textContent = sender;
  div.appendChild(s);

  const icon = document.createElement('span');
  icon.textContent = fileType?.startsWith('image/') ? '🖼️ ' : '📎 ';
  div.appendChild(icon);

  const nameSpan = document.createElement('span');
  nameSpan.textContent = fileName + ' (' + (fileSize / 1024).toFixed(1) + ' KB)';
  div.appendChild(nameSpan);

  if (url && fileType?.startsWith('image/')) {
    const img = document.createElement('img');
    img.src = url;
    img.className = 'chat-image';
    img.style.maxWidth = '100%';
    img.style.maxHeight = '300px';
    img.style.borderRadius = '8px';
    img.style.marginTop = '6px';
    img.style.cursor = 'pointer';
    img.addEventListener('click', () => window.open(url));
    div.appendChild(img);
  } else if (url && blob) {
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.textContent = ' ⬇️ Herunterladen';
    a.className = 'file-download';
    a.style.display = 'block';
    a.style.marginTop = '6px';
    a.style.color = '#58a6ff';
    div.appendChild(a);
  }

  const tm = document.createElement('div');
  tm.className = 'msg-time';
  tm.textContent = timestamp.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
  div.appendChild(tm);

  messagesContainer.appendChild(div);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function arrayBufferToBase64(buffer) {

function base64ToArrayBuffer(base64) {
  const s = atob(base64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes.buffer;
}

async function handleServerMessage(msg) {
  switch (msg.type) {

    case 'assigned_id':
      myUserId = msg.userId;
      loginContainer.style.display = 'none';
      chatContainer.style.display = 'flex';
      loginStatus.textContent = '';
      connectBtn.disabled = false;
      ws.send(JSON.stringify({ type: 'get_groups' }));
      break;

    case 'user_list':
      setUserList(msg.users);
      break;

    case 'public_key':
      try {
        const sk = await deriveSharedKey(msg.publicKey);
        setSharedKey(msg.targetUserId, sk);
        if (msg.push) break;
        activeUserId = msg.targetUserId;
        activeUsername = msg.targetUsername;
        chatPartnerName.textContent = msg.targetUsername;
        await restoreStorageState(activeUserId);
        e2eBadge.textContent = '🔒 E2E (AES-256-GCM)';
        e2eBadge.style.color = '#58a6ff';
        messageInput.disabled = true;
        sendBtn.disabled = true;
        chatStatus.textContent = 'Tausche OTP-Schlüssel aus...';
        messagesContainer.innerHTML = '<div class="system-message">🔑 OTP-Schlüsselaustausch läuft...</div>';
        await initiateOTPExchange(activeUserId);
        loadChatHistory();
      } catch (e) {
        chatStatus.textContent = 'Fehler bei Schlüsselaustausch: ' + e.message;
      }
      break;

    case 'direct_message':
      if (msg.subType === 'otp_exchange') {
        await handleOTPExchange(msg);
        return;
      }
      if (msg.nonce && receivedNonces[msg.senderUserId] && receivedNonces[msg.senderUserId].has(msg.nonce)) {
        return;
      }
      if (getSharedKey(msg.senderUserId)) {
        try {
          const plaintext = await decryptMessageFrom(msg.senderUserId, msg.iv, msg.encryptedData);
          if (msg.nonce) {
            if (!receivedNonces[msg.senderUserId]) receivedNonces[msg.senderUserId] = new Set();
            receivedNonces[msg.senderUserId].add(msg.nonce);
          }
          appendMessage(msg.senderUsername, plaintext, 'received', new Date(msg.timestamp));
          saveMessageToHistory(msg.senderUserId, msg.senderUsername, plaintext, 'received', msg.timestamp);
        } catch (e) {
          if (msg.senderUserId === activeUserId)
            chatStatus.textContent = '🔴 Entschlüsselungsfehler: ' + e.message;
        }
      }
      break;

    case 'file_message':
      handleFileMessage(msg);
      break;

    case 'group_file':
      handleFileMessage({ ...msg, isGroup: true });
      break;

    case 'group_created':
      myGroups[msg.groupId] = { name: msg.name, members: msg.members };
      groupIdPending = msg.groupId;
      renderGroupList();
      chatStatus.textContent = 'Gruppe "' + msg.name + '" erstellt.';
      break;

    case 'group_key_share':
      if (groupKeys[msg.groupId]) break;
      try {
        const decrypted = await aesDecryptOnly(msg.senderUserId, msg.iv, msg.encryptedKey);
        const rawKey = base64ToArrayBuffer(decrypted);
        groupKeys[msg.groupId] = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
        chatStatus.textContent = 'Gruppenschlüssel erhalten.';
        if (activeGroupId === msg.groupId) selectGroup(msg.groupId);
      } catch (e) {
        chatStatus.textContent = 'Gruppenschlüssel-Fehler: ' + e.message;
      }
      break;

    case 'group_message':
      if (!groupKeys[msg.groupId]) break;
      try {
        const iv = base64ToArrayBuffer(msg.iv);
        const ct = base64ToArrayBuffer(msg.encryptedData);
        const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, groupKeys[msg.groupId], ct);
        const text = new TextDecoder().decode(plaintext);
        if (msg.senderUserId === activeGroupId || msg.groupId === activeGroupId) {
          appendMessage(msg.senderUsername, text, 'received', new Date(msg.timestamp));
        }
        if (!groupHistories[msg.groupId]) groupHistories[msg.groupId] = [];
        groupHistories[msg.groupId].push({ sender: msg.senderUsername, text, type: 'received', timestamp: msg.timestamp });
      } catch { }
      break;

    case 'member_left':
      if (myGroups[msg.groupId]) {
        myGroups[msg.groupId].members = myGroups[msg.groupId].members.filter(m => m.userId !== msg.userId);
        renderGroupList();
        if (activeGroupId === msg.groupId)
          chatStatus.textContent = msg.username + ' hat die Gruppe verlassen.';
      }
      break;

    case 'groups_list':
      for (const g of msg.groups) {
        if (!myGroups[g.groupId]) {
          myGroups[g.groupId] = { name: g.name, members: g.members };
        }
      }
      renderGroupList();
      break;

    case 'storage_consent_request':
      if (msg.senderUserId) {
        pendingStorageConsentFrom = msg.senderUserId;
        storageConsentText.textContent = `${msg.senderUsername} möchte den verschlüsselten Chat-Verlauf lokal speichern. Beide müssen zustimmen.`;
        storageConsentModal.style.display = 'flex';
      }
      break;

    case 'storage_consent_response':
      if (msg.senderUserId && msg.accepted) {
        storageEnabled[msg.senderUserId] = true;
        storageToggleBtn.classList.add('active');
        storageToggleBtn.title = 'Chat-Verlauf wird gespeichert';
        chatStatus.textContent = 'Partner hat zugestimmt — Speichern aktiv.';
        if (msg.senderUserId === activeUserId) {
          flushHistoryToStorage(msg.senderUserId);
        }
      } else if (msg.senderUserId) {
        chatStatus.textContent = 'Partner hat Speichern abgelehnt.';
      }
      break;

    case 'storage_consent_revoke':
      if (msg.senderUserId) {
        storageEnabled[msg.senderUserId] = false;
        localStorage.removeItem('schistory_' + msg.senderUserId);
        storageToggleBtn.classList.remove('active');
        storageToggleBtn.title = 'Chat-Verlauf speichern';
        chatStatus.textContent = 'Partner hat Speichern deaktiviert — Verlauf gelöscht.';
      }
      break;

    case 'emergency_delete_request':
      deleteAllData(msg.senderUserId);
      messagesContainer.innerHTML = '<div class="system-message">🔴 Chat wurde vom Partner gelöscht</div>';
      messageInput.disabled = true;
      sendBtn.disabled = true;
      fileBtn.disabled = true;
      chatStatus.textContent = 'Chat wurde gelöscht.';
      break;

    case 'emergency_delete_confirmed':
      deleteAllData(activeUserId);
      messagesContainer.innerHTML = '<div class="system-message">🔴 Chat lokal gelöscht</div>';
      messageInput.disabled = true;
      sendBtn.disabled = true;
      fileBtn.disabled = true;
      chatStatus.textContent = 'Chat gelöscht.';
      break;

    case 'user_offline':
      chatStatus.textContent = 'Benutzer ist offline.';
      break;

    case 'error':
      chatStatus.textContent = msg.message;
      break;

    case 'pong':
      break;
  }
}

function setUserList(users) {
  userMap = {};
  userList.innerHTML = '';
  users.forEach(u => {
    if (u.userId === myUserId) return;
    userMap[u.userId] = u;
    const li = document.createElement('li');
    li.dataset.userId = u.userId;
    if (u.userId === activeUserId) li.classList.add('active');
    const dot = document.createElement('span');
    dot.className = 'user-dot ' + (u.online ? 'online' : 'offline');
    li.appendChild(dot);
    li.appendChild(document.createTextNode(u.username));
    li.addEventListener('click', () => selectUser(u.userId, u.username));
    userList.appendChild(li);
  });
  if (activeUserId && userMap[activeUserId])
    partnerStatus.className = 'online-indicator online';
  else if (activeUserId)
    partnerStatus.className = 'online-indicator offline';
}

async function selectUser(userId, username) {
  activeUserId = userId;
  activeUsername = username;
  chatPartnerName.textContent = username;
  partnerStatus.className = 'online-indicator online';
  document.querySelectorAll('#user-list li').forEach(li =>
    li.classList.toggle('active', li.dataset.userId === userId));

  const existing = getSharedKey(userId);
  if (existing && getOTPSendStore(userId) && getOTPRecvStore(userId)) {
    await restoreStorageState(userId);
  messageInput.disabled = false;
  sendBtn.disabled = false;
  fileBtn.disabled = false;
  e2eBadge.textContent = '🔒🔒 E2E + OTP';
  e2eBadge.style.color = '#3fb950';
  messagesContainer.innerHTML = '';
  loadChatHistory();
  chatStatus.textContent = 'Verbindung wiederhergestellt.';
  return;
}
if (existing) {
  await restoreStorageState(userId);
  chatStatus.textContent = 'Tausche OTP-Schlüssel aus...';
  messagesContainer.innerHTML = '<div class="system-message">🔑 OTP-Schlüsselaustausch läuft...</div>';
    await initiateOTPExchange(userId);
    loadChatHistory();
    return;
  }

  messageInput.disabled = true;
  sendBtn.disabled = true;
  fileBtn.disabled = true;
  otpExchangeInProgress = false;
  e2eBadge.textContent = '🔒 Schlüsselaustausch...';
  e2eBadge.style.color = '#58a6ff';
  messagesContainer.innerHTML = '<div class="system-message">Schlüsselaustausch läuft...</div>';
  chatStatus.textContent = 'Fordere öffentlichen Schlüssel an...';

  ws.send(JSON.stringify({ type: 'get_public_key', targetUserId: userId }));
}

function setOfflineStatus() {
  partnerStatus.className = 'online-indicator offline';
  messageInput.disabled = true;
  sendBtn.disabled = true;
  fileBtn.disabled = true;
}

async function sendMessage() {
  const text = messageInput.value.trim();
  if (!text) return;
  messageInput.value = '';

  if (activeGroupId) {
    await sendGroupMessage(text);
    return;
  }

  if (!activeUserId) return;
  if (!userMap[activeUserId]) { chatStatus.textContent = 'Benutzer ist offline.'; return; }
  if (!getSharedKey(activeUserId)) { chatStatus.textContent = 'Kein gemeinsamer Schlüssel.'; return; }

  chatStatus.textContent = 'Verschlüssele...';

  try {
    const nonce = ++msgCounter;
    const encrypted = await encryptMessageFor(activeUserId, text);
    const timestamp = Date.now();

    ws.send(JSON.stringify({
      type: 'direct_message', targetUserId: activeUserId,
      encryptedData: encrypted.data, iv: encrypted.iv,
      timestamp, nonce
    }));

    appendMessage('Du', text, 'sent', new Date(timestamp));
    saveMessageToHistory(activeUserId, 'Du', text, 'sent', timestamp);
    if (isStorageActive(activeUserId)) flushHistoryToStorage(activeUserId);
    const sendStore = getOTPSendStore(activeUserId);
    const rem = sendStore ? ((sendStore.data.length - sendStore.offset) / 1024).toFixed(0) : 0;
    chatStatus.textContent = `Gesendet — OTP-Rest: ${rem} KB`;
    checkOTPRenewal();
  } catch (e) {
    chatStatus.textContent = 'Fehler: ' + e.message;
  }
}

function appendMessage(sender, text, type, timestamp) {
  const div = document.createElement('div');
  div.className = 'message ' + type;
  const s = document.createElement('div'); s.className = 'msg-sender'; s.textContent = sender; div.appendChild(s);
  const t = document.createElement('div'); t.textContent = text; div.appendChild(t);
  const tm = document.createElement('div'); tm.className = 'msg-time';
  tm.textContent = timestamp.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
  div.appendChild(tm);
  messagesContainer.appendChild(div);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function saveMessageToHistory(forUserId, sender, text, type, timestamp) {
  if (!forUserId) return;
  if (!messageHistories[forUserId]) messageHistories[forUserId] = [];
  messageHistories[forUserId].push({ sender, text, type, timestamp });
}

function loadChatHistory() {
  if (!activeUserId) return;
  messagesContainer.innerHTML = '';
  const history = messageHistories[activeUserId] || [];
  if (history.length === 0) {
    const sendStore = getOTPSendStore(activeUserId);
    const recvStore = getOTPRecvStore(activeUserId);
    if (sendStore && recvStore)
      messagesContainer.innerHTML = '<div class="system-message">Bereit — Nachricht eingeben.</div>';
    return;
  }
  history.forEach(msg =>
    appendMessage(msg.sender, msg.text, msg.type, new Date(msg.timestamp)));
}

function deleteAllData(forUserId) {
  if (forUserId) {
    delete sharedKeys[forUserId];
    delete otpSendStores[forUserId];
    delete otpRecvStores[forUserId];
    delete messageHistories[forUserId];
    delete receivedNonces[forUserId];
    delete storageEnabled[forUserId];
    localStorage.removeItem('schistory_' + forUserId);
  }
}

function performEmergencyDelete() {
  for (const uid of Object.keys(sharedKeys)) deleteAllData(uid);
  for (const uid of Object.keys(otpSendStores)) deleteAllData(uid);
  for (const uid of Object.keys(storageEnabled)) deleteAllData(uid);
  const keys = Object.keys(localStorage).filter(k => k.startsWith('schistory_'));
  keys.forEach(k => localStorage.removeItem(k));
  storageToggleBtn.classList.remove('active');
  storageToggleBtn.title = 'Chat-Verlauf speichern';
  messagesContainer.innerHTML = '<div class="system-message">🔴 Chat gelöscht</div>';
  messageInput.disabled = true;
  sendBtn.disabled = true;
  fileBtn.disabled = true;
  chatStatus.textContent = 'Chat gelöscht.';
  if (activeUserId)
    ws.send(JSON.stringify({ type: 'emergency_delete', targetUserId: activeUserId }));
}

function openGroupModal() {
  groupMemberList.innerHTML = '';
  for (const uid of Object.keys(userMap)) {
    const div = document.createElement('div');
    div.className = 'member-select-item';
    const cb = document.createElement('input');
    cb.type = 'checkbox'; cb.value = uid; cb.id = 'gm_' + uid;
    const label = document.createElement('label');
    label.htmlFor = 'gm_' + uid; label.textContent = userMap[uid].username;
    div.appendChild(cb); div.appendChild(label);
    groupMemberList.appendChild(div);
  }
  groupNameInput.value = '';
  groupModal.style.display = 'flex';
}

async function createGroup() {
  const name = groupNameInput.value.trim() || 'Gruppe';
  const checks = groupMemberList.querySelectorAll('input:checked');
  const memberIds = Array.from(checks).map(c => c.value);
  if (memberIds.length < 1) { chatStatus.textContent = 'Mindestens 1 Mitglied wählen.'; return; }
  groupModal.style.display = 'none';
  chatStatus.textContent = 'Erstelle Gruppe...';

  const myGroupKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
  );
  const exportedKey = await crypto.subtle.exportKey('raw', myGroupKey);
  const groupKeyB64 = arrayBufferToBase64(exportedKey);

  ws.send(JSON.stringify({ type: 'create_group', name, memberUserIds: memberIds }));

  const delay = (ms) => new Promise(r => setTimeout(r, ms));
  await delay(300);

  for (const mid of [...memberIds, myUserId]) {
    if (mid === myUserId) {
      groupKeys[groupIdPending] = myGroupKey;
      continue;
    }
    const encrypted = await aesEncryptOnly(mid, groupKeyB64);
    ws.send(JSON.stringify({
      type: 'group_key_share', groupId: groupIdPending,
      targetUserId: mid, encryptedKey: encrypted.data, iv: encrypted.iv
    }));
  }
}

let groupIdPending = null;

function renderGroupList() {
  groupListEl.innerHTML = '';
  for (const gid of Object.keys(myGroups)) {
    const g = myGroups[gid];
    const div = document.createElement('div');
    div.className = 'group-item' + (gid === activeGroupId ? ' active' : '');
    div.textContent = '👥 ' + g.name;
    const count = document.createElement('span');
    count.className = 'group-count';
    count.textContent = g.members.length + ' Mitglieder';
    div.appendChild(count);
    div.addEventListener('click', () => selectGroup(gid));
    groupListEl.appendChild(div);
  }
}

function selectGroup(groupId) {
  activeGroupId = groupId;
  activeUserId = null;
  activeGroupId = groupId;
  const g = myGroups[groupId];
  chatPartnerName.textContent = '👥 ' + g.name;
  partnerStatus.className = 'online-indicator online';
  e2eBadge.textContent = '🔒 Gruppen-E2E';
  e2eBadge.style.color = '#3fb950';
  messageInput.disabled = false;
  sendBtn.disabled = false;
  fileBtn.disabled = false;
  renderGroupList();
  document.querySelectorAll('#user-list li').forEach(li => li.classList.remove('active'));
  messagesContainer.innerHTML = '';
  const history = groupHistories[groupId] || [];
  if (history.length === 0) {
    messagesContainer.innerHTML = '<div class="system-message">👥 Gruppenchat: ' + g.name + '</div>';
  } else {
    history.forEach(msg => appendMessage(msg.sender, msg.text, msg.type, new Date(msg.timestamp)));
  }
  chatStatus.textContent = 'Gruppe • ' + g.members.length + ' Mitglieder';
}

async function sendGroupMessage(text) {
  if (!activeGroupId || !groupKeys[activeGroupId]) return;
  const gk = groupKeys[activeGroupId];
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, gk, encoded);

  ws.send(JSON.stringify({
    type: 'group_message', groupId: activeGroupId,
    encryptedData: arrayBufferToBase64(ct), iv: arrayBufferToBase64(iv),
    timestamp: Date.now()
  }));

  appendMessage('Du', text, 'sent', new Date());
  if (!groupHistories[activeGroupId]) groupHistories[activeGroupId] = [];
  groupHistories[activeGroupId].push({ sender: 'Du', text, type: 'sent', timestamp: Date.now() });
}
