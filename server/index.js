import { createServer } from 'http';
import { readFileSync, existsSync } from 'fs';
import { extname, join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import { v4 as uuidv4 } from 'uuid';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = 3000;
const CLIENT_DIR = join(__dirname, '..', 'client');

const MIME = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json'
};

const httpServer = createServer((req, res) => {
  let filePath = join(CLIENT_DIR, req.url === '/' ? 'index.html' : req.url);
  if (!existsSync(filePath)) {
    filePath = join(CLIENT_DIR, 'index.html');
  }
  try {
    const content = readFileSync(filePath);
    const ext = extname(filePath);
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store, no-cache, must-revalidate'
    });
    res.end(content);
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
});

const wss = new WebSocketServer({ server: httpServer });
const clients = new Map();
const groups = new Map();

wss.on('connection', (ws) => {
  const userId = uuidv4();
  let username = null;
  let publicKey = null;

  ws.isAlive = true;

  ws.on('pong', () => { ws.isAlive = true; });

  ws.send(JSON.stringify({ type: 'assigned_id', userId }));

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());

      switch (msg.type) {

        case 'register':
          username = msg.username;
          publicKey = msg.publicKey;
          clients.set(userId, { ws, username, publicKey, userId });
          console.log(`[${username}] registriert (${userId.slice(0,8)}...) — ${clients.size} online`);
          broadcastUserList();
          break;

        case 'offer':
        case 'answer':
        case 'ice_candidate':
          if (msg.targetUserId) {
            const target = clients.get(msg.targetUserId);
            if (target && target.ws.readyState === 1) {
              target.ws.send(JSON.stringify({
                type: msg.type,
                senderUserId: userId,
                senderUsername: username,
                data: msg.data
              }));
            }
          }
          break;

        case 'get_public_key':
          if (msg.targetUserId) {
            const target = clients.get(msg.targetUserId);
            const requester = clients.get(userId);
            if (target && target.publicKey) {
              ws.send(JSON.stringify({
                type: 'public_key',
                targetUserId: msg.targetUserId,
                targetUsername: target.username,
                publicKey: target.publicKey
              }));
              if (requester && requester.publicKey && target.ws.readyState === 1) {
                target.ws.send(JSON.stringify({
                  type: 'public_key',
                  push: true,
                  targetUserId: userId,
                  targetUsername: requester.username,
                  publicKey: requester.publicKey
                }));
              }
            } else {
              ws.send(JSON.stringify({
                type: 'error',
                message: 'User not found or public key not available'
              }));
            }
          }
          break;

        case 'direct_message': {
          const targetUserId = msg.targetUserId;
          const target = clients.get(targetUserId);
          if (!target) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Recipient not found'
            }));
            return;
          }
          if (target.ws.readyState !== 1) {
            ws.send(JSON.stringify({
              type: 'user_offline',
              targetUserId
            }));
            return;
          }
          target.ws.send(JSON.stringify({
            type: 'direct_message',
            senderUserId: userId,
            senderUsername: username,
            encryptedData: msg.encryptedData,
            iv: msg.iv,
            timestamp: msg.timestamp,
            subType: msg.subType || null,
            pubKeyTemp: msg.pubKeyTemp || null,
            encryptedPad: msg.encryptedPad || null,
            otpData: msg.otpData || null
          }));
          break;
        }

        case 'file_message': {
          const fTarget = clients.get(msg.targetUserId);
          if (!fTarget || fTarget.ws.readyState !== 1) { break; }
          fTarget.ws.send(JSON.stringify({
            type: 'file_message',
            senderUserId: userId, senderUsername: username,
            fileName: msg.fileName, fileIv: msg.fileIv,
            fileSize: msg.fileSize, totalChunks: msg.totalChunks,
            encryptedData: msg.encryptedData, iv: msg.iv,
            chunkIndex: msg.chunkIndex,
            transferId: msg.transferId || null
          }));
          break;
        }

        case 'emergency_delete': {
          const targetUserId = msg.targetUserId;
          ws.send(JSON.stringify({
            type: 'emergency_delete_confirmed',
            message: 'Chat gelöscht'
          }));
          const target = clients.get(targetUserId);
          if (target && target.ws.readyState === 1) {
            target.ws.send(JSON.stringify({
              type: 'emergency_delete_request',
              senderUserId: userId,
              senderUsername: username
            }));
          }
          break;
        }

        case 'storage_consent_request':
        case 'storage_consent_response':
        case 'storage_consent_revoke': {
          const stTarget = clients.get(msg.targetUserId);
          if (stTarget && stTarget.ws.readyState === 1) {
            stTarget.ws.send(JSON.stringify({
              type: msg.type,
              senderUserId: userId,
              senderUsername: username,
              accepted: msg.accepted || false
            }));
          }
          break;
        }

        case 'create_group': {
          const groupId = uuidv4();
          const members = new Set([userId, ...msg.memberUserIds]);
          const memberList = [];
          for (const mid of members) {
            const c = clients.get(mid);
            if (c) memberList.push({ userId: mid, username: c.username, publicKey: c.publicKey });
          }
          groups.set(groupId, { name: msg.name || 'Gruppe', creator: userId, members, memberList });
          for (const mid of members) {
            const c = clients.get(mid);
            if (c && c.ws.readyState === 1) {
              c.ws.send(JSON.stringify({ type: 'group_created', groupId, name: msg.name, members: memberList }));
            }
          }
          break;
        }

        case 'group_key_share': {
          const target = clients.get(msg.targetUserId);
          if (target && target.ws.readyState === 1) {
            target.ws.send(JSON.stringify({
              type: 'group_key_share', groupId: msg.groupId,
              senderUserId: userId, senderUsername: username,
              encryptedKey: msg.encryptedKey, iv: msg.iv
            }));
          }
          break;
        }

        case 'group_file': {
          const group = groups.get(msg.groupId);
          if (!group) { ws.send(JSON.stringify({ type: 'error', message: 'Gruppe nicht gefunden' })); return; }
          for (const mid of group.members) {
            if (mid === userId) continue;
            const c = clients.get(mid);
            if (c && c.ws.readyState === 1) {
              c.ws.send(JSON.stringify({
                type: 'group_file', groupId: msg.groupId,
                senderUserId: userId, senderUsername: username,
                fileName: msg.fileName, fileIv: msg.fileIv,
                fileSize: msg.fileSize, totalChunks: msg.totalChunks,
                encryptedData: msg.encryptedData, iv: msg.iv,
                chunkIndex: msg.chunkIndex,
                transferId: msg.transferId || null
              }));
            }
          }
          break;
        }

        case 'group_message': {
          const group = groups.get(msg.groupId);
          if (!group) { ws.send(JSON.stringify({ type: 'error', message: 'Gruppe nicht gefunden' })); return; }
          for (const mid of group.members) {
            if (mid === userId) continue;
            const c = clients.get(mid);
            if (c && c.ws.readyState === 1) {
              c.ws.send(JSON.stringify({
                type: 'group_message', groupId: msg.groupId,
                senderUserId: userId, senderUsername: username,
                encryptedData: msg.encryptedData, iv: msg.iv,
                groupHash: msg.groupHash || null,
                timestamp: msg.timestamp
              }));
            }
          }
          break;
        }

        case 'leave_group': {
          const group = groups.get(msg.groupId);
          if (group) {
            group.members.delete(userId);
            group.memberList = group.memberList.filter(m => m.userId !== userId);
            if (group.members.size <= 1) {
              groups.delete(msg.groupId);
            } else {
              for (const mid of group.members) {
                const c = clients.get(mid);
                if (c && c.ws.readyState === 1) {
                  c.ws.send(JSON.stringify({
                    type: 'member_left', groupId: msg.groupId,
                    userId, username
                  }));
                }
              }
            }
          }
          break;
        }

        case 'get_groups':
          const userGroups = [];
          for (const [gid, g] of groups) {
            if (g.members.has(userId)) {
              userGroups.push({ groupId: gid, name: g.name, members: g.memberList });
            }
          }
          ws.send(JSON.stringify({ type: 'groups_list', groups: userGroups }));
          break;

        case 'ping':
          ws.send(JSON.stringify({ type: 'pong' }));
          break;

        default:
          break;
      }
    } catch (e) {
      console.error('Parse error:', e);
    }
  });

  ws.on('close', () => {
    clients.delete(userId);
    broadcastUserList();
  });

  function broadcastUserList() {
    const userList = [];
    for (const [id, client] of clients) {
      userList.push({
        userId: id,
        username: client.username,
        online: true
      });
    }
    for (const [, client] of clients) {
      if (client.ws.readyState === 1) {
        client.ws.send(JSON.stringify({ type: 'user_list', users: userList }));
      }
    }
  }
});

const interval = setInterval(() => {
  for (const [, client] of clients) {
    if (client.ws.isAlive === false) {
      client.ws.terminate();
      clients.delete(client.userId);
      continue;
    }
    client.ws.isAlive = false;
    client.ws.ping();
  }
}, 30000);

wss.on('close', () => clearInterval(interval));

httpServer.listen(PORT, () => {
  console.log(`Secure Chat Server läuft auf http://localhost:${PORT}`);
});
