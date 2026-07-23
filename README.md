# Secure Chat – Ende-zu-Ende verschlüsselter Chat (Post-Quantum & E2E Consensus)

Ein hochsicherer, Ende-zu-Ende verschlüsselter Online-Chat mit **Post-Quantum OTP-Pad-Ratchet**, **Ghost-Peer-Protection** (kryptographischer Gruppenkonsens via AES-GCM AAD) sowie **gekapselter IndexedDB-Speicherung** mit flüchtigem RAM-Zeroing.

---

## 🏛️ Systemarchitektur

```
Client A  <───────────────── WebSocket (Relay) ─────────────────>  Client B
   │                                                                  │
   ├─ ECDH P-384 (Statische Identity Keys)                             │
   ├─ Post-Quantum OTP Pad-Ratchet (Ephemere ECDH P-384 Re-Keyings)   │
   ├─ AES-256-GCM (Symmetrische Verschlüsselung)                        │
   ├─ OTP-XOR (Doppelverschlüsselung mit 64-KB-Pad)                     │
   ├─ Ghost-Peer-Protection (SHA-256 AAD-Konsens in Gruppen)            │
   └─ Encrypted IndexedDB + Memory Zeroing (crypto.getRandomValues)    │
```

Der Server ist als reines **Relay System** (Zero-Knowledge Router) konzipiert. Er liest, speichert oder protokolliert zu keinem Zeitpunkt Klartextnachrichten oder Schlüssel.

---

## 🔒 Sicherheitsarchitektur & Protokolle

### 1. Ephemerer OTP-Pad-Ratchet (Post-Quantum-Sicherung)
- **Doppelte Verschlüsselung**: Nachrichten werden erst mit AES-256-GCM verschlüsselt und anschließend byteweise via XOR mit einem 64-KB One-Time-Pad überlagert.
- **Ephemeres Re-Keying**: Sobald ein Pad zu 80 % verbraucht ist (`OTP_RENEW_THRESHOLD = 0.8`), generiert der Sender im Hintergrund ein frisches, ephemeres ECDH P-384 Schlüsselpaar (`KeyPair_temp`).
- **Mathematischer Ratchet-Sprung**: Ein neuer Schlüssel `AES_next` wird mittels ECDH aus `KeyPair_temp.privateKey` und dem Public Key des Empfängers berechnet. Das neue Pad wird ausschließlich mit `AES_next` verschlüsselt übertragen.
- **Post-Quantum Resilienz**: Selbst wenn in der Zukunft ein Quantencomputer den ursprünglichen Session-Key bricht, kann er den mathematischen Ratchet-Sprung (`AES_next`) nicht rückwirkend berechnen.
- **RAM-Zeroing**: Das alte Pad wird im RAM vor dem Ersetzen durch `crypto.getRandomValues()` mit Zufallsbytes überschrieben.

### 2. Gruppen-E2E & Ghost-Peer-Protection (Kryptographischer Konsens)
- **Mitglieder-Hashing**: Jeder Client führt lokal die verifizierte Mitgliederliste inklusive öffentlichen ECDH-Schlüsseln:
  $$\text{Hash}_{\text{Gruppe}} = \text{SHA-256}(\text{sortiert}(ID_1 + PubKey_1 + ID_2 + PubKey_2 + \dots))$$
- **AES-GCM Associated Data (AAD)**: Jede gesendete Gruppen-Nachricht enthält im unverschlüsselten, aber authentifizierten Header diesen $\text{Hash}_{\text{Gruppe}}$ als `additionalData`.
- **MitM- & Ghost-Peer-Erkennung**: Empfängt ein Client eine Nachricht und der empfangene Gruppen-Hash weicht vom eigenen lokalen Hash ab (z. B. weil der Server heimlich einen User eingeschleust hat), schlägt die AES-GCM Tag-Validierung fehl (`OperationError`). Der Client verwirft die Nachricht sofort und löst einen Sicherheitsalarm aus.

### 3. Sichere Speicherung im Web-Context (IndexedDB & Memory Zeroing)
- **LocalStorage-Verbot**: `localStorage` ist aus Sicherheitsgründen vollständig entfernt (Schutz vor einfachen XSS-Ausleseversuchen).
- **Verschlüsselte IndexedDB (`SecureChatDB`)**: Chat-Historien werden ausschließlich als AES-GCM-Chiffretexte (`{ iv, ct }`) in der Browser-IndexedDB abgelegt.
- **Master-Key im RAM**: Der derivierte Speicher-Schlüssel verbleibt ausschließlich im flüchtigen RAM-Speicher.
- **Kryptographisches Löschen**: Bei Widerruf der Speichereinwilligung (`storage_consent_revoke`) oder Betätigung des *Emergency-Delete*-Buttons werden alle Byte-Buffer im RAM via `crypto.getRandomValues()` genullt (`zeroMemory()`), IndexedDB-Einträge gelöscht und ein Wipe-Befehl an den Partner gesendet.

---

## 🛠️ Feature-Übersicht

| Feature | Beschreibung |
|---------|-------------|
| **Perfect Forward Secrecy** | Dynamische ECDH P-384 Schlüsselabteilung |
| **Post-Quantum Pad Ratchet** | Automatisches Ephemeral ECDH Re-Keying des OTP-Pads |
| **AES-256-GCM + OTP** | Kombinierte Doppelverschlüsselung für Nachrichten |
| **Ghost-Peer Protection** | AES-GCM AAD Gruppenkonsens verhindert Server-Eingriffe |
| **Encrypted IndexedDB** | Lokale Persistenz ausschließlich im Ciphertext-Format |
| **RAM Memory Zeroing** | Überschreiben flüchtiger Key-Buffer mit Entropie |
| **Replay-Schutz** | Monoton steigende Nonces pro Peer-Verbindung |
| **Datei- & Bild-E2E** | AES-256-GCM gechunkter Transfer (64-KB-Blöcke) |
| **Emergency Delete** | Beidseitige Krypto-Löschung & RAM-Zeroing |

---

## 🚀 Installation & Betrieb

### 1. Voraussetzungen
- **Node.js**: v18.0.0 oder höher

### 2. Server starten
```bash
cd server
npm install
node index.js
```
Der HTTP- & WebSocket-Server startet auf **`http://localhost:3000`** (bzw. auf allen Netzwerkschnittstellen).

### 3. Client nutzen
- **PowerShell Launcher**: `start-app.ps1` ausführen (öffnet den Client in Chrome im isolierten App-Modus).
- **Browser**: Gehe zu `http://localhost:3000`.
- **Mobilgeräte**: Öffne im mobilen Browser `http://<SERVER-IP>:3000`.

---

## 📁 Projektstruktur

```
SECURE-CHAT/
├── server/
│   ├── index.js          # WebSocket Relay Server & HTTP static File Server
│   ├── package.json      # Abhängigkeiten (ws, uuid)
│   └── package-lock.json
├── client/
│   ├── index.html        # UI Layout (Login, Chat-Fenster, Modals)
│   ├── style.css         # Dark Theme & Responsive UI Layout
│   ├── app.js            # Client-Kryptographie (Web Crypto API, Ratchet, IndexedDB)
│   ├── manifest.json     # PWA Manifest
│   └── sw.js             # Service Worker
├── start-app.ps1         # PowerShell App-Startskript
└── README.md             # System- & Dokumentationsübersicht
```

---

## ⚡ Verwendete Technologien

- **Web Crypto API**: `crypto.subtle` (ECDH P-384, AES-256-GCM, SHA-256, PBKDF2).
- **IndexedDB**: Asynchrone Browser-Datenbank für Chiffretexte.
- **WebSocket (ws)**: Bidirektionale Echtzeit-Kommunikation für Kontroll- & Nachrichtenpakete.
- **HTML5 & Vanilla JS / CSS**: Modernes responsive Dark-Theme Interface.

---

## 📄 Lizenz

MIT License
