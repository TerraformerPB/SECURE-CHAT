# Secure Chat – Ende-zu-Ende verschlüsselter Chat

Ein maximal sicherer, E2E-verschlüsselter Online-Chat mit OTP-Doppelverschlüsselung, temporären Gruppenchats, Datei- und Bildversand sowie optional verschlüsseltem localStorage.

## Architektur

```
Client A  <──WebSocket──>  Server (Relay)  <──WebSocket──>  Client B
     │                                                           │
     ├─ ECDH P-384 (Schlüsselaustausch)                          │
     ├─ AES-256-GCM ( symmetrische Verschlüsselung)              │
     ├─ OTP-XOR (zweite Schicht, 64 KB Pad, auto-erneuernd)     │
     └─ localStorage (optional, nur bei beidseitiger Zustimmung) │
```

Der Server **speichert keine Nachrichten** – er relayed nur verschlüsselte Bytes. Nur die Clients besitzen die Schlüssel.

## Sicherheitsmerkmale

| Merkmal | Beschreibung |
|---------|-------------|
| **Perfect Forward Secrecy** | Neue ECDH-P-384-Schlüssel pro Session |
| **AES-256-GCM** | Symmetrische Verschlüsselung aller Nachrichten |
| **OTP-Doppelverschlüsselung** | XOR mit einmaligem 64-KB-Pad auf AES-Ciphertext |
| **OTP-Auto-Renewal** | Neues Pad bei 80 % Verbrauch |
| **Replay-Schutz** | Monoton steigender Nonce-Zähler pro Nachricht |
| **Gruppen-E2E** | AES-256-Gruppenschlüssel, pro Mitglied mit dessen ECDH-Key verschlüsselt |
| **Datei-E2E** | AES-256-GCM (ohne OTP), gechunkt in 64-KB-Blöcken |
| **Notfall-Löschung** | Löscht alle Daten lokal + benachrichtigt Partner |
| **Storage-Dual-Consent** | Lokale Persistenz nur, wenn beide zustimmen |

## Installation

### 1. Voraussetzungen

- [Node.js](https://nodejs.org/) (v18 oder höher)

### 2. Server starten

```bash
cd server
npm install
node index.js
```

Der Server läuft standardmäßig auf **`http://0.0.0.0:8080`**.

### 3. Client öffnen

- **Empfohlen:** `start-app.ps1` ausführen (öffnet Chrome im App-Modus)
- Oder: `http://localhost:8080` im Browser öffnen
- Auf dem Smartphone/Tablet: IP des Servers im Browser eingeben (z. B. `http://192.168.1.100:8080`)

### 4. Nutzung

1. **Benutzernamen** eingeben und verbinden
2. **Chatpartner** aus der Benutzerliste auswählen
3. Automatischer **ECDH-Schlüsselaustausch** + **OTP-Übertragung**
4. Nachrichten schreiben, **Dateien/Bilder** senden (📎-Button)
5. Für Gruppen: auf **Gruppe erstellen** klicken, Mitglieder auswählen

### 5. PWA (Progressive Web App)

- Auf iOS: über Teilen-Menü → „Zum Home-Bildschirm"
- Auf Android: über Chrome-Menü → „Installieren"
- Funktioniert dann wie eine native App (offline nicht nutzbar, da WebSocket nötig)

## Projektstruktur

```
secure-chat/
├── server/
│   ├── index.js          # WebSocket-Server + HTTP-File-Server
│   ├── package.json
│   └── node_modules/
├── client/
│   ├── index.html        # UI (Login, Chat, Modals)
│   ├── style.css         # Dark Theme, responsive, PWA-Support
│   ├── app.js            # Gesamte Client-Logik (Krypto, OTP, Gruppen, Dateien, Storage)
│   ├── manifest.json     # PWA-Manifest
│   ├── sw.js             # Service Worker
│   ├── icon.svg          # SVG-Icon
│   ├── icon-192.png      # PWA-Icon 192px
│   └── icon-512.png      # PWA-Icon 512px
├── start-app.ps1         # PowerShell-Launcher (Chrome App-Modus)
└── README.md
```

## Technologien

- **WebSocket** (ws) – Echtzeit-Kommunikation
- **Web Crypto API** – ECDH P-384, AES-256-GCM, SHA-256
- **OTP** – XOR-basierte Double Encryption mit 64-KB-Pads
- **PWA** – Manifest + Service Worker + iOS-Meta-Tags

## Lizenz

MIT
