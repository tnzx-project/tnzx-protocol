// TNZX Protocol — Interactive Learn

// ===== ACTOR DEFINITIONS =====
const ACTORS = {
  alice:   { name: 'Alice',         role: 'Miner / Sender',      glyph: '\u{1F469}', type: 'alice' },
  bob:     { name: 'Bob',           role: 'Miner / Receiver',    glyph: '\u{1F468}', type: 'bob' },
  pool:    { name: 'TNZX Pool',    role: 'VS3-aware Stratum',   glyph: '\u{1F5A7}', type: 'pool' },
  extpool: { name: 'HashVault',    role: 'Standard Pool',       glyph: '\u{1F3ED}', type: 'extpool' },
  proxy:   { name: 'VS3 Proxy',    role: 'Middleware',          glyph: '\u{1F310}', type: 'proxy' },
  dpi:     { name: 'DPI Observer', role: 'Network Adversary',   glyph: '\u{1F441}', type: 'dpi' },
  mgate:   { name: 'Mining Gate',  role: 'PoW Access Control',  glyph: '\u{26D4}',  type: 'mgate' },
};

// ===== SCENARIOS =====
const SCENARIOS = [
  {
    id: 'key-exchange',
    title: 'Key Exchange',
    tag: 'VS3',
    actors: ['alice', 'pool', 'bob'],
    steps: [
      {
        title: 'Alice connects to the pool',
        body: 'Alice connects via standard Stratum TCP. She sends a <code>login</code> JSON-RPC with her Monero wallet address. The pool responds with a miner ID and initial job.',
        detail: '{ "method": "login", "params": { "login": "4...Alice", "pass": "x", "agent": "tnzxminer/1.0" } }\n\nPool response: { "result": { "id": "miner01", "job": {...}, "extensions": { "vs3_session": "a1b2..." } } }',
        messages: [{ from: 'alice', to: 'pool', label: 'login (wallet)', style: 'data', y: 130 }],
        highlight: ['alice', 'pool']
      },
      {
        title: 'Bob also connects to the same pool',
        body: 'Bob connects independently. Both miners now have active Stratum sessions with the pool. Neither knows the other exists yet.',
        detail: '{ "method": "login", "params": { "login": "4...Bob", "pass": "x", "agent": "tnzxminer/1.0" } }',
        messages: [{ from: 'bob', to: 'pool', label: 'login (wallet)', style: 'data', y: 150 }],
        highlight: ['bob', 'pool']
      },
      {
        title: 'Alice generates an X25519 keypair',
        body: 'Alice generates an <strong>ephemeral X25519 keypair</strong> for key exchange. The public key is 32 bytes. She will send it to Bob through the pool using ghost shares.',
        detail: 'const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");\n// publicKey: 32 bytes (sent to Bob)\n// privateKey: 32 bytes (kept secret)',
        messages: [],
        highlight: ['alice'],
        frame: { type: 'pubkey', bytes: 'aa 03 04 00 01 01 01 20 85 20 f0 09 89 30 a7 54 74 8b 7d dc b4 3e f7 5a 0d bf 3a 0d 26 38 1a f4 eb a4 a9 8e aa 9b 4e 6a' }
      },
      {
        title: 'Alice sends KEY_EXCHANGE via ghost shares',
        body: 'Alice wraps her public key in a <strong>VS3 frame</strong> with type <code>KEY_EXCHANGE (0x04)</code>. The frame is chunked into 5-byte ghost shares and submitted to the pool. Each ghost share has <code>nonce[0] = 0xAA</code> (sentinel) and <code>result = "000...0"</code> (no valid PoW).',
        detail: 'Frame: [AA][03][04][0001][00][01][20] + 32 bytes pubkey\n        mag ver typ  msgId  fi ft len\n\nChunked into ceil(40/5) = 8 ghost shares:\n  Share 1: nonce=aa030400, ntime=hihi0001  vs3_to="4...Bob"\n  Share 2: nonce=aa000120, ntime=hihi8520\n  ...\n  Share 8: nonce=aa9b4e6a, ntime=hihi0000  (zero-padded)',
        messages: [{ from: 'alice', to: 'pool', label: 'Ghost shares [KEY_EXCHANGE + pubkey]', style: 'encrypt', y: 160 }],
        highlight: ['alice', 'pool'],
        frame: { type: 'ghost-share', bytes: 'aa 03 04 00 nonce[1..3]=payload ntime[2..3]=payload result=0x00...00' }
      },
      {
        title: 'Pool detects ghost shares, reassembles frame',
        body: 'The pool sees <code>nonce[0] = 0xAA</code> (or verifies HMAC in HMAC mode). It recognizes these as ghost shares, extracts the 5-byte payload from each, and reassembles the VS3 frame. The pool sees <code>type = 0x04 KEY_EXCHANGE</code> and the <code>vs3_to</code> field pointing to Bob\'s wallet.',
        detail: 'Pool logic (pseudocode):\n  if nonce[0] == 0xAA:\n    payload = nonce[1..3] + ntime[2..3]   // 5 bytes\n    buffer.push(payload)\n    if frame_complete:\n      route to vs3_to recipient\n\nPool CANNOT read encrypted content (type 0x05)\nPool CAN read type 0x04 (key exchange is cleartext pubkey)',
        messages: [],
        highlight: ['pool']
      },
      {
        title: 'Pool forwards to Bob via job notification',
        body: 'The pool includes Alice\'s frame in Bob\'s next <strong>job notification</strong>, in a special <code>vs3</code> field. Bob\'s StratumClient detects the field and extracts the frame.',
        detail: '{ "method": "job", "params": {\n    "job_id": "abc123",\n    "blob": "...",\n    "target": "...",\n    "vs3": "aa0304000101012085...4e6a"  // Alice\'s KEY_EXCHANGE frame\n  }\n}',
        messages: [{ from: 'pool', to: 'bob', label: 'Job notification [vs3: Alice pubkey]', style: 'encrypt', y: 180 }],
        highlight: ['pool', 'bob']
      },
      {
        title: 'Bob receives Alice\'s public key',
        body: 'Bob parses the VS3 frame, sees <code>type = KEY_EXCHANGE</code>, and stores Alice\'s X25519 public key. Bob now generates his own keypair and sends his public key back through the same mechanism.',
        detail: 'Bob receives: frame.type = 0x04, frame.payload = Alice_pubkey (32 bytes)\nBob stores: peers["4...Alice"] = { publicKey: Alice_pubkey }\nBob generates own keypair and queues KEY_EXCHANGE response',
        messages: [{ from: 'bob', to: 'pool', label: 'Ghost shares [KEY_EXCHANGE + Bob pubkey]', style: 'encrypt', y: 200 }],
        highlight: ['bob', 'pool']
      },
      {
        title: 'Pool routes Bob\'s key to Alice',
        body: 'The pool reassembles Bob\'s KEY_EXCHANGE frame and includes it in Alice\'s next job notification. Alice receives Bob\'s public key.',
        messages: [{ from: 'pool', to: 'alice', label: 'Job notification [vs3: Bob pubkey]', style: 'encrypt', y: 220 }],
        highlight: ['pool', 'alice']
      },
      {
        title: 'Shared secret established',
        body: 'Both Alice and Bob now have each other\'s X25519 public keys. They can compute the <strong>shared secret</strong> via ECDH and derive encryption keys using <strong>HKDF-SHA256</strong> with domain string <code>"tnzx-e2e-v3"</code>.',
        detail: 'Alice: shared = X25519(Alice_privkey, Bob_pubkey)\nBob:   shared = X25519(Bob_privkey, Alice_pubkey)\n// Both produce identical 32-byte shared secret\n\nKey derivation:\n  K = HKDF-SHA256(shared, random_salt, "tnzx-e2e-v3")\n\nReady for XChaCha20-Poly1305 encryption.',
        messages: [],
        highlight: ['alice', 'bob']
      }
    ]
  },

  {
    id: 'encrypted-message',
    title: 'E2E Encrypted Message',
    tag: 'VS3',
    actors: ['alice', 'pool', 'bob'],
    steps: [
      {
        title: 'Alice wants to send "Hello Bob"',
        body: 'After key exchange, Alice wants to send an encrypted message to Bob. She has Bob\'s X25519 public key from the key exchange phase.',
        messages: [],
        highlight: ['alice']
      },
      {
        title: 'One-shot encryption (PFS)',
        body: 'Alice uses <strong>one-shot encryption</strong> with Perfect Forward Secrecy. She generates a fresh ephemeral X25519 keypair, computes a shared secret with Bob\'s public key, and derives a unique key. The ephemeral private key is immediately discarded.',
        detail: '1. e_priv, e_pub = generateKeyPair("x25519")\n2. shared = X25519(e_priv, Bob_pubkey)\n3. salt = random(32 bytes)\n4. K = HKDF-SHA256(shared, salt, "tnzx-e2e-v3")\n5. nonce = random(24 bytes)   // XChaCha20 uses 24-byte nonces\n6. AAD = "tnzx-oneshot-v3" || replayId || e_pub\n7. ciphertext = XChaCha20-Poly1305(K, nonce, "Hello Bob", AAD)\n8. DESTROY e_priv',
        messages: [],
        highlight: ['alice'],
        frame: { type: 'oneshot', bytes: 'replayId(16) + e_pub(32) + salt(32) + nonce(24) + ciphertext + tag(16) = 120+ bytes' }
      },
      {
        title: 'Wrap in encrypted type envelope',
        body: 'The real message type (0x01 TEXT) is prepended to the encrypted payload, then the whole thing is wrapped as <code>type 0x05 ENCRYPTED</code>. On the wire, every frame looks identical: <code>0x05</code>. The pool cannot distinguish text messages from key exchanges from ACKs.',
        detail: 'wrapTypedPayload(MSG_TYPE.TEXT, ciphertext):\n  inner = [0x01] + encrypted_payload     // real type hidden inside\n  frame = buildVS3Frame(inner, 0x05)     // external type always 0x05\n\nWhat the pool sees:  type = 0x05 ENCRYPTED\nWhat Bob decrypts:   type = 0x01 TEXT, payload = "Hello Bob"',
        messages: [],
        highlight: ['alice']
      },
      {
        title: 'Frame chunked into ghost shares',
        body: 'The VS3 frame (header + encrypted payload) is chunked into <strong>5-byte pieces</strong>. Each chunk becomes a ghost share: <code>nonce[0]=0xAA</code> sentinel, <code>nonce[1..3]</code> = first 3 payload bytes, <code>ntime[2..3]</code> = next 2 bytes. Shares are paced at 150ms intervals.',
        detail: '"Hello Bob" encrypted = ~130 bytes\n+ VS3 header (8 bytes) = ~138 bytes\nChunks: ceil(138/5) = 28 ghost shares\nTime to send: 28 * 150ms = 4.2 seconds\n\nEach share: { method: "submit", params: {\n  nonce: "aaPPPPPP",    // AA + 3 payload bytes\n  ntime: "hhhhPPPP",    // epoch hi + 2 payload bytes\n  result: "000...000",   // no valid PoW\n  vs3_to: "4...Bob"     // only on first share\n}}',
        messages: [{ from: 'alice', to: 'pool', label: '28 ghost shares [0x05 ENCRYPTED]', style: 'ghost', y: 160 }],
        highlight: ['alice', 'pool']
      },
      {
        title: 'Pool reassembles and routes',
        body: 'The pool collects ghost shares, reassembles the frame. It sees <code>type = 0x05 ENCRYPTED</code> and <code>vs3_to = Bob\'s wallet</code>. It <strong>cannot read the message</strong> — it just routes the opaque bytes to Bob via his next job notification.',
        detail: 'Pool log:\n  [ghost] miner01 share #1  nonce=aa... → frame buffer\n  [ghost] miner01 share #2  nonce=aa... → frame buffer\n  ...\n  [ghost] miner01 share #28 nonce=aa... → frame COMPLETE\n  [route] frame type=0x05 ENCRYPTED, 138 bytes → Bob (4...Bob)\n  // Pool sees ONLY: type=0x05. Cannot read content, real type, or text.',
        messages: [{ from: 'pool', to: 'bob', label: 'Job [vs3: 0x05 encrypted frame]', style: 'encrypt', y: 190 }],
        highlight: ['pool', 'bob']
      },
      {
        title: 'Bob decrypts the message',
        body: 'Bob receives the frame, sees <code>type = 0x05</code>, extracts the ephemeral public key, computes the shared secret, derives the key, decrypts, verifies the Poly1305 tag, checks the replay ID, and unwraps the inner type to get <code>0x01 TEXT</code> + <code>"Hello Bob"</code>.',
        detail: 'Bob:\n1. Parse frame → type=0x05, payload = encrypted blob\n2. Extract: replayId(16) + e_pub(32) + salt(32) + nonce(24) + ciphertext + tag\n3. shared = X25519(Bob_privkey, e_pub)\n4. K = HKDF-SHA256(shared, salt, "tnzx-e2e-v3")\n5. plaintext = XChaCha20-Poly1305.decrypt(K, nonce, ciphertext, AAD)\n6. Check replayId not in cache (5-min TTL)\n7. unwrapTypedPayload(plaintext) → realType=0x01, payload="Hello Bob"\n8. emit("message", { from: "4...Alice", text: "Hello Bob" })',
        messages: [],
        highlight: ['bob']
      }
    ]
  },

  {
    id: 'ghost-share-encoding',
    title: 'Ghost Share Encoding',
    tag: 'VS3-Monero',
    actors: ['alice', 'pool'],
    steps: [
      {
        title: 'What is a ghost share?',
        body: 'A <strong>ghost share</strong> is a Stratum <code>submit</code> that carries data instead of valid proof-of-work. The <code>result</code> field is all zeros — no hash computation needed. The pool accepts it if it detects the VS3 sentinel.',
        detail: 'Regular share:  result = "3f7a8b..." (valid hash below target)\nGhost share:    result = "000000..." (no PoW, data carrier only)\n\nThe pool distinguishes them:\n  if difficulty > ghostDiffMax → real mining share\n  elif nonce[0] == 0xAA       → VS3 ghost share (extract payload)\n  else                         → regular share (process normally)',
        messages: [],
        highlight: ['alice', 'pool']
      },
      {
        title: 'VS3-Monero encoding: 5 bytes per share',
        body: 'In VS3-Monero profile, each ghost share carries <strong>5 bytes of payload</strong>. The bytes are embedded in the <code>nonce</code> (4 bytes) and <code>ntime</code> (4 bytes) fields.',
        detail: 'nonce (4 bytes):  [0xAA] [P0] [P1] [P2]\n                   sentinel  payload bytes 0-2\n\nntime (4 bytes):  [epoch_hi] [epoch_hi] [P3] [P4]\n                   real time (preserved)  payload bytes 3-4\n\nTotal: 5 payload bytes per ghost share',
        messages: [],
        highlight: ['alice'],
        frame: { type: 'ghost-nonce', bytes: 'AA 48 65 6C|65 B2 6C 6F', labels: ['nonce: AA + "Hel"', 'ntime: epoch + "lo"'] }
      },
      {
        title: 'Example: encoding "Hello"',
        body: 'Let\'s encode the ASCII string <code>"Hello"</code> (5 bytes: <code>48 65 6C 6C 6F</code>) into one ghost share. The current epoch high word is <code>65B2</code>.',
        detail: 'Payload: "Hello" = [0x48, 0x65, 0x6C, 0x6C, 0x6F]\n\nnonce = 0xAA486C6C    →  sentinel + bytes 0,1,2\n         ↑↑ ↑↑↑↑\n         AA H  e  l\n\nntime = 0x65B26C6F    →  epoch_hi + bytes 3,4\n         ↑↑↑↑ ↑↑↑↑\n         real  l  o\n\nresult = "0000000000000000000000000000000000000000000000000000000000000000"\n\nJSON-RPC submit:\n  { "method": "submit", "params": {\n      "id": "miner01",\n      "nonce": "aa48656c",\n      "result": "00...00",\n      "ntime": "65b26c6f"\n  }}',
        messages: [{ from: 'alice', to: 'pool', label: 'submit {nonce:"aa48656c", ntime:"65b26c6f"}', style: 'ghost', y: 160 }],
        highlight: ['alice', 'pool'],
        frame: { type: 'nonce-detail', bytes: 'AA 48 65 6C 65 B2 6C 6F' }
      },
      {
        title: 'Pool extracts payload',
        body: 'The pool sees <code>nonce[0] = 0xAA</code>, identifies it as a ghost share. It extracts 3 bytes from <code>nonce[1..3]</code> and 2 bytes from <code>ntime[2..3]</code>, producing the 5-byte payload <code>[48 65 6C 6C 6F]</code>.',
        detail: 'Pool extraction:\n  nonce  = aa 48 65 6c\n  ntime  = 65 b2 6c 6f\n\n  payload[0] = nonce[1] = 0x48  (H)\n  payload[1] = nonce[2] = 0x65  (e)\n  payload[2] = nonce[3] = 0x6c  (l)\n  payload[3] = ntime[2] = 0x6c  (l)\n  payload[4] = ntime[3] = 0x6f  (o)\n\n  Extracted: [48 65 6C 6C 6F] = "Hello"',
        messages: [],
        highlight: ['pool']
      },
      {
        title: 'HMAC sentinel mode (anti-DPI)',
        body: 'The fixed <code>0xAA</code> sentinel is detectable by DPI after ~256 shares. In <strong>HMAC mode</strong>, the sentinel is replaced by <code>HMAC-SHA256(sessionKey, nonce[1..3])[0]</code> — a different value for every share, indistinguishable from random.',
        detail: 'Key derivation (at login):\n  vs3_session = pool provides 32-byte token\n  sessionKey = HKDF-SHA256(vs3_session, wallet, "tnzx-ghost-v1")\n\nPer share:\n  nonce[1..3] = payload\n  nonce[0]    = HMAC-SHA256(sessionKey, nonce[1..3])[0]\n\nVerification (pool):\n  expected = HMAC-SHA256(sessionKey, nonce[1..3])[0]\n  if nonce[0] == expected → ghost share\n  else → regular share\n\nDPI observer: nonce[0] appears uniformly random.\nNo statistical test can detect ghost shares.',
        messages: [],
        highlight: ['alice', 'pool']
      }
    ]
  },

  {
    id: 'mining-gate',
    title: 'Mining Gate',
    tag: 'VS2',
    actors: ['alice', 'pool', 'mgate'],
    steps: [
      {
        title: 'What is Mining Gate?',
        body: 'Mining Gate is the <strong>PoW-gated access control</strong> system. You must actively mine to use the VS communication channel. This provides anti-spam, economic sustainability, and natural cover traffic — all from one mechanism.',
        detail: 'State machine:\n  INACTIVE → GRACE → ACTIVE ↔ SUSPENDED\n\nINACTIVE: never mined, VS channel CLOSED\nGRACE:    first 2 minutes, needs 3 valid shares\nACTIVE:   mining above threshold, VS channel OPEN\nSUSPENDED: dropped below threshold, 5-min cooldown',
        messages: [],
        highlight: ['mgate']
      },
      {
        title: 'T+0s: Alice connects (INACTIVE)',
        body: 'Alice connects to the pool. Her Mining Gate state is <code>INACTIVE</code>. The VS communication channel is <strong>closed</strong>. She cannot send or receive messages.',
        messages: [{ from: 'alice', to: 'pool', label: 'login', style: 'data', y: 140 }],
        highlight: ['alice', 'pool'],
        detail: 'State: INACTIVE\nVS Channel: CLOSED\nShares in window: 0\nRequired for GRACE → ACTIVE: 3 valid shares'
      },
      {
        title: 'T+5s: First valid share (GRACE)',
        body: 'Alice submits her first <strong>real mining share</strong> (valid PoW, not a ghost). Mining Gate transitions to <code>GRACE</code> — a 2-minute observation period. She needs 2 more valid shares.',
        messages: [{ from: 'alice', to: 'pool', label: 'submit (valid PoW share #1)', style: 'data', y: 160 }],
        highlight: ['alice', 'mgate'],
        detail: 'State: INACTIVE → GRACE\nVS Channel: still CLOSED\nGrace period: 120 seconds remaining\nShares: 1/3 for activation'
      },
      {
        title: 'T+15s & T+25s: More shares',
        body: 'Alice submits 2 more valid shares within the grace period.',
        messages: [
          { from: 'alice', to: 'pool', label: 'valid share #2', style: 'data', y: 170 },
          { from: 'alice', to: 'pool', label: 'valid share #3', style: 'data', y: 195 }
        ],
        highlight: ['alice', 'mgate'],
        detail: 'State: GRACE (2/3 → 3/3)\nminSharesActivation reached!'
      },
      {
        title: 'T+25s: ACTIVE — channel opens',
        body: 'With 3 valid shares submitted, Mining Gate transitions to <code>ACTIVE</code>. The VS communication channel is now <strong>OPEN</strong>. Alice can send and receive encrypted messages via ghost shares.',
        detail: 'State: GRACE → ACTIVE\nVS Channel: OPEN ✓\n\nFormula:\n  mining_active = (shares_in_window / expected_shares) >= threshold\n  expected_shares = (hashrate / difficulty) × window_seconds\n  threshold = 0.5 (50% of expected rate)\n\nAlice can now send ghost shares.',
        messages: [{ from: 'mgate', to: 'alice', label: 'VS channel OPEN', style: 'ghost', y: 220 }],
        highlight: ['alice', 'mgate']
      },
      {
        title: 'T+700s: No mining for 10 min (SUSPENDED)',
        body: 'Alice stops mining. After the 10-minute sliding window shows below-threshold hashrate, Mining Gate transitions to <code>SUSPENDED</code>. The VS channel <strong>closes</strong>. There\'s a 5-minute cooldown before she can reactivate.',
        detail: 'State: ACTIVE → SUSPENDED\nVS Channel: CLOSED\nCooldown: 300 seconds\nReason: shares_in_window / expected_shares < 0.5',
        messages: [{ from: 'mgate', to: 'alice', label: 'VS channel CLOSED (suspended)', style: 'danger', y: 240 }],
        highlight: ['alice', 'mgate']
      },
      {
        title: 'T+1000s: Resume mining → ACTIVE again',
        body: 'Alice resumes mining. After submitting enough shares to meet the threshold, Mining Gate transitions back to <code>ACTIVE</code>. The channel reopens.',
        messages: [
          { from: 'alice', to: 'pool', label: 'resume mining (valid shares)', style: 'data', y: 250 },
          { from: 'mgate', to: 'alice', label: 'VS channel OPEN (reactivated)', style: 'ghost', y: 275 }
        ],
        highlight: ['alice', 'mgate'],
        detail: 'State: SUSPENDED → ACTIVE\nVS Channel: OPEN ✓\nThe cycle continues: mine to communicate.'
      }
    ]
  },

  {
    id: 'proxy-mode',
    title: 'Proxy Mode',
    tag: 'VS3',
    actors: ['alice', 'proxy', 'extpool', 'bob'],
    steps: [
      {
        title: 'Why a proxy?',
        body: 'Not all pools are TNZX-aware. The <strong>VS3 Proxy</strong> sits between miners and a standard pool (e.g., HashVault). It intercepts ghost shares, reassembles frames, routes messages — the external pool never knows VS3 exists.',
        messages: [],
        highlight: ['proxy']
      },
      {
        title: 'Alice connects to the proxy',
        body: 'Alice connects to the VS3 Proxy as if it were a regular Stratum pool. The proxy assigns her a miner ID and provides a <code>vs3_session</code> token for HMAC sentinel mode.',
        messages: [{ from: 'alice', to: 'proxy', label: 'login (wallet)', style: 'data', y: 140 }],
        highlight: ['alice', 'proxy'],
        detail: 'Proxy response includes:\n  extensions: { vs3_session: "random32bytes..." }\n\nHMAC key derivation:\n  sessionKey = HKDF-SHA256(vs3_session, wallet, "tnzx-ghost-v1")'
      },
      {
        title: 'Proxy connects upstream to HashVault',
        body: 'The proxy opens its own Stratum connection to HashVault (or any standard pool). It logs in with a wallet address. HashVault sees a normal miner.',
        messages: [{ from: 'proxy', to: 'extpool', label: 'login (proxy wallet)', style: 'data', y: 160 }],
        highlight: ['proxy', 'extpool'],
        detail: 'HashVault sees: a single miner connecting via standard Stratum.\nNo VS3 extensions, no ghost shares, no special fields.'
      },
      {
        title: 'Alice sends a real mining share',
        body: 'Alice submits a valid mining share. The proxy detects it\'s NOT a ghost share (HMAC check fails or nonce[0] != sentinel) and <strong>forwards it upstream</strong> to HashVault. Alice earns mining rewards normally.',
        messages: [
          { from: 'alice', to: 'proxy', label: 'submit (valid PoW)', style: 'data', y: 180 },
          { from: 'proxy', to: 'extpool', label: 'forward submit', style: 'data', y: 200 }
        ],
        highlight: ['alice', 'proxy', 'extpool']
      },
      {
        title: 'Alice sends ghost shares (message to Bob)',
        body: 'Alice sends ghost shares carrying an encrypted message. The proxy detects the HMAC sentinel, extracts the payload, reassembles the VS3 frame. It does <strong>NOT forward</strong> ghost shares to HashVault (they would be rejected as invalid).',
        messages: [
          { from: 'alice', to: 'proxy', label: 'ghost shares [0x05 ENCRYPTED]', style: 'ghost', y: 220 },
        ],
        highlight: ['alice', 'proxy'],
        detail: 'Proxy logic:\n  if HMAC(sessionKey, nonce[1..3])[0] == nonce[0]:\n    → ghost share, extract payload, DO NOT forward\n  else:\n    → real share, forward to upstream pool'
      },
      {
        title: 'Proxy routes to Bob',
        body: 'The proxy holds the reassembled frame and includes it in Bob\'s next job notification via the <code>vs3</code> field. Bob decrypts it normally.',
        messages: [
          { from: 'proxy', to: 'bob', label: 'job [vs3: encrypted frame]', style: 'encrypt', y: 250 }
        ],
        highlight: ['proxy', 'bob'],
        detail: 'HashVault never sees:\n  - Ghost shares (intercepted by proxy)\n  - VS3 frames (internal to proxy)\n  - vs3_session tokens (proxy-only extension)\n\nHashVault DOES see:\n  - Normal valid mining shares\n  - Standard Stratum protocol'
      },
      {
        title: 'External pool is completely unaware',
        body: 'From HashVault\'s perspective, nothing unusual is happening. It processes mining shares and pays out normally. The VS3 communication layer is <strong>entirely invisible</strong> to the external pool — and to any DPI observer watching the proxy→HashVault connection.',
        messages: [],
        highlight: ['extpool'],
        detail: 'The proxy architecture means:\n  1. ANY Stratum pool can be used (no pool cooperation needed)\n  2. Mining rewards flow normally\n  3. VS3 traffic is invisible to the upstream pool\n  4. DPI between proxy and pool sees only legitimate mining traffic'
      }
    ]
  },

  {
    id: 'dpi-observer',
    title: 'DPI Adversary View',
    tag: 'Security',
    actors: ['alice', 'dpi', 'pool'],
    steps: [
      {
        title: 'A DPI observer monitors Alice\'s traffic',
        body: 'A Deep Packet Inspection system watches all traffic between Alice and the pool. It can read every byte. What does it see?',
        messages: [{ from: 'alice', to: 'dpi', label: 'TCP traffic (Stratum JSON-RPC)', style: 'danger', y: 140 }],
        highlight: ['dpi']
      },
      {
        title: 'It sees: standard Stratum protocol',
        body: 'The DPI sees <code>login</code>, <code>job</code>, and <code>submit</code> JSON-RPC messages — exactly what any cryptocurrency miner produces. The protocol is Stratum, commonly used for mining Monero, Bitcoin, etc.',
        detail: 'DPI observes:\n  → { "method": "login", "params": { "login": "4...wallet" } }\n  ← { "result": { "id": "miner01", "job": {...} } }\n  → { "method": "submit", "params": { "nonce": "a1b2c3d4", "result": "3f7a8b..." } }\n  ← { "result": { "status": "OK" } }\n\nVerdict: legitimate cryptocurrency mining.',
        messages: [],
        highlight: ['dpi']
      },
      {
        title: 'Ghost shares look like regular shares',
        body: 'Ghost shares are <code>submit</code> messages with nonce and result fields. The nonce values appear random (especially in HMAC mode). The result is all zeros — but the DPI would need to validate the hash against the block template to detect this.',
        detail: 'Regular share:  { "nonce": "a1b2c3d4", "result": "000f8a..." }  ← valid hash\nGhost share:    { "nonce": "7e48656c", "result": "000000..." }  ← all zeros\n\nTo distinguish: DPI must reconstruct block header + compute hash.\nThis requires: current job template (blob), which the DPI may not have.\n\nIn HMAC mode: nonce[0] is HMAC output, appears random.\nNo statistical test distinguishes it from legitimate nonces.',
        messages: [{ from: 'alice', to: 'pool', label: 'submit (ghost? or real?)', style: 'info', y: 180 }],
        highlight: ['dpi']
      },
      {
        title: 'The entropy argument',
        body: 'XChaCha20 output is computationally indistinguishable from random. Nonce fields in mining are uniformly distributed. Encrypted payload bytes embedded in nonce fields have the <strong>same statistical distribution</strong> as legitimate nonce bytes. This is the information-theoretic argument for undetectability.',
        detail: 'Paper Section 7.2:\n\n  "The XChaCha20 keystream is a PRF output;\n   ciphertext bytes are computationally uniform.\n   Nonce bytes in legitimate mining are uniform\n   (the miner varies them to find a valid hash).\n   Therefore: encrypted payload bytes embedded\n   in nonce fields are distribution-equivalent\n   to legitimate mining traffic."\n\nCaveat: ntime field replacement IS detectable\n(timestamps become non-monotonic).\nThis is a known limitation documented in the spec.',
        messages: [],
        highlight: ['dpi']
      },
      {
        title: 'What the DPI cannot determine',
        body: 'Even if the DPI suspects steganographic communication, it <strong>cannot read the content</strong> (XChaCha20-Poly1305 encryption), <strong>cannot identify the recipient</strong> (vs3_to field is in cleartext JSON but meaningless without pool context), and <strong>cannot selectively block ghost shares</strong> without blocking all mining traffic.',
        detail: 'DPI capabilities vs TNZX:\n  ✗ Read message content         → E2E encrypted\n  ✗ Identify message type         → encrypted envelope (all = 0x05)\n  ✗ Block ghost shares only        → must block ALL mining traffic\n  ✗ Detect HMAC sentinel           → appears random\n  ~ Detect result=0x00 shares      → needs hash validation (expensive)\n  ✓ Block all mining traffic        → "nuclear option" (economic consequences)\n  ✓ Endpoint compromise             → bypasses all network protection',
        messages: [],
        highlight: ['dpi']
      }
    ]
  },

  {
    id: 'frame-format',
    title: 'VS3 Frame Format',
    tag: 'Reference',
    actors: ['alice', 'pool'],
    steps: [
      {
        title: 'VS3 frame structure (8-byte header)',
        body: 'Every VS3 message is wrapped in a frame with an 8-byte header followed by the payload. The header carries routing and fragmentation info.',
        frame: { type: 'vs3-header', bytes: 'AA 03 05 00 0A 00 01 1E', labels: [
          'MAGIC (0xAA)', 'VERSION (0x03=VS3)', 'TYPE (0x05=ENCRYPTED)', 'MSG_ID hi', 'MSG_ID lo',
          'FRAG_IDX (0=first)', 'FRAG_TOTAL (1=no frag)', 'PAYLOAD_LEN (30 bytes)'
        ]},
        messages: [],
        highlight: ['alice'],
        detail: 'Offset  Field           Size  Description\n[0]     MAGIC_BYTE       1    0xAA — frame boundary marker\n[1]     version          1    0x03 = VS3\n[2]     type             1    MSG_TYPE (0x05 ENCRYPTED on wire)\n[3-4]   message_id       2    16-bit big-endian (ties fragments)\n[5]     fragment_index   1    0-based fragment number\n[6]     fragment_total   1    Total fragments (1 = single frame)\n[7]     payload_len      1    Bytes in this fragment (max 128)'
      },
      {
        title: 'Fragmentation: large messages',
        body: 'Messages larger than 128 bytes are <strong>fragmented</strong> across multiple frames. Max 50 fragments per message = ~6,400 bytes max message size. Each fragment shares the same <code>message_id</code> and is numbered 0..N-1.',
        detail: 'Example: 400-byte encrypted message\n\nFrame 0: [AA][03][05][00 0A][00][04][80] + 128 bytes\nFrame 1: [AA][03][05][00 0A][01][04][80] + 128 bytes\nFrame 2: [AA][03][05][00 0A][02][04][80] + 128 bytes\nFrame 3: [AA][03][05][00 0A][03][04][10] + 16 bytes\n\n4 frames, same message_id=0x000A\nTotal ghost shares: 4 × ceil(136/5) = 4 × 28 = 112 shares\nTime at 150ms pace: 16.8 seconds',
        messages: [],
        highlight: ['alice']
      },
      {
        title: 'Message types (MSG_TYPE)',
        body: 'The protocol defines 6 message types. On the wire, <strong>all frames show type 0x05</strong> due to the encrypted type envelope. The real type is the first byte of the decrypted payload.',
        detail: 'MSG_TYPE = {\n  TEXT:         0x01,  // Text message\n  ACK:          0x02,  // Delivery acknowledgment\n  PING:         0x03,  // Keepalive / latency check\n  KEY_EXCHANGE: 0x04,  // X25519 public key (cleartext)\n  ENCRYPTED:    0x05,  // ← external wire type for ALL frames\n  HASHCASH:     0x06,  // PoW token for Mining Gate\n}\n\nTypes 0x07–0xFF: available for applications',
        messages: [],
        highlight: []
      },
      {
        title: 'Encrypted type envelope',
        body: 'Before encryption, the real message type is prepended to the payload: <code>[real_type] + [payload]</code>. Then the whole thing is encrypted and wrapped as type <code>0x05</code>. The pool sees only <code>0x05</code> for every frame — it cannot distinguish a text message from a key exchange from an ACK.',
        detail: 'Sender (Alice):\n  inner = [0x01] + encrypt("Hello Bob")    // real type = TEXT\n  frame = buildVS3Frame(inner, 0x05)       // wire type = ENCRYPTED\n\nPool sees:        type = 0x05  (opaque)\nBob decrypts:     [0x01] + "Hello Bob"\n  → real type = 0x01 TEXT\n  → payload = "Hello Bob"',
        messages: [],
        highlight: []
      }
    ]
  },

  {
    id: 'protocol-evolution',
    title: 'VS1 → VS2 → VS3',
    tag: 'Overview',
    actors: ['alice', 'pool', 'bob'],
    steps: [
      {
        title: 'VS1: PNG steganography (2025)',
        body: '<strong>Visual Stratum 1</strong> — the original. Hides data in PNG image pixels using LSB steganography. Pool sends "mining stats charts" to miners via HTTPS. The chart pixels carry hidden encrypted data. Download-only; 45 KB per image.',
        detail: 'Channel:    PNG images over HTTPS (port 443)\nDirection:  Pool → Miner (download only)\nCapacity:   400×300 px × 3 channels × 1 bit = 45,000 bytes\nEncryption: XChaCha20-Poly1305 + X25519 ECDH\nCover:      Real mining statistics charts\nLimitations: No upload, no anti-spam, no economic model',
        messages: [{ from: 'pool', to: 'alice', label: 'HTTPS: PNG chart (45KB hidden data)', style: 'data', y: 160 }],
        highlight: ['pool', 'alice']
      },
      {
        title: 'VS2: Mining Gate + Stratum embedding (2026)',
        body: '<strong>Visual Stratum 2</strong> adds two key innovations: <strong>Mining Gate</strong> (PoW-gated access) and <strong>Stratum embedding</strong> (data hidden in mining share fields). This gives bidirectional communication and anti-spam.',
        detail: 'New in VS2:\n  1. Mining Gate — must mine to communicate\n  2. Stratum share embedding — upload channel\n     STEALTH: 1 byte/share (nonce LSB nibbles)\n     STANDARD: 3 bytes/share (nonce + extranonce2)\n     EXTENDED: 7 bytes/share (+ ntime)\n\nEconomic model:\n  Mining fees fund infrastructure\n  PoW prevents spam\n  Real mining provides cover traffic',
        messages: [
          { from: 'alice', to: 'pool', label: 'Stratum shares (embedded data)', style: 'ghost', y: 160 },
          { from: 'pool', to: 'alice', label: 'PNG charts (hidden response)', style: 'data', y: 185 }
        ],
        highlight: ['alice', 'pool']
      },
      {
        title: 'VS3: Multi-channel + Ghost shares (2026)',
        body: '<strong>Visual Stratum 3</strong> — the current version. Introduces <strong>ghost shares</strong> (no PoW needed for data), <strong>encrypted type envelope</strong>, <strong>HMAC sentinel</strong>, and specifies 4 transport channels for adaptive mode selection.',
        detail: 'New in VS3:\n  1. Ghost shares — no valid PoW, pure data carrier\n  2. Encrypted type envelope — all frames = 0x05\n  3. HMAC sentinel — anti-DPI, replaces 0xAA\n  4. 4 transport channels:\n     L1 Stratum:  5-256 B/share  (implemented)\n     L2 HTTP/2:   100 KB/s       (specified)\n     L3 WebSocket: 50 KB/s       (specified)\n     L4 PNG LSB:   45 KB/s       (specified)\n  5. Adaptive modes: ANON / BALANCED / SPEED\n  6. One-shot PFS encryption\n  7. Compact session encryption (-64% overhead)',
        messages: [
          { from: 'alice', to: 'pool', label: 'Ghost shares [0x05 ENCRYPTED]', style: 'ghost', y: 155 },
          { from: 'pool', to: 'bob', label: 'Job [vs3: frame]', style: 'encrypt', y: 180 },
        ],
        highlight: ['alice', 'pool', 'bob']
      }
    ]
  }
];

// ===== STATE =====
let currentScenario = null;
let currentStep = -1;
let autoPlayInterval = null;
let renderedMessages = [];

// ===== BOOT =====
document.addEventListener('DOMContentLoaded', () => {
  renderNav();
  loadScenario(SCENARIOS[0].id);
});

// ===== NAV =====
function renderNav() {
  const nav = document.getElementById('scenario-nav');
  for (const sc of SCENARIOS) {
    const btn = document.createElement('button');
    btn.className = 'scenario-btn';
    btn.dataset.id = sc.id;
    btn.innerHTML = `${sc.title} <span class="sc-tag">${sc.tag}</span>`;
    btn.onclick = () => loadScenario(sc.id);
    nav.appendChild(btn);
  }
}

function loadScenario(id) {
  stopAutoPlay();
  currentScenario = SCENARIOS.find(s => s.id === id);
  if (!currentScenario) return;

  // Update nav
  document.querySelectorAll('.scenario-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.id === id);
  });

  currentStep = -1;
  renderedMessages = [];
  renderActors();
  clearStage();
  nextStep();
}

// ===== ACTORS =====
function renderActors() {
  const row = document.getElementById('actors-row');
  row.innerHTML = '';

  const stage = document.getElementById('stage');
  // Remove old lifelines
  stage.querySelectorAll('.actor-lifeline').forEach(el => el.remove());

  for (const actorId of currentScenario.actors) {
    const a = ACTORS[actorId];
    const el = document.createElement('div');
    el.className = 'actor';
    el.id = `actor-${actorId}`;
    el.dataset.type = a.type;
    el.innerHTML = `
      <div class="actor-avatar">${a.glyph}</div>
      <div class="actor-name">${a.name}</div>
      <div class="actor-role">${a.role}</div>`;
    row.appendChild(el);
  }

  // Add lifelines after layout
  requestAnimationFrame(() => {
    for (const actorId of currentScenario.actors) {
      const actorEl = document.getElementById(`actor-${actorId}`);
      if (!actorEl) continue;
      const rect = actorEl.getBoundingClientRect();
      const stageRect = stage.getBoundingClientRect();
      const x = rect.left - stageRect.left + rect.width / 2;

      const line = document.createElement('div');
      line.className = 'actor-lifeline';
      line.style.left = x + 'px';
      stage.appendChild(line);
    }
  });
}

// ===== STEP CONTROL =====
function nextStep() {
  if (!currentScenario) return;
  if (currentStep >= currentScenario.steps.length - 1) {
    stopAutoPlay();
    return;
  }
  currentStep++;
  renderStep();
}

function prevStep() {
  if (currentStep <= 0) return;
  currentStep--;
  // Re-render from scratch up to current step
  clearStage();
  const target = currentStep;
  currentStep = -1;
  for (let i = 0; i <= target; i++) {
    currentStep = i;
    renderStep(i < target); // skip animation for past steps
  }
}

function renderStep(skipAnimation) {
  const step = currentScenario.steps[currentStep];

  // Update controls
  document.getElementById('btn-prev').disabled = currentStep <= 0;
  document.getElementById('btn-next').disabled = currentStep >= currentScenario.steps.length - 1;
  document.getElementById('step-counter').textContent = `Step ${currentStep + 1} / ${currentScenario.steps.length}`;

  // Update info panel
  document.getElementById('info-title').textContent = step.title;
  document.getElementById('info-body').innerHTML = step.body;
  const detailEl = document.getElementById('info-detail');
  if (step.detail) {
    detailEl.textContent = step.detail;
    detailEl.classList.add('visible');
  } else {
    detailEl.classList.remove('visible');
  }

  // Highlight actors
  document.querySelectorAll('.actor').forEach(el => {
    const id = el.id.replace('actor-', '');
    el.classList.toggle('highlight', step.highlight?.includes(id));
    el.classList.toggle('dimmed', step.highlight?.length > 0 && !step.highlight?.includes(id));
  });

  // Draw messages
  if (step.messages) {
    for (const msg of step.messages) {
      drawMessage(msg, skipAnimation);
    }
  }

  // Frame inspector
  const inspector = document.getElementById('frame-inspector');
  if (step.frame) {
    inspector.style.display = 'block';
    renderFrameInspector(step.frame);
  } else {
    inspector.style.display = 'none';
  }
}

// ===== MESSAGE DRAWING =====
function drawMessage(msg, skipAnimation) {
  const svg = document.getElementById('message-layer');
  const annot = document.getElementById('annotations-layer');
  const stage = document.getElementById('stage');
  const stageRect = stage.getBoundingClientRect();

  const fromEl = document.getElementById(`actor-${msg.from}`);
  const toEl = document.getElementById(`actor-${msg.to}`);
  if (!fromEl || !toEl) return;

  const fromRect = fromEl.getBoundingClientRect();
  const toRect = toEl.getBoundingClientRect();

  const x1 = fromRect.left - stageRect.left + fromRect.width / 2;
  const x2 = toRect.left - stageRect.left + toRect.width / 2;
  const y = msg.y || 150;

  // Arrow colors
  const colors = {
    data: '#58a6ff', encrypt: '#bc8cff', ghost: '#3fb950',
    danger: '#f85149', info: '#d29922', note: '#8b949e'
  };
  const color = colors[msg.style] || colors.data;

  // Draw arrow line
  const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
  line.setAttribute('x1', x1);
  line.setAttribute('y1', y);
  line.setAttribute('x2', x2);
  line.setAttribute('y2', y);
  line.setAttribute('stroke', color);
  line.setAttribute('class', `msg-arrow${skipAnimation ? '' : ' animate'}`);
  if (skipAnimation) line.style.strokeDashoffset = '0';
  svg.appendChild(line);

  // Arrowhead
  const dir = x2 > x1 ? 1 : -1;
  const headX = x2 - dir * 8;
  const head = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
  head.setAttribute('points', `${x2},${y} ${headX},${y - 5} ${headX},${y + 5}`);
  head.setAttribute('fill', color);
  head.setAttribute('class', `msg-arrowhead${skipAnimation ? '' : ' animate'}`);
  if (skipAnimation) head.style.opacity = '1';
  svg.appendChild(head);

  // Label
  const label = document.createElement('div');
  label.className = `msg-label ${msg.style}${skipAnimation ? ' visible' : ''}`;
  label.textContent = msg.label;
  label.style.left = ((x1 + x2) / 2) + 'px';
  label.style.top = (y - 22) + 'px';
  label.style.transform = 'translateX(-50%)';
  annot.appendChild(label);

  if (!skipAnimation) {
    setTimeout(() => label.classList.add('visible'), 300);
  }
}

function clearStage() {
  document.getElementById('message-layer').innerHTML = '';
  document.getElementById('annotations-layer').innerHTML = '';
  renderedMessages = [];
}

// ===== FRAME INSPECTOR =====
function renderFrameInspector(frame) {
  const hexEl = document.getElementById('frame-hex');
  const fieldsEl = document.getElementById('frame-fields');

  if (frame.type === 'vs3-header') {
    const bytes = frame.bytes.split(' ');
    const classes = ['magic', 'version', 'type', 'msgid', 'msgid', 'fragidx', 'fragtot', 'paylen'];
    hexEl.innerHTML = bytes.map((b, i) =>
      `<div class="hex-byte ${classes[i] || 'payload'}" title="${frame.labels?.[i] || ''}">${b}</div>`
    ).join('');

    fieldsEl.innerHTML = [
      { color: '#f85149', label: 'MAGIC 0xAA' },
      { color: '#58a6ff', label: 'VERSION 0x03' },
      { color: '#bc8cff', label: 'TYPE 0x05' },
      { color: '#d29922', label: 'MSG_ID (2B)' },
      { color: '#3fb950', label: 'FRAG_IDX' },
      { color: '#3fb950', label: 'FRAG_TOTAL' },
      { color: '#39d2c0', label: 'PAYLOAD_LEN' },
    ].map(f => `<div class="field-tag"><span class="field-color" style="background:${f.color}"></span>${f.label}</div>`).join('');
  } else if (frame.type === 'nonce-detail') {
    const bytes = frame.bytes.split(' ');
    const classes = ['sentinel', 'nonce', 'nonce', 'nonce', 'ntime', 'ntime', 'ntime', 'ntime'];
    hexEl.innerHTML = bytes.map((b, i) =>
      `<div class="hex-byte ${classes[i]}">${b}</div>`
    ).join('');

    fieldsEl.innerHTML = [
      { color: '#f85149', label: 'SENTINEL (0xAA or HMAC)' },
      { color: '#f85149', label: 'NONCE[1..3] = payload' },
      { color: '#d29922', label: 'NTIME[0..1] = epoch' },
      { color: '#d29922', label: 'NTIME[2..3] = payload' },
    ].map(f => `<div class="field-tag"><span class="field-color" style="background:${f.color}"></span>${f.label}</div>`).join('');
  } else {
    // Generic display
    hexEl.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${frame.bytes}</div>`;
    fieldsEl.innerHTML = '';
  }
}

// ===== AUTO PLAY =====
function toggleAutoPlay() {
  const btn = document.getElementById('btn-auto');
  if (autoPlayInterval) {
    stopAutoPlay();
  } else {
    btn.classList.add('playing');
    btn.innerHTML = '\u{23F8} Pause';
    autoPlayInterval = setInterval(() => {
      if (currentStep >= currentScenario.steps.length - 1) {
        stopAutoPlay();
        return;
      }
      nextStep();
    }, 3000);
  }
}

function stopAutoPlay() {
  if (autoPlayInterval) {
    clearInterval(autoPlayInterval);
    autoPlayInterval = null;
  }
  const btn = document.getElementById('btn-auto');
  btn.classList.remove('playing');
  btn.innerHTML = '\u{25B6} Auto';
}

// ===== KEYBOARD =====
document.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowRight' || e.key === ' ') { e.preventDefault(); nextStep(); }
  if (e.key === 'ArrowLeft') { e.preventDefault(); prevStep(); }
  if (e.key === 'p') toggleAutoPlay();
});
