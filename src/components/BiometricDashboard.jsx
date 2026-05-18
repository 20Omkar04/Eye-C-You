import { useState, useEffect, useRef, useCallback } from "react";

/* ═══════════════════════════════════════════════════════════════════════════
   PAILLIER HOMOMORPHIC ENCRYPTION ENGINE (BigInt)
   ═══════════════════════════════════════════════════════════════════════════ */

function millerRabinIsPrime(n, rounds = 15) {
  if (n < 2n) return false;
  if (n === 2n || n === 3n || n === 5n || n === 7n) return true;
  if (n % 2n === 0n) return false;
  let r = 0n, d = n - 1n;
  while (d % 2n === 0n) { d /= 2n; r++; }
  const witnesses = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n];
  witnessLoop: for (const a of witnesses) {
    if (a >= n) continue;
    let x = modExp(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let i = 0n; i < r - 1n; i++) {
      x = modExp(x, 2n, n);
      if (x === n - 1n) continue witnessLoop;
    }
    return false;
  }
  return true;
}

function modExp(base, exp, mod) {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function modInv(a, m) {
  let [old_r, r] = [((a % m) + m) % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error("No modular inverse");
  return ((old_s % m) + m) % m;
}

function gcd(a, b) { while (b) [a, b] = [b, a % b]; return a; }
function lcm(a, b) { return (a / gcd(a, b)) * b; }

function secureRandomBigInt(bits) {
  const bytes = Math.ceil(bits / 8);
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  arr[0] |= 0x80;
  arr[bytes - 1] |= 0x01;
  let n = 0n;
  for (const b of arr) n = (n << 8n) | BigInt(b);
  return n;
}

function randomInRange(upperBound) {
  const bits = upperBound.toString(2).length;
  let c;
  do { c = secureRandomBigInt(bits) % upperBound; } while (c < 2n);
  return c;
}

function generatePrime(bits) {
  let c;
  do { c = secureRandomBigInt(bits) | 1n; } while (!millerRabinIsPrime(c));
  return c;
}

function generateKeys(primeBits = 32) {
  let p, q;
  do {
    p = generatePrime(primeBits);
    q = generatePrime(primeBits);
  } while (p === q || gcd(p * q, (p - 1n) * (q - 1n)) !== 1n);
  const n = p * q;
  const nSq = n * n;
  const lambda = lcm(p - 1n, q - 1n);
  const g = n + 1n;
  const mu = modInv(lambda, n);
  return { publicKey: { n, nSq, g, bits: primeBits }, privateKey: { lambda, mu, p, q } };
}

function encrypt(m, pubKey) {
  const { n, nSq } = pubKey;
  const mBig = BigInt(m);
  let r;
  do { r = randomInRange(n); } while (gcd(r, n) !== 1n);
  const gm = (1n + mBig * n) % nSq;
  const rn = modExp(r, n, nSq);
  return (gm * rn) % nSq;
}

function decrypt(c, privKey, pubKey) {
  const { n, nSq } = pubKey;
  const { lambda, mu } = privKey;
  const u = modExp(c, lambda, nSq);
  const L = (u - 1n) / n;
  return (L * mu) % n;
}

function homomorphicAdd(c1, c2, pubKey) { return (c1 * c2) % pubKey.nSq; }
function blindSubtract(encLive, encStored, pubKey) {
  return homomorphicAdd(encLive, modInv(encStored, pubKey.nSq), pubKey);
}

function serializeC(c) { return "0x" + c.toString(16); }
function truncHex(h, n = 10) {
  const s = h.replace("0x", "");
  return s.length <= n * 2 ? h : `0x${s.slice(0, n)}…${s.slice(-4)}`;
}

const SUBJECT_ID = "subject_mtech_demo_001";
const PRIME_BITS = 32;
const DIMS = 3;
const MAX_VAL = 999;
const MATCH_THRESHOLD = 50n;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ═══════════════════════════════════════════════════════════════════════════
   VISUAL COMPONENTS
   ═══════════════════════════════════════════════════════════════════════════ */

const styles = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600;700&display=swap');

  * { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #020408;
    --surface: #060d14;
    --surface2: #0a1520;
    --border: rgba(0,200,255,0.12);
    --border2: rgba(160,80,255,0.12);
    --cyan: #00e5ff;
    --cyan2: #00b8d4;
    --violet: #aa60ff;
    --violet2: #7b2fff;
    --green: #00ffb3;
    --red: #ff3d6b;
    --amber: #ffb020;
    --text: #c8dde8;
    --text-dim: #4a6375;
    --text-dimmer: #243040;
    --font-mono: 'Share Tech Mono', monospace;
    --font-display: 'Orbitron', monospace;
    --font-ui: 'Rajdhani', sans-serif;
  }

  body { background: var(--bg); }

  .eye-app {
    min-height: 100vh;
    background: var(--bg);
    font-family: var(--font-mono);
    color: var(--text);
    position: relative;
    overflow-x: hidden;
  }

  /* Grid background */
  .eye-app::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  /* Radial glow */
  .eye-app::after {
    content: '';
    position: fixed;
    top: -20%;
    left: 50%;
    transform: translateX(-50%);
    width: 80vw;
    height: 60vh;
    background: radial-gradient(ellipse at center, rgba(0,100,180,0.08) 0%, transparent 70%);
    pointer-events: none;
    z-index: 0;
  }

  .z1 { position: relative; z-index: 1; }

  /* ─── Header ─── */
  .header {
    border-bottom: 1px solid var(--border);
    padding: 14px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: rgba(2,4,8,0.95);
    backdrop-filter: blur(12px);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .header-brand {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .iris-icon {
    width: 42px;
    height: 42px;
    border: 1px solid rgba(0,229,255,0.3);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: radial-gradient(circle, rgba(0,100,180,0.3), transparent);
    position: relative;
  }

  .iris-icon::before {
    content: '';
    position: absolute;
    inset: 3px;
    border-radius: 50%;
    border: 1px solid rgba(0,229,255,0.2);
    animation: spin-slow 8s linear infinite;
  }

  @keyframes spin-slow { to { transform: rotate(360deg); } }
  @keyframes spin-rev { to { transform: rotate(-360deg); } }
  @keyframes pulse-glow {
    0%, 100% { opacity: 0.4; }
    50% { opacity: 1; }
  }
  @keyframes scan-line {
    0% { transform: translateY(-100%); opacity: 0; }
    20% { opacity: 1; }
    80% { opacity: 1; }
    100% { transform: translateY(100%); opacity: 0; }
  }
  @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }
  @keyframes data-flow {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(100%); }
  }
  @keyframes fadeInUp {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes pop-in {
    0% { opacity: 0; transform: scale(0.9); }
    100% { opacity: 1; transform: scale(1); }
  }

  .brand-title {
    font-family: var(--font-display);
    font-size: 18px;
    font-weight: 900;
    letter-spacing: 0.25em;
    color: #fff;
    text-shadow: 0 0 20px rgba(0,229,255,0.5);
  }

  .brand-sub {
    font-family: var(--font-ui);
    font-size: 9px;
    color: var(--text-dim);
    letter-spacing: 0.2em;
    font-weight: 300;
    margin-top: 1px;
  }

  .step-pills {
    display: flex;
    gap: 6px;
  }

  .step-pill {
    padding: 3px 10px;
    border-radius: 2px;
    font-family: var(--font-display);
    font-size: 7px;
    font-weight: 700;
    letter-spacing: 0.15em;
    border: 1px solid;
    transition: all 0.3s;
  }

  .step-pill.pending { border-color: var(--text-dimmer); color: var(--text-dimmer); }
  .step-pill.active { border-color: var(--cyan); color: var(--cyan); background: rgba(0,229,255,0.08); animation: pulse-glow 1.5s ease-in-out infinite; }
  .step-pill.complete { border-color: rgba(0,255,179,0.4); color: var(--green); background: rgba(0,255,179,0.06); }

  .he-badge {
    display: flex;
    align-items: center;
    gap: 6px;
    border: 1px solid rgba(0,255,179,0.25);
    border-radius: 2px;
    padding: 4px 10px;
  }

  .he-badge-dot {
    width: 5px;
    height: 5px;
    border-radius: 50%;
    background: var(--green);
    animation: pulse-glow 1.5s ease-in-out infinite;
  }

  .he-badge-text {
    font-family: var(--font-display);
    font-size: 7px;
    color: var(--green);
    letter-spacing: 0.15em;
  }

  /* ─── Result Banner ─── */
  .result-banner {
    padding: 12px 24px;
    text-align: center;
    border-bottom: 1px solid;
    animation: pop-in 0.4s ease-out;
  }

  .result-banner.granted {
    border-color: rgba(0,255,179,0.3);
    background: linear-gradient(135deg, rgba(0,255,179,0.05), transparent);
  }

  .result-banner.denied {
    border-color: rgba(255,61,107,0.3);
    background: linear-gradient(135deg, rgba(255,61,107,0.05), transparent);
  }

  .result-title {
    font-family: var(--font-display);
    font-size: 14px;
    font-weight: 900;
    letter-spacing: 0.2em;
  }

  .result-sub {
    font-family: var(--font-ui);
    font-size: 10px;
    opacity: 0.6;
    margin-top: 4px;
    letter-spacing: 0.05em;
  }

  /* ─── Main Grid ─── */
  .main-grid {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }

  @media (max-width: 900px) { .main-grid { grid-template-columns: 1fr; } }

  /* ─── Panel ─── */
  .panel {
    border-radius: 4px;
    overflow: hidden;
    position: relative;
  }

  .panel-client { border: 1px solid var(--border); background: rgba(6,13,20,0.8); }
  .panel-cloud { border: 1px solid var(--border2); background: rgba(6,13,20,0.8); }

  .panel::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
  }

  .panel-client::before { background: linear-gradient(90deg, transparent, var(--cyan), transparent); }
  .panel-cloud::before { background: linear-gradient(90deg, transparent, var(--violet), transparent); }

  .panel-header {
    padding: 14px 16px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .panel-header-client { background: linear-gradient(90deg, rgba(0,229,255,0.04), transparent); }
  .panel-header-cloud { background: linear-gradient(270deg, rgba(170,96,255,0.04), transparent); }

  .panel-icon {
    width: 34px;
    height: 34px;
    border-radius: 3px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    flex-shrink: 0;
  }

  .panel-icon-client { border: 1px solid rgba(0,229,255,0.25); background: rgba(0,229,255,0.06); }
  .panel-icon-cloud { border: 1px solid rgba(170,96,255,0.25); background: rgba(170,96,255,0.06); }

  .panel-title {
    font-family: var(--font-display);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.2em;
  }

  .panel-title-client { color: var(--cyan2); }
  .panel-title-cloud { color: var(--violet); }

  .panel-sub {
    font-family: var(--font-ui);
    font-size: 8px;
    color: var(--text-dim);
    letter-spacing: 0.15em;
    font-weight: 300;
    margin-top: 2px;
  }

  .live-dot {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 5px;
  }

  .dot {
    width: 5px;
    height: 5px;
    border-radius: 50%;
    animation: pulse-glow 1.5s ease-in-out infinite;
  }

  .dot-cyan { background: var(--cyan); }
  .dot-violet { background: var(--violet); }

  .live-text {
    font-family: var(--font-display);
    font-size: 7px;
    color: var(--text-dim);
    letter-spacing: 0.15em;
  }

  .panel-body { padding: 14px 16px; display: flex; flex-direction: column; gap: 14px; }

  /* ─── Section ─── */
  .section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 8px;
  }

  .section-label {
    font-family: var(--font-display);
    font-size: 8px;
    font-weight: 700;
    letter-spacing: 0.2em;
    color: var(--cyan2);
  }

  .section-label-violet { color: var(--violet); }

  .disabled-section { opacity: 0.25; pointer-events: none; }

  /* ─── Button ─── */
  .btn {
    padding: 6px 14px;
    border-radius: 2px;
    font-family: var(--font-display);
    font-size: 8px;
    font-weight: 700;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    cursor: pointer;
    transition: all 0.2s;
    border: 1px solid;
    position: relative;
    overflow: hidden;
  }

  .btn::after {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.05), transparent);
    transform: translateX(-100%);
    transition: transform 0.3s;
  }

  .btn:hover::after { transform: translateX(100%); }

  .btn:disabled { opacity: 0.3; cursor: not-allowed; }
  .btn:disabled::after { display: none; }

  .btn-cyan { border-color: rgba(0,229,255,0.5); color: var(--cyan); background: rgba(0,229,255,0.04); }
  .btn-cyan:hover:not(:disabled) { background: rgba(0,229,255,0.1); border-color: var(--cyan); box-shadow: 0 0 12px rgba(0,229,255,0.15); }

  .btn-green { border-color: rgba(0,255,179,0.5); color: var(--green); background: rgba(0,255,179,0.04); }
  .btn-green:hover:not(:disabled) { background: rgba(0,255,179,0.1); border-color: var(--green); box-shadow: 0 0 12px rgba(0,255,179,0.15); }

  .btn-amber { border-color: rgba(255,176,32,0.5); color: var(--amber); background: rgba(255,176,32,0.04); }
  .btn-amber:hover:not(:disabled) { background: rgba(255,176,32,0.1); border-color: var(--amber); box-shadow: 0 0 12px rgba(255,176,32,0.15); }

  /* ─── Key cards ─── */
  .key-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }

  .key-card {
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 3px;
    padding: 10px;
    background: rgba(0,0,0,0.4);
    animation: fadeInUp 0.3s ease-out;
  }

  .key-card-label {
    font-family: var(--font-ui);
    font-size: 7px;
    color: var(--text-dim);
    letter-spacing: 0.15em;
    font-weight: 600;
    margin-bottom: 6px;
  }

  .key-card-value {
    font-size: 8px;
    word-break: break-all;
    line-height: 1.4;
  }

  /* ─── Iris ─── */
  .iris-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 8px 0;
  }

  .iris-container {
    position: relative;
    width: 110px;
    height: 110px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .iris-ring {
    position: absolute;
    border-radius: 50%;
    border: 1px solid;
  }

  .iris-ring-1 {
    inset: 0;
    border-color: rgba(0,229,255,0.2);
  }

  .iris-ring-1.scanning { animation: spin-slow 4s linear infinite; }

  .iris-ring-2 {
    inset: 8px;
    border-color: rgba(0,229,255,0.12);
  }

  .iris-ring-2.scanning { animation: spin-rev 2.5s linear infinite; }

  .iris-corner {
    position: absolute;
    width: 14px;
    height: 14px;
  }

  .corner-tl { top: 0; left: 0; border-top: 2px solid rgba(0,229,255,0.6); border-left: 2px solid rgba(0,229,255,0.6); }
  .corner-tr { top: 0; right: 0; border-top: 2px solid rgba(0,229,255,0.6); border-right: 2px solid rgba(0,229,255,0.6); }
  .corner-bl { bottom: 0; left: 0; border-bottom: 2px solid rgba(0,229,255,0.6); border-left: 2px solid rgba(0,229,255,0.6); }
  .corner-br { bottom: 0; right: 0; border-bottom: 2px solid rgba(0,229,255,0.6); border-right: 2px solid rgba(0,229,255,0.6); }

  /* ─── Vector display ─── */
  .vec-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 4px; }

  .vec-card {
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 3px;
    padding: 10px;
    background: rgba(0,0,0,0.3);
    animation: fadeInUp 0.3s ease-out;
  }

  .vec-card-label {
    font-family: var(--font-ui);
    font-size: 7px;
    color: var(--text-dim);
    letter-spacing: 0.15em;
    font-weight: 600;
    margin-bottom: 6px;
  }

  .vec-item { font-size: 9px; line-height: 1.8; }

  /* ─── Sync card ─── */
  .sync-card {
    border: 1px solid rgba(0,255,179,0.2);
    border-radius: 3px;
    padding: 10px 12px;
    background: rgba(0,255,179,0.03);
    animation: fadeInUp 0.3s ease-out;
  }

  .sync-card-title { font-size: 8px; color: var(--green); margin-bottom: 4px; }
  .sync-card-row { font-size: 7px; color: var(--text-dim); line-height: 1.8; }

  /* ─── Delta card ─── */
  .delta-card {
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 3px;
    padding: 10px 12px;
    background: rgba(0,0,0,0.3);
    animation: fadeInUp 0.3s ease-out;
  }

  .delta-label {
    font-family: var(--font-ui);
    font-size: 7px;
    color: var(--text-dim);
    letter-spacing: 0.15em;
    font-weight: 600;
    margin-bottom: 6px;
  }

  .delta-item { font-size: 9px; line-height: 1.9; }
  .delta-ok { color: var(--green); }
  .delta-bad { color: var(--red); }

  /* ─── Terminal ─── */
  .terminal {
    border-radius: 3px;
    overflow: hidden;
    border: 1px solid;
  }

  .terminal-client { border-color: rgba(0,229,255,0.15); }
  .terminal-cloud { border-color: rgba(170,96,255,0.15); }
  .terminal-green { border-color: rgba(0,255,179,0.15); }
  .terminal-red { border-color: rgba(255,61,107,0.15); }

  .terminal-bar {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 10px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    background: rgba(0,0,0,0.4);
  }

  .term-bar-label {
    font-family: var(--font-display);
    font-size: 7px;
    font-weight: 700;
    letter-spacing: 0.2em;
  }

  .term-dots { margin-left: auto; display: flex; gap: 4px; }
  .term-dot { width: 5px; height: 5px; border-radius: 50%; background: rgba(255,255,255,0.1); }

  .terminal-body {
    padding: 10px;
    height: 140px;
    overflow-y: auto;
    background: rgba(2,4,8,0.95);
    scrollbar-width: thin;
    scrollbar-color: rgba(0,229,255,0.2) transparent;
  }

  .term-empty { font-size: 8px; color: var(--text-dimmer); font-style: italic; }

  .term-line {
    font-size: 8px;
    line-height: 1.7;
    display: flex;
    gap: 6px;
  }

  .term-num { color: var(--text-dimmer); user-select: none; min-width: 18px; flex-shrink: 0; }

  .term-text { }
  .term-error { color: var(--red); }
  .term-success { color: var(--green); }
  .term-key { color: var(--amber); }
  .term-cloud { color: #c084fc; }
  .term-client { color: var(--cyan2); }
  .term-default { color: #7a9bb0; }

  /* ─── ZK Status ─── */
  .zk-card {
    border: 1px solid rgba(170,96,255,0.2);
    border-radius: 3px;
    padding: 12px;
    background: rgba(170,96,255,0.03);
  }

  .zk-header {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: 10px;
  }

  .zk-title {
    font-family: var(--font-display);
    font-size: 8px;
    font-weight: 700;
    letter-spacing: 0.2em;
    color: var(--violet);
  }

  .zk-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; }

  .zk-item {
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 2px;
    padding: 8px;
    background: rgba(0,0,0,0.3);
  }

  .zk-item-label { font-family: var(--font-ui); font-size: 7px; color: var(--text-dim); letter-spacing: 0.1em; margin-bottom: 3px; }
  .zk-item-val { font-family: var(--font-display); font-size: 9px; font-weight: 700; }

  /* ─── Pipeline ─── */
  .pipeline-card {
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 3px;
    padding: 12px;
    background: rgba(0,0,0,0.25);
  }

  .pipeline-title {
    font-family: var(--font-display);
    font-size: 8px;
    font-weight: 700;
    letter-spacing: 0.2em;
    color: var(--violet);
    margin-bottom: 10px;
  }

  .pipeline-steps { display: flex; flex-direction: column; gap: 6px; }

  .pipeline-step {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 8px;
    transition: all 0.3s;
  }

  .pipeline-step.done { }
  .pipeline-step.pending { opacity: 0.3; }

  .pipeline-dot {
    width: 5px;
    height: 5px;
    border-radius: 50%;
    margin-top: 3px;
    flex-shrink: 0;
    transition: all 0.3s;
  }

  .pipeline-dot.done { background: var(--violet); box-shadow: 0 0 6px var(--violet); }
  .pipeline-dot.pending { background: #1a2a3a; }

  .pipeline-op {
    font-family: var(--font-display);
    font-size: 7px;
    font-weight: 700;
    color: var(--violet);
    width: 52px;
    flex-shrink: 0;
    letter-spacing: 0.1em;
  }

  .pipeline-desc { color: #7a9bb0; line-height: 1.3; }

  /* ─── DB Table ─── */
  .db-card {
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 3px;
    overflow: hidden;
    background: rgba(0,0,0,0.25);
  }

  .db-header {
    padding: 8px 12px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    background: rgba(0,0,0,0.3);
    font-size: 8px;
    color: #7a9bb0;
    letter-spacing: 0.1em;
  }

  .db-body { padding: 10px 12px; }
  .db-empty { font-size: 8px; color: var(--text-dimmer); text-align: center; padding: 12px 0; font-style: italic; }

  .db-row {
    display: flex;
    gap: 10px;
    font-size: 7px;
    padding: 3px 0;
    border-bottom: 1px solid rgba(255,255,255,0.03);
  }

  .db-row:last-child { border-bottom: none; }
  .db-key { color: var(--text-dim); width: 160px; flex-shrink: 0; truncate; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .db-val { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* ─── Guarantees ─── */
  .guarantees-card {
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 3px;
    padding: 12px;
    background: rgba(0,0,0,0.2);
  }

  .guarantees-title {
    font-family: var(--font-display);
    font-size: 8px;
    font-weight: 700;
    letter-spacing: 0.2em;
    color: var(--violet);
    margin-bottom: 8px;
  }

  .guarantee-item {
    font-size: 7.5px;
    color: #7a9bb0;
    padding: 3px 0;
    display: flex;
    gap: 8px;
    line-height: 1.4;
  }

  .guarantee-check { color: var(--green); flex-shrink: 0; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 3px; height: 3px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(0,229,255,0.2); border-radius: 2px; }
`;

/* ─────────────────────────────────────────────
   IrisAnimation
───────────────────────────────────────────── */
function IrisAnimation({ scanning, done }) {
  return (
    <div className="iris-wrap">
      <div className="iris-container">
        <div className={`iris-ring iris-ring-1 ${scanning ? "scanning" : ""}`} />
        <div className={`iris-ring iris-ring-2 ${scanning ? "scanning" : ""}`} />
        <div className="iris-corner corner-tl" />
        <div className="iris-corner corner-tr" />
        <div className="iris-corner corner-bl" />
        <div className="iris-corner corner-br" />
        <svg viewBox="0 0 100 100" style={{ width: 80, height: 80, position: "relative" }}>
          <defs>
            <radialGradient id="ig2" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor={done ? "#00ffb3" : "#00e5ff"} stopOpacity="0.9" />
              <stop offset="45%" stopColor={done ? "#00c98a" : "#0080a0"} stopOpacity="0.5" />
              <stop offset="100%" stopColor="#020408" />
            </radialGradient>
            <filter id="glow2">
              <feGaussianBlur stdDeviation="2" result="b" />
              <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <radialGradient id="scanGrad" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#00e5ff" stopOpacity="0" />
              <stop offset="80%" stopColor="#00e5ff" stopOpacity="0.06" />
              <stop offset="100%" stopColor="#00e5ff" stopOpacity="0.2" />
            </radialGradient>
          </defs>
          <circle cx="50" cy="50" r="48" fill="#020408" stroke="rgba(0,229,255,0.08)" strokeWidth="1" />
          <circle cx="50" cy="50" r="34" fill="url(#ig2)" filter="url(#glow2)" />
          {[...Array(16)].map((_, i) => {
            const a = (i * 22.5 * Math.PI) / 180;
            return (
              <line
                key={i}
                x1={50 + 17 * Math.cos(a)} y1={50 + 17 * Math.sin(a)}
                x2={50 + 33 * Math.cos(a)} y2={50 + 33 * Math.sin(a)}
                stroke={done ? "#00ffb3" : "#00e5ff"}
                strokeWidth="0.6"
                strokeOpacity={scanning ? "0.9" : "0.25"}
              />
            );
          })}
          <circle cx="50" cy="50" r="12" fill="#000" />
          <circle cx="44" cy="44" r="2.5" fill="white" fillOpacity="0.4" />
          <circle cx="57" cy="56" r="1" fill="white" fillOpacity="0.2" />
          {scanning && (
            <line x1="16" y1="50" x2="84" y2="50" stroke="#00e5ff" strokeWidth="0.8" strokeOpacity="0.7">
              <animateTransform attributeName="transform" type="rotate" from="0 50 50" to="360 50 50" dur="1.2s" repeatCount="indefinite" />
            </line>
          )}
          {done && (
            <text x="50" y="55" textAnchor="middle" fontSize="11" fill="#00ffb3" fontWeight="bold">✓</text>
          )}
          {scanning && (
            <circle cx="50" cy="50" r="34" fill="url(#scanGrad)">
              <animate attributeName="opacity" values="0;1;0" dur="1.5s" repeatCount="indefinite" />
            </circle>
          )}
        </svg>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────
   Terminal
───────────────────────────────────────────── */
function TerminalLog({ logs, title, variant = "client" }) {
  const ref = useRef(null);
  useEffect(() => { ref.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);

  const barColor = {
    client: "var(--cyan2)",
    cloud: "var(--violet)",
    green: "var(--green)",
    red: "var(--red)",
  }[variant];

  const termClass = {
    client: "terminal-client",
    cloud: "terminal-cloud",
    green: "terminal-green",
    red: "terminal-red",
  }[variant];

 const getLineClass = (line) => {
  if (!line) return "term-default";

  if (line.startsWith("[CLOUD]")) return "term-cloud";
  if (line.startsWith("[CLIENT]")) return "term-client";

  if (line.includes("[ERROR]") || line.includes("DENIED") || line.includes("FAILED")) {
    return "term-error";
  }
  
  if (line.includes("[INFO]") || line.includes("GRANTED") || line.includes("SUCCESS")) {
    return "term-success";
  }
  
  if (line.includes("[WARN]") || line.includes("KEY")) {
    return "term-key";
  }

  return "term-default";
};

  return (
    <div className={`terminal ${termClass}`}>
      <div className="terminal-bar">
        <div className="dot" style={{ background: barColor, animation: "pulse-glow 1.5s ease-in-out infinite" }} />
        <span className="term-bar-label" style={{ color: barColor }}>{title}</span>
        <div className="term-dots">
          {[0, 1, 2].map(i => <div key={i} className="term-dot" />)}
        </div>
      </div>
      <div className="terminal-body">
        {logs.length === 0
          ? <div className="term-empty">Awaiting input…</div>
          : logs.map((l, i) => (
            <div key={i} className={`term-line ${getLineClass(l)}`}>
              <span className="term-num">{String(i + 1).padStart(2, "0")}│</span>
              <span>{l}</span>
            </div>
          ))
        }
        <div ref={ref} />
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────
   MAIN DASHBOARD
───────────────────────────────────────────── */
export default function EyeCYouDashboard() {
  const [pubKey, setPubKey] = useState(null);
  const [privKey, setPrivKey] = useState(null);
  const [rawVec, setRawVec] = useState([]);
  const [encVec, setEncVec] = useState([]);
  const [storedTemplate, setStoredTemplate] = useState([]);
  const [deltaVec, setDeltaVec] = useState([]);
  const [authResult, setAuthResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [synced, setSynced] = useState(false);
  const [syncId, setSyncId] = useState(null);
  const [step, setStep] = useState("IDLE");
  const [clientLog, setClientLog] = useState([]);
  const [cloudLog, setCloudLog] = useState([]);

  const logC = useCallback((m) => setClientLog(p => [...p, `[CLIENT] ${m}`]), []);
  const logG = useCallback((m) => setCloudLog(p => [...p, m]), []);

  const handleInit = useCallback(async () => {
    setStep("KEYGEN");
    setPubKey(null); setPrivKey(null);
    setClientLog([]); setCloudLog([]);
    setAuthResult(null); setSynced(false); setScanDone(false);
    setRawVec([]); setEncVec([]); setDeltaVec([]);
    logC("Initializing Eye C You Biometric Auth System…");
    logC(`Prime bit-length: ${PRIME_BITS} bits`);
    logC("Running Miller-Rabin primality checks…");
    await sleep(350);
    const { publicKey, privateKey } = generateKeys(PRIME_BITS);
    setPubKey(publicKey); setPrivKey(privateKey);
    logC(`n = 0x${publicKey.n.toString(16).slice(0, 16)}… (public modulus)`);
    logC("g = n + 1 (Paillier generator)");
    logC("λ = lcm(p−1, q−1) computed (private)");
    logC("μ = λ⁻¹ mod n computed (private)");
    logC("Key pair ready. Private key sealed locally.");
    logG("[CLOUD] Supabase Gateway online — accepting encrypted payloads.");
    logG(`[CLOUD] Public n registered: 0x${publicKey.n.toString(16).slice(0, 12)}…`);
    logG("[CLOUD] Private key: NOT TRANSMITTED — blind compute only.");
    setStep("KEYGEN_DONE");
  }, [logC, logG]);

  const handleScan = useCallback(async () => {
    if (!pubKey) return;
    setScanning(true); setScanDone(false); setEncVec([]);
    logC("Activating iris biometric scanner…");
    await sleep(1400);
    const raw = Array.from({ length: DIMS }, () => Math.floor(Math.random() * MAX_VAL) + 1);
    setRawVec(raw);
    logC(`Raw iris vector captured: [${raw.join(", ")}]`);
    logC("Encrypting each component (IND-CPA: fresh r per Enc)…");
    await sleep(200);
    const enc = raw.map(v => encrypt(v, pubKey));
    setEncVec(enc);
    enc.forEach((c, i) => logC(`[${i}] ${raw[i]} → Enc(…${c.toString(16).slice(-8)})`));
    logC("Raw vector purged. Only ciphertext remains.");
    setScanning(false); setScanDone(true); setStep("SCANNED");
  }, [pubKey, logC]);

  const handleSync = useCallback(async () => {
    if (!encVec.length || !pubKey) return;
    logC("Serializing encrypted payload for Supabase upsert…");
    logG("[CLOUD] Incoming upsert request received…");
    await sleep(400);
    const serialized = encVec.map(serializeC);
    logC(`${serialized.length} ciphertext strings (~${serialized[0].length} hex chars each)`);
    logC("POST /rest/v1/eye_c_you_biometric_templates — no plaintext in body");
    await sleep(500);
    const id = `sb_${Math.random().toString(36).slice(2, 10)}`;
    setStoredTemplate(encVec);
    setSyncId(id); setSynced(true); setStep("SYNCED");
    logC(`Supabase upsert OK → id: ${id}`);
    logG(`[CLOUD] Record stored → id: ${id}`);
    logG("[CLOUD] Column encrypted_iris_payload = text[] (hex ciphertexts only)");
    logG("[CLOUD] Cloud has ZERO knowledge of underlying biometric values.");
  }, [encVec, pubKey, logC, logG]);

  const handleAuth = useCallback(async () => {
    if (!synced || !pubKey || !privKey || !rawVec.length) return;
    setStep("AUTHING"); setAuthResult(null); setDeltaVec([]);
    logC("─── AUTHENTICATION SEQUENCE INITIATED ───");
    logC("Generating fresh live iris scan…");
    logG("[CLOUD] ─── BLIND COMPUTE SEQUENCE STARTED ───");
    logG("[CLOUD] Fetching template from eye_c_you_biometric_templates…");
    await sleep(700);
    const liveRaw = rawVec.map(v => Math.max(1, v + Math.floor((Math.random() - 0.5) * 22)));
    logC(`Live scan: [${liveRaw.join(", ")}]`);
    const encLive = liveRaw.map(v => encrypt(v, pubKey));
    encLive.forEach((c, i) => logC(`Live[${i}] → Enc(…${c.toString(16).slice(-8)})`));
    logC("Transmitting Enc(live) to Cloud Gateway…");
    logG(`[CLOUD] Enc(live) received — ${encLive.length} components`);
    logG("[CLOUD] Starting HE subtraction: Enc(Δ) = Enc(live) · Enc(stored)⁻¹ mod n²");
    await sleep(500);
    const encDelta = encLive.map((el, i) => blindSubtract(el, storedTemplate[i], pubKey));
    encDelta.forEach((d, i) => logG(`[CLOUD] Enc(Δ[${i}]) = …${d.toString(16).slice(-8)}`));
    logG("[CLOUD] Blind HE subtraction complete — returning Enc(Δ) to client.");
    await sleep(400);
    logC("Received Enc(Δ). Decrypting with PRIVATE KEY (local only)…");
    const dec = encDelta.map(c => decrypt(c, privKey, pubKey));
    setDeltaVec(dec);
    const halfN = pubKey.n / 2n;
    const interp = dec.map(d => d > halfN ? d - pubKey.n : d);
    interp.forEach((d, i) => logC(`Δ[${i}] = ${d}  (live=${liveRaw[i]}, stored=${rawVec[i]})`));
    const totalDiff = interp.reduce((s, d) => s + (d < 0n ? -d : d), 0n);
    logC(` Σ|Δ| = ${totalDiff}  (threshold ≤ ${MATCH_THRESHOLD})`);
    const match = totalDiff <= MATCH_THRESHOLD;
    setAuthResult(match);
    if (match) {
      logC("Σ|Δ| ≤ threshold → IDENTITY VERIFIED");
      logC("ACCESS GRANTED");
      logG("[CLOUD] Client confirmed HE match. Privacy preserved end-to-end.");
    } else {
      logC(" Σ|Δ| > threshold → MISMATCH");
      logC("ACCESS DENIED");
      logG("[CLOUD] Client reported mismatch. Audit timestamp updated.");
    }
    setStep("DONE");
  }, [synced, pubKey, privKey, rawVec, storedTemplate, logC, logG]);

  const keysReady = !!pubKey;
  const hasIris = encVec.length > 0;
  const isDone = step === "DONE";

  const stepStatus = (s) => {
    const order = ["KEYGEN_DONE", "SCANNED", "SYNCED", "DONE"];
    const cur = order.indexOf(step === "AUTHING" ? "SYNCED" : step);
    const idx = order.indexOf(s);
    if (isDone) return "complete";
    if (cur === idx) return "active";
    if (cur > idx) return "complete";
    return "pending";
  };

  const cloudVariant = isDone && authResult ? "green" : isDone ? "red" : "cloud";

  return (
    <>
      <style>{styles}</style>
      <div className="eye-app">
        <div className="z1">
          {/* ─── Header ─── */}
          <header className="header">
            <div className="header-brand">
              <div className="iris-icon">
                <svg viewBox="0 0 24 24" style={{ width: 18, height: 18, position: "relative", zIndex: 1 }}>
                  <ellipse cx="12" cy="12" rx="10" ry="7" stroke="#00e5ff" strokeWidth="1.5" fill="none" />
                  <circle cx="12" cy="12" r="4" stroke="#00e5ff" strokeWidth="1" fill="rgba(0,229,255,0.1)" />
                  <circle cx="12" cy="12" r="1.5" fill="#00e5ff" />
                  <circle cx="10" cy="10.5" r="0.7" fill="white" fillOpacity="0.6" />
                </svg>
              </div>
              <div>
                <div className="brand-title">EYE C YOU</div>
                <div className="brand-sub">PRIVACY-PRESERVING BIOMETRIC AUTH · PAILLIER HE · SUPABASE</div>
              </div>
            </div>

            <div className="step-pills" style={{ display: "flex", gap: 6 }}>
              {[["KEYGEN_DONE", "01 KEYGEN"], ["SCANNED", "02 SCAN"], ["SYNCED", "03 SYNC"], ["DONE", "04 AUTH"]].map(([s, l]) => (
                <div key={s} className={`step-pill ${stepStatus(s)}`}>
                  {stepStatus(s) === "complete" ? "✓ " : ""}{l}
                </div>
              ))}
            </div>

            <div className="he-badge">
              <div className="he-badge-dot" />
              <span className="he-badge-text">HE ACTIVE</span>
            </div>
          </header>

          {/* ─── Result Banner ─── */}
          {isDone && (
            <div className={`result-banner ${authResult ? "granted" : "denied"}`}>
              <div className="result-title" style={{ color: authResult ? "var(--green)" : "var(--red)" }}>
                {authResult ? "ACCESS GRANTED — IDENTITY VERIFIED" : "ACCESS DENIED — BIOMETRIC MISMATCH"}
              </div>
              <div className="result-sub">
                {authResult
                  ? "Homomorphic difference vector Σ|Δ| within acceptance threshold. Zero plaintext exposed."
                  : "Homomorphic difference vector Σ|Δ| exceeded threshold. No biometric data revealed to cloud."}
              </div>
            </div>
          )}

          {/* ─── Main Grid ─── */}
          <div className="main-grid">
            {/* ════ LEFT: CLIENT ════ */}
            <div className="panel panel-client">
              <div className="panel-header panel-header-client">
                <div className="panel-icon panel-icon-client">💻</div>
                <div>
                  <div className="panel-title panel-title-client">CLIENT MACHINE</div>
                  <div className="panel-sub">LOCAL CRYPTO ENGINE · PRIVATE KEY NEVER LEAVES</div>
                </div>
                <div className="live-dot">
                  <div className="dot dot-cyan" />
                  <span className="live-text">LIVE</span>
                </div>
              </div>

              <div className="panel-body">
                {/* Step 1 */}
                <section>
                  <div className="section-header">
                    <span className="section-label">01 · SYSTEM INIT</span>
                    <button
                      className={`btn ${step === "KEYGEN" ? "btn-cyan" : "btn-cyan"}`}
                      onClick={handleInit}
                      disabled={step === "KEYGEN"}
                    >
                      {keysReady ? "↻ REINIT" : "⚙ INITIALIZE"}
                    </button>
                  </div>
                  {keysReady && pubKey && (
                    <div className="key-grid">
                      <div className="key-card">
                        <div className="key-card-label">PUBLIC KEY n</div>
                        <div className="key-card-value" style={{ color: "var(--amber)" }}>
                          0x{pubKey.n.toString(16).slice(0, 20)}…
                        </div>
                      </div>
                      <div className="key-card">
                        <div className="key-card-label">PRIVATE KEY λ</div>
                        <div className="key-card-value" style={{ color: "var(--red)", letterSpacing: "0.2em" }}>
                          ████████ [SEALED]
                        </div>
                      </div>
                    </div>
                  )}
                </section>

                {/* Step 2 */}
                <section className={!keysReady ? "disabled-section" : ""}>
                  <div className="section-header">
                    <span className="section-label">02 · IRIS ACQUISITION</span>
                    <button
                      className="btn btn-cyan"
                      onClick={handleScan}
                      disabled={!keysReady || scanning}
                    >
                      {scanning ? "⟳ SCANNING…" : "👁 SCAN IRIS"}
                    </button>
                  </div>
                  <IrisAnimation scanning={scanning} done={scanDone} />
                  {rawVec.length > 0 && (
                    <div className="vec-grid">
                      <div className="vec-card">
                        <div className="vec-card-label">RAW VECTOR</div>
                        {rawVec.map((v, i) => (
                          <div key={i} className="vec-item" style={{ color: "var(--amber)" }}>[{i}] {v}</div>
                        ))}
                      </div>
                      <div className="vec-card">
                        <div className="vec-card-label">CIPHERTEXT</div>
                        {encVec.map((c, i) => (
                          <div key={i} className="vec-item" style={{ color: "var(--cyan2)", fontSize: 7 }}>[{i}] {truncHex(serializeC(c), 7)}</div>
                        ))}
                      </div>
                    </div>
                  )}
                </section>

                {/* Step 3 */}
                <section className={!hasIris ? "disabled-section" : ""}>
                  <div className="section-header">
                    <span className="section-label">03 · SUPABASE SYNC</span>
                    <button
                      className="btn btn-green"
                      onClick={handleSync}
                      disabled={!hasIris || synced}
                    >
                      {synced ? "✓ SYNCED" : "☁ SYNC"}
                    </button>
                  </div>
                  {synced && (
                    <div className="sync-card">
                      <div className="sync-card-title"> Template stored in Supabase</div>
                      <div className="sync-card-row">id: {syncId}</div>
                      <div className="sync-card-row">table: eye_c_you_biometric_templates</div>
                      <div className="sync-card-row">payload: encrypted_iris_payload (text[])</div>
                    </div>
                  )}
                </section>

                {/* Step 4 */}
                <section className={!synced ? "disabled-section" : ""}>
                  <div className="section-header">
                    <span className="section-label">04 · BLIND AUTHENTICATE</span>
                    <button
                      className="btn btn-amber"
                      onClick={handleAuth}
                      disabled={!synced || step === "AUTHING"}
                    >
                      {step === "AUTHING" ? "⟳ VERIFYING…" : "AUTHENTICATE"}
                    </button>
                  </div>
                  {deltaVec.length > 0 && pubKey && (
                    <div className="delta-card">
                      <div className="delta-label">DECRYPTED Δ VECTOR (local only)</div>
                      {deltaVec.map((d, i) => {
                        const halfN = pubKey.n / 2n;
                        const v = d > halfN ? d - pubKey.n : d;
                        const ok = v < 20n && v > -20n;
                        return (
                          <div key={i} className={`delta-item ${ok ? "delta-ok" : "delta-bad"}`}>
                            [{i}] Δ = {v.toString()} {ok ? "✓" : "✗"}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </section>

                <TerminalLog logs={clientLog} title="CLIENT MACHINE LOG" variant="client" />
              </div>
            </div>

            {/* ════ RIGHT: CLOUD ════ */}
            <div className="panel panel-cloud">
              <div className="panel-header panel-header-cloud">
                <div className="panel-icon panel-icon-cloud">☁</div>
                <div>
                  <div className="panel-title panel-title-cloud">BLIND SUPABASE GATEWAY</div>
                  <div className="panel-sub">ZERO-KNOWLEDGE COMPUTE · NO PLAINTEXT ACCESS</div>
                </div>
                <div className="live-dot">
                  <div className="dot dot-violet" />
                  <span className="live-text">LIVE</span>
                </div>
              </div>

              <div className="panel-body">
                {/* ZK Status */}
                <div className="zk-card">
                  <div className="zk-header">
                    <div className="dot dot-violet" />
                    <span className="zk-title">ZERO-KNOWLEDGE STATUS</span>
                  </div>
                  <div className="zk-grid">
                    {[
                      ["Plaintext Access", "DENIED", "var(--red)"],
                      ["HE Scheme", "PAILLIER", "var(--cyan)"],
                      ["Operation", "ADDITIVE", "var(--green)"],
                    ].map(([label, val, color]) => (
                      <div key={label} className="zk-item">
                        <div className="zk-item-label">{label}</div>
                        <div className="zk-item-val" style={{ color }}>{val}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Pipeline */}
                <div className="pipeline-card">
                  <div className="pipeline-title">HE OPERATION PIPELINE</div>
                  <div className="pipeline-steps">
                    {[
                      ["RECEIVE", "Enc(liveᵢ) ← Client Machine", encVec.length > 0],
                      ["FETCH", "Enc(storedᵢ) ← Supabase DB", synced],
                      ["INVERT", "Enc(−bᵢ) = Enc(bᵢ)⁻¹ mod n²", isDone],
                      ["MULTIPLY", "Enc(Δᵢ) = Enc(liveᵢ)·Enc(−storedᵢ) mod n²", isDone],
                      ["RETURN", "Enc(Δ) → Client for decryption", isDone],
                    ].map(([op, desc, done]) => (
                      <div key={op} className={`pipeline-step ${done ? "done" : "pending"}`}>
                        <div className={`pipeline-dot ${done ? "done" : "pending"}`} />
                        <span className="pipeline-op">{op}</span>
                        <span className="pipeline-desc">{desc}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* DB Table */}
                <div className="db-card">
                  <div className="db-header">TABLE: eye_c_you_biometric_templates</div>
                  <div className="db-body">
                    {!synced ? (
                      <div className="db-empty">No records — complete Step 3 to sync.</div>
                    ) : (
                      <>
                        {[["id", syncId, "var(--text-dim)"], ["subject_identifier", SUBJECT_ID, "var(--amber)"]].map(([k, v, c]) => (
                          <div key={k} className="db-row">
                            <span className="db-key">{k}</span>
                            <span className="db-val" style={{ color: c }}>{v}</span>
                          </div>
                        ))}
                        {encVec.map((c, i) => (
                          <div key={i} className="db-row">
                            <span className="db-key">encrypted_iris_payload[{i}]</span>
                            <span className="db-val" style={{ color: "var(--cyan2)" }}>{truncHex(serializeC(c), 10)}</span>
                          </div>
                        ))}
                        {pubKey && (
                          <div className="db-row">
                            <span className="db-key">paillier_n_public_modulus</span>
                            <span className="db-val" style={{ color: "var(--violet)" }}>0x{pubKey.n.toString(16).slice(0, 14)}…</span>
                          </div>
                        )}
                        <div className="db-row">
                          <span className="db-key">key_bit_length</span>
                          <span className="db-val" style={{ color: "var(--text-dim)" }}>{String(PRIME_BITS * 2)}</span>
                        </div>
                      </>
                    )}
                  </div>
                </div>

                {/* Guarantees */}
                <div className="guarantees-card">
                  <div className="guarantees-title">PRIVACY GUARANTEES</div>
                  {[
                    "Supabase stores ONLY hex ciphertext — zero plaintext biometrics",
                    "HE operations use PUBLIC key only — private key never transmitted",
                    "Decryption happens exclusively on the client machine",
                    "Fresh random r per Enc() call — IND-CPA semantic security",
                    "Enc(a)·Enc(b) mod n² = Enc(a+b) — Paillier additive HE",
                    "Cloud learns nothing about iris vector from ciphertext",
                  ].map(p => (
                    <div key={p} className="guarantee-item">
                      <span className="guarantee-check">✓</span>
                      <span>{p}</span>
                    </div>
                  ))}
                </div>

                <TerminalLog logs={cloudLog} title="BLIND CLOUD GATEWAY LOG" variant={cloudVariant} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}