// edex.type — backend (HTTP auth + WebSocket multiplayer rooms)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { WebSocketServer } = require('ws');

/* ---------- storage (data.json) ---------- */
const DIR = process.env.DATA_DIR || __dirname;           // Render disk: DATA_DIR=/var/data
fs.mkdirSync(DIR, { recursive: true });
const DB = path.join(DIR, 'data.json');
let db = { secret: crypto.randomBytes(32).toString('hex'), users: {} };
try { db = JSON.parse(fs.readFileSync(DB)); } catch {}
if (process.env.SECRET) db.secret = process.env.SECRET;  // keeps login tokens valid across restarts
const save = () => fs.writeFile(DB, JSON.stringify(db), () => {});
save();

/* ---------- auth ---------- */
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const sign = s => crypto.createHmac('sha256', db.secret).update(s).digest('base64url');
const mkToken = n => { const p = Buffer.from(JSON.stringify({ n, e: Date.now() + 30 * 864e5 })).toString('base64url'); return p + '.' + sign(p); };
const chkToken = t => {
  try {
    const [p, s] = String(t).split('.');
    if (!s || sign(p) !== s) return;
    const o = JSON.parse(Buffer.from(p, 'base64url'));
    if (o.e > Date.now() && db.users[o.n]) return o.n;
  } catch {}
};
const pubUser = (n) => { const u = db.users[n]; return { name: n, games: u.games, wins: u.wins, best: u.best }; };

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/auth') {
    let b = '';
    req.on('data', d => { b += d; if (b.length > 2000) req.destroy(); });
    req.on('end', () => {
      const out = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
      try {
        const { mode, name, pass } = JSON.parse(b);
        const n = String(name || '').trim().toLowerCase(), pw = String(pass || '');
        if (!/^[a-z0-9_]{3,16}$/.test(n) || pw.length < 6) return out(400, { error: 'Login: 3–16 ta lotin harf/raqam, parol: kamida 6 belgi' });
        let u = db.users[n];
        if (mode === 'register') {
          if (u) return out(409, { error: 'Bu login band' });
          const salt = crypto.randomBytes(16).toString('hex');
          db.users[n] = { salt, hash: hash(pw, salt), games: 0, wins: 0, best: {} };
          save();
        } else if (!u || hash(pw, u.salt) !== u.hash) return out(401, { error: 'Login yoki parol xato' });
        out(200, { token: mkToken(n) });
      } catch { out(400, { error: 'Xato soʻrov' }); }
    });
    return;
  }
  fs.readFile(path.join(__dirname, 'public', 'index.html'), (e, d) => {
    res.writeHead(e ? 404 : 200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(d);
  });
});

/* ---------- game ---------- */
const WORDS = ('the be to of and a in that have it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us code server client data function variable network binary system array string loop class object method input output debug compile script database packet router cloud cache stack queue token thread domain linux python java html style query frame pixel browser kernel module cursor').split(' ');
const rooms = new Map(); let rid = 0;
const gen = n => Array.from({ length: n }, () => WORDS[Math.random() * WORDS.length | 0]).join(' ');
const send = (ws, o) => ws.readyState === 1 && ws.send(JSON.stringify(o));
const bc = (r, o) => r.players.forEach(p => send(p.ws, o));
const lobby = r => bc(r, { t: 'lobby', size: r.size, mode: r.mode, val: r.val, code: r.code, players: r.players.map(p => ({ name: p.name, ready: p.ready })) });

const wpm = (r, p) => {
  const lim = r.mode === 'time' ? r.t0 + r.val * 1000 : Infinity;
  const el = (p.fin || Math.min(Date.now(), lim)) - r.t0;
  return el > 800 ? Math.min(400, Math.round(p.c / 5 / (el / 60000))) : 0;
};

function join(p, m) {
  leave(p);
  let size = [1, 2, 3, 5].includes(m.size) ? m.size : 2;
  const mode = m.mode === 'words' ? 'words' : 'time';
  const val = (mode === 'time' ? [15, 30, 60] : [10, 25, 50]).includes(m.val) ? m.val : (mode === 'time' ? 30 : 25);
  const code = String(m.code || '').toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 12);
  if (code && size === 1) size = 2;
  const key = code ? 'c:' + code : `${size}|${mode}|${val}`;
  let r = (size > 1) && [...rooms.values()].find(x => x.key === key && x.state === 'wait' && x.players.length < x.size);
  if (!r) { r = { id: ++rid, key, code, size, mode, val, state: 'wait', players: [] }; rooms.set(r.id, r); }
  if (r.size > 1) r.players.forEach(x => x.ready = false);
  Object.assign(p, { room: r, ready: r.size === 1, c: 0, k: 0, w: 0, done: false, fin: 0 });
  r.players.push(p);
  lobby(r); check(r);
}

function leave(p) {
  const r = p.room; if (!r) return;
  p.room = null;
  r.players = r.players.filter(x => x !== p);
  if (!r.players.length) { clearTimeout(r.timer); clearInterval(r.iv); rooms.delete(r.id); return; }
  if (r.state === 'wait') { r.players.forEach(x => x.ready = false); lobby(r); }
  else if (r.state === 'play' && r.players.every(x => x.done)) end(r);
}

function check(r) {
  const n = r.players.length;
  if (r.state === 'wait' && n && r.players.every(p => p.ready) && (n > 1 || r.size === 1)) countdown(r);
}

function countdown(r) {
  r.state = 'count'; let n = 3;
  const tick = () => {
    if (!r.players.length) return;
    if (n > 0) { bc(r, { t: 'count', n }); n--; setTimeout(tick, 1000); } else go(r);
  };
  tick();
}

function go(r) {
  r.state = 'play'; r.text = gen(r.mode === 'words' ? r.val : 250); r.t0 = Date.now();
  bc(r, { t: 'go', text: r.text, mode: r.mode, val: r.val });
  r.timer = setTimeout(() => end(r), (r.mode === 'time' ? r.val : 180) * 1000 + 600);
  r.iv = setInterval(() => bc(r, { t: 'prog', players: r.players.map(p => ({ name: p.name, c: p.c, wpm: wpm(r, p), done: p.done })) }), 250);
}

function end(r) {
  if (r.state !== 'play') return;
  r.state = 'done'; clearTimeout(r.timer); clearInterval(r.iv);
  const ranking = r.players.map(p => ({ name: p.name, wpm: wpm(r, p), acc: p.k ? Math.round(100 * (p.k - p.w) / p.k) : 0 })).sort((a, b) => b.wpm - a.wpm);
  bc(r, { t: 'result', ranking, mode: r.mode, val: r.val });
  ranking.forEach((x, i) => {
    const u = db.users[x.name]; if (!u) return;
    u.games++; if (i === 0 && ranking.length > 1) u.wins++;
    const k = r.mode + r.val; if (x.wpm > (u.best[k] || 0)) u.best[k] = x.wpm;
  });
  save();
  r.players.forEach(p => p.room = null);
  rooms.delete(r.id);
}

/* ---------- websocket ---------- */
const wss = new WebSocketServer({ server });
wss.on('connection', (ws, req) => {
  const name = chkToken(new URL(req.url, 'http://x').searchParams.get('token'));
  if (!name) return ws.close(4001);
  wss.clients.forEach(c => { if (c !== ws && c.p && c.p.name === name) c.close(4002); });
  const p = ws.p = { ws, name, room: null, ready: false, c: 0, k: 0, w: 0, done: false, fin: 0 };
  ws.alive = true; ws.on('pong', () => ws.alive = true);
  send(ws, { t: 'hi', user: pubUser(name) });
  ws.on('message', d => {
    let m; try { m = JSON.parse(d); } catch { return; }
    const r = p.room;
    if (m.t === 'join') join(p, m);
    else if (m.t === 'leave') leave(p);
    else if (m.t === 'ready' && r && r.state === 'wait' && (r.players.length > 1 || r.size === 1)) { p.ready = !p.ready; lobby(r); check(r); }
    else if (m.t === 'p' && r && r.state === 'play' && !p.done) {
      const c = m.c | 0, k = m.k | 0, w = m.w | 0;
      if (c >= 0 && c <= r.text.length && c <= k && c <= (Date.now() - r.t0) / 40 + 10) {
        p.c = c; p.k = k; p.w = w;
        if (m.fin && r.mode === 'words') { p.done = true; p.fin = Date.now(); if (r.players.every(x => x.done)) end(r); }
      }
    }
  });
  ws.on('close', () => leave(p));
});
setInterval(() => wss.clients.forEach(c => { if (!c.alive) return c.terminate(); c.alive = false; c.ping(); }), 30000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('edex.type  →  http://localhost:' + PORT));
