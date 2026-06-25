// ── SECURITY CONFIG ────────────────────────
const UK       = 'sf_users_v4';
const SK       = 'sf_sess_v4';
const LK       = 'sf_locks_v4';
const MAX_ATTEMPTS  = 5;
const LOCKOUT_MS    = 15 * 60 * 1000;
const SESSION_TTL   = 7 * 24 * 60 * 60 * 1000;

// ── SAFE JSON PARSE (prevents crash on tampered localStorage) ──
function safeJSON(str, fallback = {}) {
  try { return JSON.parse(str || 'null') || fallback; }
  catch { return fallback; }
}

// ── DIGIT CAP — enforces max 2 digits and valid range on time inputs ──
function capDigits(el, maxLen, min, max) {
  // Strip non-digits
  el.value = el.value.replace(/[^0-9]/g, '');
  // Enforce maxlength
  if (el.value.length > maxLen) el.value = el.value.slice(0, maxLen);
  // Clamp to valid range once 2 digits entered
  if (el.value.length === maxLen) {
    const n = parseInt(el.value, 10);
    if (n > max) el.value = String(max).padStart(maxLen, '0');
    if (n < min) el.value = String(min).padStart(maxLen, '0');
  }
}

// ── INTERNET CONNECTIVITY CHECK ────────────────────────────────────────
function checkOnline() {
  const banner = document.getElementById('offline-banner');
  if (!banner) return;
  if (!navigator.onLine) {
    banner.style.display = 'flex';
  } else {
    banner.style.display = 'none';
  }
}
window.addEventListener('online',  checkOnline);
window.addEventListener('offline', checkOnline);

// ── SHA-256 via Web Crypto API (async, irreversible) ──
async function sha256(str) {
  const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

// Salt = username + fixed app salt (prevents rainbow table attacks)
async function hashPw(username, password) {
  return sha256(username + '::acadvault_2026::' + password);
}

// ── USER STORE ─────────────────────────────
const getU  = ()  => safeJSON(localStorage.getItem(UK), {});
const setU  = u   => localStorage.setItem(UK,  JSON.stringify(u));
const getLocks = ()=> safeJSON(localStorage.getItem(LK), {});
const setLocks = l => localStorage.setItem(LK,  JSON.stringify(l));

// ── SESSION (with expiry) ──────────────────
function setCU(username) {
  localStorage.setItem(SK, JSON.stringify({ u: username, exp: Date.now() + SESSION_TTL }));
}
function getCU() {
  try {
    const raw = localStorage.getItem(SK);
    if (!raw) return null;
    const s = JSON.parse(raw);
    if (!s || !s.u || !s.exp) return null;
    if (Date.now() > s.exp) { clrCU(); return null; }  // expired
    return s.u;
  } catch { return null; }
}
function clrCU() { localStorage.removeItem(SK); }

// ── LOCKOUT HELPERS ────────────────────────
function getLockout(u) {
  const locks = getLocks();
  return locks[u] || { attempts: 0, lockedUntil: 0 };
}
function recordFailedAttempt(u) {
  const locks = getLocks();
  if (!locks[u]) locks[u] = { attempts: 0, lockedUntil: 0 };
  locks[u].attempts++;
  if (locks[u].attempts >= MAX_ATTEMPTS) {
    locks[u].lockedUntil = Date.now() + LOCKOUT_MS;
    locks[u].attempts = 0; // reset counter after lockout
  }
  setLocks(locks);
  return locks[u];
}
function clearLockout(u) {
  const locks = getLocks();
  delete locks[u];
  setLocks(locks);
}
function isLocked(u) {
  const lk = getLockout(u);
  if (lk.lockedUntil && Date.now() < lk.lockedUntil) {
    const minsLeft = Math.ceil((lk.lockedUntil - Date.now()) / 60000);
    return minsLeft;
  }
  return 0;
}

// ── DATA STORE ─────────────────────────────
const dk = u => 'sf_d_v4_' + u;
function ldUD(u) {
  const d = safeJSON(localStorage.getItem(dk(u)), {});
  if (!d.subs)     d.subs     = [];
  if (!d.sess)     d.sess     = [];
  if (!d.calTests) d.calTests = [];
  if (!d.timer)    d.timer    = {n:0,m:0,d:''};
  if (!d.streak)   d.streak   = {n:0,ld:''};
  return d;
}
function svUD(u, d) { localStorage.setItem(dk(u), JSON.stringify(d)); }

// ── MIGRATE OLD ACCOUNTS (btoa → sha256) ───
// Silently migrate any accounts still using old btoa hashing
async function migrateOldAccounts() {
  const oldKey = 'sf_users_v3';
  const old = safeJSON(localStorage.getItem(oldKey), {});
  if (!Object.keys(old).length) return;
  const users = getU();
  for (const [u, data] of Object.entries(old)) {
    if (!users[u] && data.pw) {
      // We can't re-hash because we don't know the plaintext password.
      // Mark them as needing password reset instead.
      users[u] = { name: data.name, pw: null, needsReset: true, at: data.at };
    }
  }
  setU(users);
}

// ── PASSWORD STRENGTH (enforced on register) ──
function pwScore(pw) {
  let sc = 0;
  if (pw.length >= 8)  sc++;
  if (pw.length >= 12) sc++;
  if (/[A-Z]/.test(pw)) sc++;
  if (/[0-9]/.test(pw)) sc++;
  if (/[^a-zA-Z0-9]/.test(pw)) sc++;
  return sc; // 0-5
}
function checkPwStr(pw) {
  const bars = [gv('pw1'),gv('pw2'),gv('pw3'),gv('pw4')];
  const lbl  = gv('pw-lbl');
  bars.forEach(b => { b.className = 'pw-bar'; });
  if (!pw) { lbl.textContent = 'Enter a password'; return; }
  const sc  = pwScore(pw);
  const cls = sc <= 1 ? 'weak' : sc <= 3 ? 'medium' : 'strong';
  const txt = sc <= 1 ? 'Too weak' : sc <= 3 ? 'Medium' : 'Strong ✓';
  const fill = Math.min(sc, 4);
  for (let i = 0; i < fill; i++) bars[i].classList.add(cls);
  lbl.textContent = txt + (sc <= 1 ? ' — use 8+ chars, numbers & symbols' : '');
  lbl.style.color = cls==='weak' ? 'var(--red)' : cls==='medium' ? 'var(--amber)' : 'var(--green)';
}

// ── UI HELPERS ─────────────────────────────
function switchTab(t) {
  const isL = t === 'login';
  document.querySelectorAll('.auth-tab').forEach((e,i) => e.classList.toggle('active',(i===0&&isL)||(i===1&&!isL)));
  gv('form-login').classList.toggle('active', isL);
  gv('form-register').classList.toggle('active', !isL);
  gv('auth-title').textContent = isL ? 'Welcome back' : 'Create your account';
  gv('auth-sub').textContent   = isL ? 'Sign in to continue your study journey' : 'Join AcadVault and start achieving more';
  clrM();
}
function clrM() { ['login-err','reg-err','reg-ok'].forEach(id=>{ const e=gv(id); e.classList.remove('show'); e.textContent=''; }); }
const shErr = (id,m) => { const e=gv(id); e.innerHTML='⚠ '+m; e.classList.add('show'); };
const shOk  = (id,m) => { const e=gv(id); e.innerHTML=m;      e.classList.add('show'); };

// ── USERNAME CHECKER ───────────────────────
let unT = null;
function checkUsername(v) {
  const s = gv('us-status'); v = v.trim().toLowerCase();
  if (!v) { s.className='us'; return; }
  if (v.length < 3) { s.className='us taken'; s.textContent='✗ At least 3 characters required'; return; }
  if (!/^[a-z0-9_]+$/.test(v)) { s.className='us taken'; s.textContent='✗ Only letters, numbers, underscores'; return; }
  s.className='us check'; s.textContent='⟳ Checking…';
  clearTimeout(unT);
  unT = setTimeout(() => {
    const us = getU();
    if (us[v]) { s.className='us taken'; s.textContent='✗ @'+v+' is already taken'; }
    else        { s.className='us ok';    s.textContent='✓ @'+v+' is available!'; }
  }, 400);
}

// ── LOGIN ──────────────────────────────────
async function doLogin() {
  clrM();
  const u = gv('l-user').value.trim().toLowerCase();
  const p = gv('l-pass').value;
  if (!u || !p) { shErr('login-err','Please fill in all fields.'); return; }

  // Check lockout
  const locked = isLocked(u);
  if (locked) {
    shErr('login-err', `Account locked after too many attempts.<br>Try again in <strong>${locked} minute${locked!==1?'s':''}</strong>.`);
    return;
  }

  const us = getU();
  if (!us[u]) { shErr('login-err','No account found with that username.'); return; }

  // Handle accounts needing password reset (migrated from old system)
  if (us[u].needsReset) {
    shErr('login-err','This account was created on an older version. Please <strong>create a new account</strong> to continue.');
    return;
  }

  // SHA-256 hash comparison
  const hash = await hashPw(u, p);
  if (us[u].pw !== hash) {
    const lock = recordFailedAttempt(u);
    const remaining = MAX_ATTEMPTS - lock.attempts;
    if (lock.lockedUntil) {
      shErr('login-err',`Too many failed attempts. Account locked for <strong>15 minutes</strong>.`);
    } else {
      shErr('login-err',`Incorrect password. <strong>${remaining} attempt${remaining!==1?'s':''}</strong> remaining before lockout.`);
    }
    return;
  }

  // Success
  clearLockout(u);
  setCU(u);
  launch(u, us[u].name);
}

// ── REGISTER ───────────────────────────────
async function doRegister() {
  clrM();
  const name = gv('r-name').value.trim();
  const u    = gv('r-user').value.trim().toLowerCase();
  const p    = gv('r-pass').value;
  const p2   = gv('r-pass2').value;

  if (!name||!u||!p||!p2) { shErr('reg-err','Please fill in all fields.'); return; }
  if (u.length < 3)        { shErr('reg-err','Username must be at least 3 characters.'); return; }
  if (!/^[a-z0-9_]+$/.test(u)) { shErr('reg-err','Only letters, numbers and underscores in username.'); return; }
  if (p.length < 8)        { shErr('reg-err','Password must be at least 8 characters.'); return; }
  if (pwScore(p) < 2)      { shErr('reg-err','Password is too weak. Add numbers or symbols.'); return; }
  if (p !== p2)            { shErr('reg-err','Passwords do not match.'); return; }

  const us = getU();
  if (us[u]) { shErr('reg-err','Username @'+u+' is already taken. Please choose another.'); return; }

  // Hash password before storing
  const hash = await hashPw(u, p);
  us[u] = { name, pw: hash, at: new Date().toISOString() };
  setU(us);
  shOk('reg-ok','✓ Account created securely! Signing you in…');
  setTimeout(() => { setCU(u); launch(u, name); }, 900);
}

// ── LOGOUT ─────────────────────────────────
function doLogout() {
  clrCU(); D=null; cUser=null;
  if (checkInterval)  { clearInterval(checkInterval);  checkInterval=null; }
  if (activeCountdown){ clearInterval(activeCountdown); activeCountdown=null; }
  activeSessionId = null;
  gv('app-screen').style.display = 'none';
  gv('auth-screen').style.display = 'flex';
  gv('l-user').value=''; gv('l-pass').value=''; clrM();
}

// ── LAUNCH ─────────────────────────────────
function launch(u, name) {
  cUser = u; D = ldUD(u);
  gv('auth-screen').style.display = 'none';
  gv('app-screen').style.display  = 'block';
  const ini = name.trim().split(/\s+/).map(w=>w[0]).join('').slice(0,2).toUpperCase();
  gv('user-avatar').textContent = ini;
  gv('user-name').textContent   = name;
  gv('user-tag').textContent    = '@'+u;
  const h  = new Date().getHours();
  const gr = h<5?'Good night':h<12?'Good morning':h<17?'Good afternoon':'Good evening';
  gv('dash-greet').innerHTML = gr+', <span>'+name.split(' ')[0]+'</span> 👋';
  go('dashboard'); renderT();
  if (checkInterval) clearInterval(checkInterval);
  checkInterval = setInterval(runSessionCheck, 30000);
  setTimeout(runSessionCheck, 1000);
}

// ── APP ───────────────────────────────────

// ── XSS SANITISER ────────────────────────────────────────────────────────────
// Escapes user-typed content before inserting into innerHTML.
// Prevents <script>, event handlers, and any injected HTML from executing.
function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#039;');
}

const COLORS={gold:{bg:'rgba(201,168,76,0.12)',bd:'rgba(201,168,76,0.25)',tx:'#c9a84c'},blue:{bg:'rgba(91,156,246,0.12)',bd:'rgba(91,156,246,0.25)',tx:'#5b9cf6'},green:{bg:'rgba(62,207,142,0.12)',bd:'rgba(62,207,142,0.25)',tx:'#3ecf8e'},purple:{bg:'rgba(167,139,250,0.12)',bd:'rgba(167,139,250,0.25)',tx:'#a78bfa'},red:{bg:'rgba(241,107,107,0.12)',bd:'rgba(241,107,107,0.25)',tx:'#f16b6b'},teal:{bg:'rgba(45,212,191,0.12)',bd:'rgba(45,212,191,0.25)',tx:'#2dd4bf'},pink:{bg:'rgba(244,114,182,0.12)',bd:'rgba(244,114,182,0.25)',tx:'#f472b6'},amber:{bg:'rgba(245,166,35,0.12)',bd:'rgba(245,166,35,0.25)',tx:'#f5a623'}};
let D=null,cUser=null;
const save=()=>svUD(cUser,D);
const today=()=>new Date().toISOString().split('T')[0];
const fmtD=d=>new Date(d+'T00:00:00').toLocaleDateString('en-IN',{weekday:'short',day:'numeric',month:'short'});
const gv=id=>document.getElementById(id);
const sv=(id,v)=>{gv(id).textContent=v;};

function setMobNav(el) {
  document.querySelectorAll('.mn-item').forEach(n => n.classList.remove('active'));
  el.classList.add('active');
}

// ── STREAK TOOLTIP ────────────────────────────────────────────────────────
function showStreakInfo() {
  const tt = gv('streak-tooltip');
  if (!tt) return;
  tt.style.display = tt.style.display === 'none' ? 'block' : 'none';
  // Auto-hide after 5 seconds
  if (tt.style.display === 'block') setTimeout(() => { tt.style.display = 'none'; }, 5000);
}
// Close tooltip when clicking elsewhere
document.addEventListener('click', e => {
  const tt = gv('streak-tooltip');
  if (tt && !e.target.closest('.streak-c') && !e.target.closest('#streak-tooltip')) {
    tt.style.display = 'none';
  }
});

function go(id){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  gv('page-'+id).classList.add('active');
  const m={dashboard:'Dashboard',planner:'Planner',tracker:'Tracker',subjects:'Subjects',calendar:'Calendar',timer:'Focus Timer'};
  document.querySelectorAll('.nav-item').forEach(n=>{if(n.textContent.trim()===m[id])n.classList.add('active');});
  // sync mobile nav
  const mobLabels={dashboard:'Home',planner:'Planner',tracker:'Tracker',calendar:'Calendar',timer:'Timer',subjects:'Subjects'};
  document.querySelectorAll('.mn-item').forEach(n=>{
    n.classList.toggle('active', n.querySelector('.mn-lbl')?.textContent===mobLabels[id]);
  });
  refresh();
}

function refresh(){
  if(!D)return;
  const t=today();
  const yesterday=new Date(Date.now()-86400000).toISOString().split('T')[0];

  // ── STREAK LOGIC (45-min minimum per day) ──────────────────────────────
  const STREAK_MIN_MINS = 45; // minimum minutes to keep streak alive

  // Helper: how many minutes studied on a given date
  function minsStudiedOn(dateStr) {
    return D.sess
      .filter(s => s.date === dateStr && s.done)
      .reduce((a,s) => a + (s.ad || s.dur), 0);
  }

  const todayMins     = minsStudiedOn(t);
  const yesterdayMins = minsStudiedOn(yesterday);

  // Update streak
  if (todayMins >= STREAK_MIN_MINS) {
    // User met today's goal
    if (D.streak.ld === yesterday) {
      // Continuing from yesterday
      D.streak.n++;
    } else if (D.streak.ld !== t) {
      // Fresh start or gap > 1 day
      D.streak.n = 1;
    }
    D.streak.ld = t;
    save();
  } else if (D.streak.ld === yesterday && yesterdayMins < STREAK_MIN_MINS) {
    // Yesterday existed in record but user didn't meet the minimum — reset
    D.streak.n = 0;
    D.streak.ld = '';
    save();
  } else if (D.streak.ld && D.streak.ld < yesterday) {
    // Missed at least one full day — reset
    D.streak.n = 0;
    D.streak.ld = '';
    save();
  }

  sv('snum', D.streak.n);

  // Update streak today status for tooltip
  const statusEl = gv('streak-today-status');
  if (statusEl) {
    const remaining = Math.max(0, STREAK_MIN_MINS - todayMins);
    if (todayMins >= STREAK_MIN_MINS) {
      statusEl.innerHTML = `<span style="color:var(--green)">✓ Today's goal met! (${todayMins}min studied)</span>`;
    } else {
      statusEl.innerHTML = `<span style="color:var(--amber)">⏳ Today: ${todayMins}min studied — need <strong>${remaining} more min</strong> to keep streak</span>`;
    }
  }
  gv('today-date').textContent=new Date().toLocaleDateString('en-IN',{weekday:'long',year:'numeric',month:'long',day:'numeric'});
  const ws=new Date();ws.setDate(ws.getDate()-ws.getDay());
  const wds=Array.from({length:7},(_,i)=>{const d=new Date(ws);d.setDate(d.getDate()+i);return d.toISOString().split('T')[0];});
  const wsess=D.sess.filter(s=>wds.includes(s.date));
  const done=wsess.filter(s=>s.done);
  const min=done.reduce((a,s)=>a+(s.ad||s.dur),0);
  const rate=wsess.length?Math.round(done.length/wsess.length*100):0;
  sv('st-hrs',(min/60).toFixed(1));sv('st-sub',done.length+' sessions done');
  sv('st-done',done.length);sv('st-rate',rate+'%');
  const tsess=D.sess.filter(s=>s.date===t);
  sv('today-count',tsess.length+' session'+(tsess.length!==1?'s':'')+' today');
  gv('today-sess').innerHTML=tsess.length?tsess.map(sHTML).join(''):'<div class="empty"><div class="empty-icon">📝</div><p>No sessions today.<br>Head to the Planner!</p></div>';
  const vals=wds.map(d=>D.sess.filter(s=>s.date===d&&s.done).reduce((a,s)=>a+(s.ad||s.dur),0));
  const maxV=Math.max(...vals,1);
  const dnames=['Su','Mo','Tu','We','Th','Fr','Sa'];
  gv('weekly-chart').innerHTML=wds.map((d,i)=>{const h=Math.round(vals[i]/maxV*80)+4;return`<div class="bw"><div class="bv">${vals[i]>0?(vals[i]/60).toFixed(1)+'h':''}</div><div class="bar" style="height:${h}px;background:${d===t?'var(--gold)':'var(--surface3)'}"></div><div class="bl">${dnames[i]}</div></div>`;}).join('');
  const sp=gv('sub-prog');
  if(!D.subs.length){sp.innerHTML='<p style="font-size:13px;color:var(--dim)">Add subjects to see progress.</p>';}
  else sp.innerHTML=D.subs.map(sub=>{
    const c=COLORS[sub.c]||COLORS.gold;
    // All-time done minutes for this subject
    const totalMins=D.sess.filter(s=>s.sid===sub.id&&s.done).reduce((a,s)=>a+(s.ad||s.dur),0);
    // This week done minutes
    const weekMins=D.sess.filter(s=>s.sid===sub.id&&wds.includes(s.date)&&s.done).reduce((a,s)=>a+(s.ad||s.dur),0);
    const goal=sub.g||10;
    const pct=Math.min(Math.round(totalMins/(goal*60)*100),100);
    return`<div style="margin-bottom:14px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
        <span style="font-size:13px;font-weight:500">${esc(sub.e)} ${esc(sub.n)}</span>
        <span style="font-size:12px;color:var(--muted)">${(totalMins/60).toFixed(1)}h / ${goal}h</span>
      </div>
      <div class="pbar"><div class="pfill" style="width:${pct}%;background:${c.tx}"></div></div>
      <div style="font-size:10px;color:var(--dim);margin-top:3px;text-align:right">This week: ${(weekMins/60).toFixed(1)}h</div>
    </div>`;
  }).join('');
  if(!gv('pl-date').value)gv('pl-date').value=today();
  const up=[...D.sess].sort((a,b)=>(a.date+a.time).localeCompare(b.date+b.time)).filter(s=>s.date>=today());
  gv('upcoming').innerHTML=up.length?up.map(sHTML).join(''):'<div class="empty"><div class="empty-icon">🗓</div><p>No upcoming sessions.</p></div>';
  updateTrackerSubjectDropdown();renderTracker();renderSubs();renderCal();renderOverdueBanners();renderTestReminders();
  gv('t-link').innerHTML='<option value="">— None —</option>'+D.sess.filter(s=>!s.done).map(s=>`<option value="${s.id}">${esc(s.topic)} (${fmtD(s.date)})</option>`).join('');
  if(D.timer.d===today()){sv('t-sess',D.timer.n);gv('t-total').textContent=D.timer.m+' min';}
}

function sHTML(s){
  const sub=D.subs.find(x=>x.id===s.sid);
  const c=sub?(COLORS[sub.c]||COLORS.gold):COLORS.gold;
  return`<div class="si ${s.done?'done':''}">
    <div class="si-chk ${s.done?'chk':''}" onclick="toggleD('${s.id}')">✓</div>
    <div class="si-info">
      <div class="si-title">${esc(s.topic)}</div>
      <div class="si-meta"><span style="color:${c.tx};font-weight:600">${sub?sub.e+' '+sub.n:'No subject'}</span>${s.time?' · '+s.time:''} · ${s.dur}min${s.priority==='high'?' · <span style="color:var(--red);font-weight:600">⚡ High</span>':''}</div>
    </div>
    <div class="si-acts"><button class="btn btn-danger btn-ico" onclick="delSess('${s.id}')">🗑</button></div>
  </div>`;
}

// ── INPUT GUARDS ─────────────────────────────────────────────────────────────
// Blocks non-numeric keystrokes on number-only fields
function numOnly(e) {
  const allowed = ['Backspace','Delete','Tab','Enter','ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End'];
  if (allowed.includes(e.key)) return true;
  if (e.ctrlKey || e.metaKey) return true;  // allow Ctrl+A, Ctrl+C etc.
  if (e.key >= '0' && e.key <= '9') return true;
  e.preventDefault(); return false;
}

// ── AM/PM DISPLAY HELPER for native <input type="time"> ─────────────────────
// Updates the AM/PM toggle display to reflect the current value
function syncAmPmDisplay() {
  const t = gv('pl-time');
  if (!t || !t.value) return;
  const [hStr] = t.value.split(':');
  const h = parseInt(hStr, 10);
  document.querySelectorAll('#pl-ampm-display .ampm-opt').forEach(o => o.classList.remove('active'));
  const target = document.querySelector(`#pl-ampm-display .ampm-opt:${h < 12 ? 'first-child' : 'last-child'}`);
  if (target) target.classList.add('active');
}

// Sets the time to AM or PM while preserving the current hour/minute
function setTimeAmPm(ampm) {
  const t = gv('pl-time');
  if (!t) return;
  let [hStr, mStr] = (t.value || '12:00').split(':');
  let h = parseInt(hStr || '12', 10);
  if (ampm === 'AM' && h >= 12) h -= 12;
  if (ampm === 'PM' && h < 12)  h += 12;
  t.value = String(h).padStart(2,'0') + ':' + (mStr || '00');
  validatePlTime();
}

// Live hint below the time picker
function validatePlTime() {
  const t    = gv('pl-time');
  const hint = gv('pl-time-hint');
  if (!hint) return;
  syncAmPmDisplay();

  const timeVal = t ? t.value : '';
  const dateVal = gv('pl-date') ? gv('pl-date').value : '';

  if (!timeVal) {
    hint.className = 'time-hint';
    hint.textContent = '';
    return;
  }

  const [hh, mm] = timeVal.split(':').map(Number);
  const h12   = hh % 12 || 12;
  const ampm  = hh < 12 ? 'AM' : 'PM';
  const disp  = `${h12}:${String(mm).padStart(2,'0')} ${ampm}`;

  if (!dateVal) {
    hint.className = 'time-hint ok';
    hint.textContent = `✓ ${disp}`;
    return;
  }

  const sessionDT = new Date(dateVal + 'T' + timeVal);
  const now       = new Date();
  const diffMins  = Math.round((sessionDT - now) / 60000);

  if (diffMins < 0) {
    hint.className = 'time-hint err';
    hint.textContent = `⚠ ${disp} has already passed`;
  } else if (diffMins < 10) {
    hint.className = 'time-hint warn';
    hint.textContent = `⚡ ${disp} — starting in ${diffMins} min`;
  } else {
    hint.className = 'time-hint ok';
    hint.textContent = `✓ ${disp} — ${Math.floor(diffMins/60)}h ${diffMins%60}m from now`;
  }
}

// ── Tomorrow's date ──────────────────────────────────────────────────────────
function tomorrowStr() {
  const d = new Date(); d.setDate(d.getDate() + 1);
  return d.toISOString().split('T')[0];
}

// ── addSess — uses native time value directly ────────────────────────────────
function addSess() {
  const sn    = gv('pl-sub').value.trim();
  const topic = gv('pl-topic').value.trim();
  let   date  = gv('pl-date').value;
  const time24 = gv('pl-time') ? gv('pl-time').value : '';

  if (!sn)    { alert('Please enter a subject name.');  return; }
  if (!topic) { alert('Please enter a topic or task.'); return; }
  if (!date)  { alert('Please pick a date.');           return; }

  // Validate time if provided
  if (time24) {
    const sessionDT = new Date(date + 'T' + time24);
    const now       = new Date();
    const diffMins  = Math.round((sessionDT - now) / 60000);

    const [hh, mm] = time24.split(':').map(Number);
    const h12   = hh % 12 || 12;
    const ampm  = hh < 12 ? 'AM' : 'PM';
    const displayT = `${h12}:${String(mm).padStart(2,'0')} ${ampm}`;

    if (diffMins < 0) {
      const tomorrow    = tomorrowStr();
      const fmtTomorrow = new Date(tomorrow + 'T00:00:00').toLocaleDateString('en-IN',{weekday:'long',day:'numeric',month:'long'});
      const fmtToday    = new Date(date     + 'T00:00:00').toLocaleDateString('en-IN',{weekday:'long',day:'numeric',month:'long'});
      showTimeConflictModal({ displayT, fmtToday, fmtTomorrow, tomorrow, sn, topic, date, time24 });
      return;
    }
  }

  _commitSession(sn, topic, date, time24);
}

// ── Time Conflict Modal ──────────────────────────────────────────────────────
function showTimeConflictModal({ displayT, fmtToday, fmtTomorrow, tomorrow, sn, topic, date, time24 }) {
  const old = gv('time-conflict-modal');
  if (old) old.remove();
  const snS    = sn.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
  const topicS = topic.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
  const modal  = document.createElement('div');
  modal.id = 'time-conflict-modal';
  modal.className = 'mo open';
  modal.innerHTML = `
    <div class="modal" style="max-width:420px">
      <div class="mo-hdr">
        <div class="mo-title" style="font-size:18px">⚠ Time Already Passed</div>
        <button class="x-btn" onclick="document.getElementById('time-conflict-modal').remove()">✕</button>
      </div>
      <div style="font-size:13px;color:var(--muted);margin-bottom:20px;line-height:1.7">
        <strong style="color:var(--text)">${displayT}</strong> on <strong style="color:var(--text)">${fmtToday}</strong> has already passed. What would you like to do?
      </div>
      <div class="conflict-opt" onclick="resolveConflict('tomorrow','${snS}','${topicS}','${tomorrow}','${time24}')">
        <div class="co-icon">📅</div><div class="co-info"><div class="co-title">Schedule for tomorrow</div><div class="co-sub">${displayT} · ${fmtTomorrow}</div></div><div class="co-arrow">→</div>
      </div>
      <div class="conflict-opt" onclick="resolveConflict('changetime')">
        <div class="co-icon">🕐</div><div class="co-info"><div class="co-title">Change the time</div><div class="co-sub">Go back and pick a future time</div></div><div class="co-arrow">→</div>
      </div>
      <div class="conflict-opt" onclick="resolveConflict('anyway','${snS}','${topicS}','${date}','')">
        <div class="co-icon">📋</div><div class="co-info"><div class="co-title">Add without a time</div><div class="co-sub">Schedule for ${fmtToday} with no specific time</div></div><div class="co-arrow">→</div>
      </div>
    </div>`;
  document.body.appendChild(modal);
}

function resolveConflict(action, sn, topic, date, time24) {
  const modal = document.getElementById('time-conflict-modal');
  if (modal) modal.remove();
  if (action === 'changetime') return;
  _commitSession(sn, topic, date, time24 || '');
}

function _commitSession(sn, topic, date, time24) {
  let sub = D.subs.find(s => s.n.toLowerCase() === sn.toLowerCase());
  if (!sub) { sub = {id:Date.now().toString(), n:sn, e:'📖', c:'gold', g:10, x:''}; D.subs.push(sub); }
  D.sess.push({
    id:(Date.now()+1).toString(), sid:sub.id,
    topic: topic.slice(0,120),
    date, time: time24 || '',
    dur: Math.min(480, Math.max(15, parseInt(gv('pl-dur').value)||60)),
    priority: gv('pl-pri').value,
    notes: (gv('pl-notes').value||'').trim().slice(0,500),
    done:false, ad:null
  });
  save(); refresh();
  gv('pl-topic').value = '';
  gv('pl-notes').value = '';
  gv('pl-sub').value   = '';
  if (gv('pl-time'))  gv('pl-time').value = '';
  const hint = gv('pl-time-hint'); if (hint) { hint.className='time-hint'; hint.textContent=''; }
}

function subSug(v){
  const s=gv('sub-sug');
  if(!v.trim()||!D){s.style.display='none';return;}
  const m=D.subs.filter(x=>x.n.toLowerCase().includes(v.toLowerCase()));
  if(!m.length){s.style.display='none';return;}
  s.style.display='block';
  s.innerHTML=m.map(x=>`<div class="sug-item" onclick="pickSub('${x.n.replace(/'/g,"\\'")}')"><span style="font-size:18px">${x.e}</span><span>${x.n}</span></div>`).join('');
}
function pickSub(n){gv('pl-sub').value=n;hideSug();}
function hideSug(){gv('sub-sug').style.display='none';}
function toggleD(id){const s=D.sess.find(x=>x.id===id);if(!s)return;s.done=!s.done;if(s.done&&!s.ad)s.ad=s.dur;save();refresh();}
function delSess(id){if(!confirm('Delete this session?'))return;D.sess=D.sess.filter(s=>s.id!==id);save();refresh();}
// ── TRACKER FILTER STATE ──────────────────
let trStatus = 'all';

function setTrStatus(s, el) {
  trStatus = s;
  document.querySelectorAll('#tr-status-chips .chip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  renderTracker();
}

// Legacy filt() kept for compatibility
function filt(f, el) { setTrStatus(f, el); }

function clearTrFilters() {
  trStatus = 'all';
  gv('tr-search').value = '';
  gv('tr-subject').value = '';
  gv('tr-priority').value = '';
  gv('tr-sort').value = 'date-asc';
  document.querySelectorAll('#tr-status-chips .chip').forEach(c => c.classList.remove('active'));
  document.querySelector('#tr-status-chips [data-status="all"]').classList.add('active');
  renderTracker();
}

function updateTrackerSubjectDropdown() {
  if (!D) return;
  const sel = gv('tr-subject');
  if (!sel) return;
  const prev = sel.value;
  sel.innerHTML = '<option value="">All Subjects</option>' +
    D.subs.map(s => `<option value="${s.id}">${s.e} ${s.n}</option>`).join('');
  sel.value = prev;
}

function renderTracker() {
  if (!D) return;
  updateTrackerSubjectDropdown();

  const t        = today();
  const search   = (gv('tr-search')?.value   || '').toLowerCase().trim();
  const subjId   = gv('tr-subject')?.value   || '';
  const priority = gv('tr-priority')?.value  || '';
  const sort     = gv('tr-sort')?.value       || 'date-asc';

  let sessions = [...D.sess];

  // Status filter
  const statusFns = {
    all:     () => true,
    done:    s  => s.done,
    pending: s  => !s.done,
    today:   s  => s.date === t,
  };
  sessions = sessions.filter(statusFns[trStatus] || (() => true));

  // Subject filter
  if (subjId) sessions = sessions.filter(s => s.sid === subjId);

  // Priority filter
  if (priority) sessions = sessions.filter(s => s.priority === priority);

  // Search filter (topic, subject name, notes)
  if (search) {
    sessions = sessions.filter(s => {
      const sub = D.subs.find(x => x.id === s.sid);
      return (
        (s.topic  || '').toLowerCase().includes(search) ||
        (sub?.n   || '').toLowerCase().includes(search) ||
        (s.notes  || '').toLowerCase().includes(search)
      );
    });
  }

  // Sort
  sessions.sort((a, b) => {
    if (sort === 'date-asc')  return (a.date+a.time).localeCompare(b.date+b.time);
    if (sort === 'date-desc') return (b.date+b.time).localeCompare(a.date+a.time);
    if (sort === 'subject') {
      const sa = D.subs.find(x=>x.id===a.sid)?.n||'';
      const sb = D.subs.find(x=>x.id===b.sid)?.n||'';
      return sa.localeCompare(sb);
    }
    if (sort === 'duration') return (b.dur||0) - (a.dur||0);
    return 0;
  });

  // Show/hide clear button
  const hasFilters = search || subjId || priority || trStatus !== 'all';
  const clearBtn = gv('tr-clear');
  if (clearBtn) clearBtn.style.display = hasFilters ? 'inline-flex' : 'none';

  // Result count
  const countEl = gv('tr-count');
  if (countEl) {
    const total = D.sess.length;
    countEl.textContent = sessions.length === total
      ? `${total} session${total !== 1 ? 's' : ''}`
      : `${sessions.length} of ${total} sessions`;
  }

  gv('tracker').innerHTML = sessions.length
    ? sessions.map(sHTML).join('')
    : `<div class="empty"><div class="empty-icon">🔍</div><p>${hasFilters ? 'No sessions match your filters.' : 'Add sessions in the Planner first!'}</p></div>`;
}
let editId=null;
function openMo(id){
  editId=id||null;
  if(id){const s=D.subs.find(x=>x.id===id);gv('mo-title').textContent='Edit Subject';gv('sn').value=s.n;gv('se').value=s.e;gv('sc').value=s.c;gv('sg').value=s.g;gv('sx').value=s.x||'';}
  else{gv('mo-title').textContent='New Subject';['sn','se','sx'].forEach(i=>gv(i).value='');gv('sc').value='gold';gv('sg').value=10;}
  gv('mo').classList.add('open');
}
function closeMo(){gv('mo').classList.remove('open');editId=null;}
function saveSub(){
  const n=gv('sn').value.trim();if(!n){alert('Enter a name.');return;}
  const obj={n,e:gv('se').value.trim()||'📖',c:gv('sc').value,g:parseInt(gv('sg').value)||10,x:gv('sx').value};
  if(editId)Object.assign(D.subs.find(s=>s.id===editId),obj);
  else D.subs.push({id:Date.now().toString(),...obj});
  save();closeMo();refresh();
}
function delSub(id){if(!confirm('Delete subject and all its sessions?'))return;D.subs=D.subs.filter(s=>s.id!==id);D.sess=D.sess.filter(s=>s.sid!==id);save();refresh();}
function renderSubs(){
  if(!D)return;
  const g=gv('sub-grid');
  if(!D.subs.length){g.innerHTML='<div class="empty" style="grid-column:1/-1"><div class="empty-icon">📚</div><p>No subjects yet!<br>Type one in the Planner or click "+ New Subject".</p></div>';return;}

  // Weekly hours (for "this week" badge)
  const ws=new Date();ws.setDate(ws.getDate()-ws.getDay());
  const wds=Array.from({length:7},(_,i)=>{const d=new Date(ws);d.setDate(d.getDate()+i);return d.toISOString().split('T')[0];});

  g.innerHTML=D.subs.map(sub=>{
    const c=COLORS[sub.c]||COLORS.gold;
    const allS=D.sess.filter(s=>s.sid===sub.id);
    const doneS=allS.filter(s=>s.done);

    // ── ALL-TIME minutes (fills the bar) ──
    const totalMins=doneS.reduce((a,s)=>a+(s.ad||s.dur),0);
    const totalHrs=(totalMins/60).toFixed(1);
    const goal=sub.g||10;

    // ── THIS WEEK minutes (small badge) ──
    const weekMins=doneS.filter(s=>wds.includes(s.date)).reduce((a,s)=>a+(s.ad||s.dur),0);
    const weekHrs=(weekMins/60).toFixed(1);

    // ── Bar % based on all-time vs goal ──
    const pct=Math.min(Math.round(totalMins/(goal*60)*100),100);

    const de=sub.x?Math.ceil((new Date(sub.x)-new Date())/86400000):null;

    return`<div class="sub-card" style="border-color:${c.bd}">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div class="sub-icon" style="background:${c.bg};border:1px solid ${c.bd}">${esc(sub.e)}</div>
        <div style="display:flex;gap:6px">
          <button class="btn btn-ghost btn-ico" onclick="openMo('${sub.id}')">✏️</button>
          <button class="btn btn-danger btn-ico" onclick="delSub('${sub.id}')">🗑</button>
        </div>
      </div>
      <div class="sub-name" style="color:${c.tx}">${esc(sub.n)}</div>
      <div class="sub-stats">${allS.length} session${allS.length!==1?'s':''} · ${totalHrs}h total</div>
      <div style="font-size:11px;color:var(--muted);margin-bottom:10px">
        This week: <span style="color:${c.tx};font-weight:600">${weekHrs}h</span>
      </div>
      ${de!==null?`<div style="font-size:12px;color:${de<=7?'var(--red)':'var(--muted)'};margin-bottom:10px;font-weight:500">📅 Exam in ${de} day${de!==1?'s':''}</div>`:''}
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">
        <span style="font-size:11px;color:var(--muted)">All-time progress</span>
        <span style="font-size:11px;font-weight:600;color:${c.tx}">${totalHrs}h / ${goal}h goal</span>
      </div>
      <div class="pbar"><div class="pfill" style="width:${pct}%;background:${c.tx}"></div></div>
      <div style="font-size:11px;color:var(--muted);margin-top:5px;text-align:right;font-weight:500">${pct}% complete</div>
    </div>`;
  }).join('');
}
// ── CALENDAR TESTS ────────────────────────────────────────────────────────
// Tests are stored in D.calTests = [{id, title, subject, date, time, notes, _remindedDay}]

function addCalTest() {
  const title   = gv('ct-title').value.trim();
  const subject = gv('ct-subject').value.trim();
  const date    = gv('ct-date').value;
  if (!title)   { alert('Please enter a test name.');  return; }
  if (!date)    { alert('Please pick a date.');         return; }
  if (!D.calTests) D.calTests = [];
  D.calTests.push({
    id: 'ct' + Date.now(),
    title, subject, date,
    time:  gv('ct-time').value || '',
    notes: gv('ct-notes').value.trim(),
    _remindedDay: false
  });
  save(); refresh();
  ['ct-title','ct-subject','ct-notes','ct-time'].forEach(id => gv(id).value = '');
  showAlert(`<div class="sa-badge postpone">📝 Test Added</div>
    <div class="sa-title">${title}</div>
    <div class="sa-meta">${subject ? subject + ' · ' : ''}${fmtD(date)}${gv('ct-time') ? '' : ''}<br>🔔 You'll be reminded the day before</div>
    <div class="sa-btns"><button class="sa-snooze" onclick="removeAlert(this.closest('.sess-alert'))">Got it</button></div>`);
}

function delCalTest(id) {
  if (!confirm('Delete this test?')) return;
  D.calTests = D.calTests.filter(t => t.id !== id);
  save(); refresh();
}

function calTestHTML(ct) {
  const now    = today();
  const isPast = ct.date < now;
  const isToday = ct.date === now;
  const daysLeft = Math.ceil((new Date(ct.date + 'T00:00:00') - new Date()) / 86400000);
  let urgency = '';
  if (isToday)       urgency = `<span style="color:var(--red);font-weight:700">🚨 TODAY</span>`;
  else if (daysLeft === 1) urgency = `<span style="color:var(--amber);font-weight:700">⚡ Tomorrow</span>`;
  else if (daysLeft <= 3)  urgency = `<span style="color:var(--amber)">in ${daysLeft} days</span>`;
  else if (!isPast)        urgency = `<span style="color:var(--muted)">in ${daysLeft} days</span>`;
  else                     urgency = `<span style="color:var(--dim)">Completed</span>`;

  return `<div class="cal-test-item ${isPast ? 'ct-past' : ''}">
    <div class="ct-dot"></div>
    <div class="ct-info">
      <div class="ct-title">${isPast ? '<s>' : ''}📝 ${esc(ct.title)}${isPast ? '</s>' : ''}</div>
      <div class="ct-meta">
        ${ct.subject ? `<span class="ct-sub-badge">${esc(ct.subject)}</span>` : ''}
        ${ct.time ? fmtTime(ct.time) + ' · ' : ''}${fmtD(ct.date)}
        ${ct.notes ? ` · <em style="color:var(--dim)">${esc(ct.notes.slice(0,40))}${ct.notes.length>40?'…':''}</em>` : ''}
      </div>
      <div style="margin-top:4px">${urgency}</div>
    </div>
    <button class="btn btn-danger btn-ico" onclick="delCalTest('${ct.id}')">🗑</button>
  </div>`;
}

// Dashboard: upcoming tests reminder
function renderTestReminders() {
  if (!D || !D.calTests) return;
  const t = today();
  // Show tests happening today or tomorrow on the dashboard
  const upcoming = D.calTests
    .filter(ct => ct.date >= t)
    .sort((a,b) => a.date.localeCompare(b.date))
    .slice(0, 3);
  const el = gv('dash-tests-area');
  if (!el) return;
  if (!upcoming.length) { el.innerHTML = ''; return; }
  el.innerHTML = upcoming.map(ct => {
    const daysLeft = Math.ceil((new Date(ct.date+'T00:00:00') - new Date()) / 86400000);
    const isToday  = ct.date === t;
    const isTomorrow = daysLeft === 1;
    if (!isToday && !isTomorrow && daysLeft > 3) return ''; // only show close ones
    return `<div class="overdue-banner" style="background:linear-gradient(135deg,rgba(241,107,107,0.1),rgba(241,107,107,0.03));border-color:rgba(241,107,107,0.3)">
      <div class="ob-icon">📝</div>
      <div class="ob-info">
        <div class="ob-title" style="color:var(--red)">${isToday ? '🚨 TEST TODAY' : isTomorrow ? '⚡ TEST TOMORROW' : `📅 Test in ${daysLeft} days`} — ${esc(ct.title)}</div>
        <div class="ob-meta">${ct.subject ? ct.subject + ' · ' : ''}${fmtD(ct.date)}${ct.time ? ' at ' + fmtTime(ct.time) : ''}</div>
      </div>
    </div>`;
  }).join('');
}

// 1-day-before test reminder via popup
function checkTestReminders() {
  if (!D || !D.calTests) return;
  const t = today();
  D.calTests.forEach(ct => {
    const daysLeft = Math.ceil((new Date(ct.date+'T00:00:00') - new Date()) / 86400000);
    if (daysLeft === 1 && !ct._remindedDay) {
      ct._remindedDay = true; save();
      sendNotif('📝 Test Tomorrow!', ct.title + (ct.subject ? ' — ' + ct.subject : ''));
      showAlert(`<div class="sa-badge" style="background:rgba(241,107,107,0.15);color:var(--red);border:1px solid rgba(241,107,107,0.3)">📝 Test Tomorrow</div>
        <div class="sa-title">${esc(ct.title)}</div>
        <div class="sa-meta">${ct.subject ? ct.subject + ' · ' : ''}${fmtD(ct.date)}${ct.time ? ' at ' + fmtTime(ct.time) : ''}<br>${ct.notes ? ct.notes.slice(0,60) : 'Make sure you\'re prepared!'}</div>
        <div class="sa-btns"><button class="sa-snooze" onclick="removeAlert(this.closest('.sess-alert'))">Got it, thanks!</button></div>`);
    }
    // Same-day reminder
    if (ct.date === t && !ct._remindedToday) {
      ct._remindedToday = true; save();
      sendNotif('🚨 Test Today!', ct.title + (ct.subject ? ' — ' + ct.subject : ''));
      showAlert(`<div class="sa-badge" style="background:rgba(241,107,107,0.15);color:var(--red);border:1px solid rgba(241,107,107,0.3)">🚨 Test Today!</div>
        <div class="sa-title">${esc(ct.title)}</div>
        <div class="sa-meta">${ct.subject ? ct.subject + ' · ' : ''}${ct.time ? 'At ' + fmtTime(ct.time) : 'Today'}</div>
        <div class="sa-btns"><button class="sa-snooze" onclick="removeAlert(this.closest('.sess-alert'))">Noted!</button></div>`);
    }
  });
}



function addMeeting(){
  const title=gv('mt-title').value.trim();
  const date=gv('mt-date').value;
  const time=gv('mt-time').value;
  if(!title){alert('Please enter a meeting title.');return;}
  if(!date){alert('Please pick a date.');return;}
  if(!time){alert('Please set a starting time.');return;}
  const mtg={
    id:'m'+(Date.now()),
    title, date, time,
    dur:parseInt(gv('mt-dur').value)||30,
    type:gv('mt-type').value,
    desc:gv('mt-desc').value.trim(),
    loc:gv('mt-loc').value.trim(),
    done:false,
    _notif5:false, _alertedStart:false
  };
  if(!D.meetings) D.meetings=[];
  D.meetings.push(mtg);
  save(); refresh();
  ['mt-title','mt-desc','mt-loc'].forEach(id=>gv(id).value='');
  gv('mt-dur').value=30;
  showAlert(`<div class="sa-badge postpone">📅 Meeting Added</div>
    <div class="sa-title">${title}</div>
    <div class="sa-meta">${fmtD(date)} at ${fmtTime(time)}</div>
    <div class="sa-btns"><button class="sa-snooze" onclick="removeAlert(this.closest('.sess-alert'))">Done</button></div>`);
}

function delMeeting(id){
  if(!confirm('Delete this meeting?'))return;
  D.meetings=D.meetings.filter(m=>m.id!==id);
  save(); refresh();
}

let editMtgId=null;
function openMeetingMo(id){
  editMtgId=id;
  const m=D.meetings.find(x=>x.id===id);
  if(!m)return;
  gv('mm-title').value=m.title;
  gv('mm-desc').value=m.desc||'';
  gv('mm-date').value=m.date;
  gv('mm-time').value=m.time;
  gv('mm-dur').value=m.dur||30;
  gv('mm-type').value=m.type||'other';
  gv('mm-loc').value=m.loc||'';
  gv('meeting-modal').classList.add('open');
}
function closeMeetingMo(){gv('meeting-modal').classList.remove('open');editMtgId=null;}
function saveMeetingEdit(){
  const m=D.meetings.find(x=>x.id===editMtgId);
  if(!m){closeMeetingMo();return;}
  const title=gv('mm-title').value.trim();
  if(!title){alert('Please enter a meeting title.');return;}
  m.title=title; m.desc=gv('mm-desc').value.trim();
  m.date=gv('mm-date').value; m.time=gv('mm-time').value;
  m.dur=parseInt(gv('mm-dur').value)||30;
  m.type=gv('mm-type').value; m.loc=gv('mm-loc').value.trim();
  m._alertedStart=false; m._notif5=false;
  save(); closeMeetingMo(); refresh();
}

function meetingHTML(m){
  const icon=MTG_ICONS[m.type]||'📌';
  const label=MTG_LABELS[m.type]||'Meeting';
  const now=nowDT();
  const mDT=m.date+'T'+m.time;
  const isOver=mDT<now;
  return`<div class="meeting-item">
    <div class="mi-dot" style="${isOver?'background:var(--dim)':''}"></div>
    <div class="mi-info">
      <div class="mi-title" style="${isOver?'text-decoration:line-through;opacity:0.5':''}">
        ${icon} ${esc(m.title)}
      </div>
      <div class="mi-meta">
        <span class="mi-badge">${label}</span>
        ${fmtTime(m.time)} · ${m.dur}min
        ${m.loc?' · 📍 '+esc(m.loc):''}
        ${m.desc?' · <em style="color:var(--dim)">'+esc(m.desc.slice(0,40))+(m.desc.length>40?'…':'')+'</em>':''}
      </div>
    </div>
    <div class="mi-acts" style="display:flex;gap:5px;opacity:0;transition:opacity 0.15s">
      <button class="btn btn-ghost btn-ico" onclick="openMeetingMo('${m.id}')">✏️</button>
      <button class="btn btn-danger btn-ico" onclick="delMeeting('${m.id}')">🗑</button>
    </div>
  </div>`;
}

// ── Dashboard: Today's meetings reminder ──
function renderMeetingReminders(){
  if(!D)return;
  const reminderEl=gv('meeting-reminder-area');
  const listEl=gv('dash-meetings-list');
  if(!D.meetings)D.meetings=[];
  const t=today(), now=nowDT();
  const todayMtgs=[...D.meetings]
    .filter(m=>m.date===t)
    .sort((a,b)=>a.time.localeCompare(b.time));

  // ── Top reminder banners (only for upcoming / imminent) ──
  if(reminderEl){
    const imminent=todayMtgs.filter(m=>{
      const mins=minsUntil(m.date+'T'+m.time);
      return mins>=-5 && mins<=30; // within 5min past or 30min future
    });
    reminderEl.innerHTML=imminent.map(m=>{
      const mDT=m.date+'T'+m.time;
      const mins=minsUntil(mDT);
      const isOver=mDT<now;
      const icon=MTG_ICONS[m.type]||'📌';
      const label=MTG_LABELS[m.type]||'Meeting';
      let timeLabel='';
      if(isOver)timeLabel='<span style="color:var(--red);font-weight:700">⚠ Just passed</span>';
      else if(mins<=5)timeLabel=`<span style="color:var(--amber);font-weight:700">⚡ Starting very soon!</span>`;
      else timeLabel=`in ${mins}m`;
      return`<div class="meeting-reminder ${isOver?'mr-overdue':''}">
        <div class="mr-icon">${icon}</div>
        <div class="mr-info">
          <div class="mr-title">${esc(m.title)}</div>
          <div class="mr-meta"><span class="mi-badge" style="background:rgba(91,156,246,0.1);border-color:rgba(91,156,246,0.2);color:var(--blue)">${label}</span> · ${m.dur}min${m.loc?' · 📍 '+esc(m.loc):''}${m.desc?' · '+esc(m.desc.slice(0,35))+(m.desc.length>35?'…':''):''}</div>
        </div>
        <div style="text-align:right;flex-shrink:0">
          <div class="mr-time">${fmtTime(m.time)}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:2px">${timeLabel}</div>
        </div>
      </div>`;
    }).join('');
  }

  // ── Dashboard meetings card (all today's meetings) ──
  if(listEl){
    if(!todayMtgs.length){
      listEl.innerHTML='<div class="empty" style="padding:20px 10px"><div class="empty-icon" style="font-size:24px">📅</div><p>No meetings today.</p></div>';
    } else {
      listEl.innerHTML=todayMtgs.map(m=>{
        const mDT=m.date+'T'+m.time;
        const isOver=mDT<now;
        const mins=minsUntil(mDT);
        const icon=MTG_ICONS[m.type]||'📌';
        const label=MTG_LABELS[m.type]||'Meeting';
        let badge='';
        if(isOver) badge='<span style="font-size:10px;color:var(--dim);font-weight:600;margin-left:6px">✓ Passed</span>';
        else if(mins<=5) badge='<span style="font-size:10px;color:var(--amber);font-weight:700;margin-left:6px">⚡ Now</span>';
        else if(mins<=30) badge=`<span style="font-size:10px;color:var(--blue);font-weight:600;margin-left:6px">in ${mins}m</span>`;
        return`<div style="display:flex;align-items:center;gap:12px;padding:11px 0;border-bottom:1px solid var(--border);opacity:${isOver?0.5:1}">
          <div style="width:36px;height:36px;border-radius:9px;background:rgba(91,156,246,0.1);border:1px solid rgba(91,156,246,0.2);display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0">${icon}</div>
          <div style="flex:1;min-width:0">
            <div style="font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(m.title)}${badge}</div>
            <div style="font-size:11px;color:var(--muted);margin-top:2px">${label}${m.loc?' · 📍 '+esc(m.loc):''}</div>
          </div>
          <div style="font-family:'Cormorant Garamond',serif;font-size:15px;font-weight:700;color:${isOver?'var(--dim)':'var(--blue)'};white-space:nowrap">${fmtTime(m.time)}</div>
        </div>`;
      }).join('')+'<div style="height:2px"></div>';
    }
  }
}

// ── Meeting check in session engine ──
function checkMeetings(){
  if(!D||!D.meetings)return;
  D.meetings.forEach(m=>{
    const mDT=m.date+'T'+m.time;
    const mins=minsUntil(mDT);
    if(mins===5&&!m._notif5){
      m._notif5=true; save();
      sendNotif('Meeting in 5 minutes 🔔', m.title+' starts soon');
      showAlert(`<div class="sa-badge postpone">📅 In 5 mins</div>
        <div class="sa-title">${esc(m.title)}</div>
        <div class="sa-meta">${MTG_LABELS[m.type]||'Meeting'} at ${fmtTime(m.time)}${m.loc?' · '+esc(m.loc):''}</div>
        <div class="sa-btns"><button class="sa-snooze" onclick="removeAlert(this.closest('.sess-alert'))">Got it</button></div>`);
    }
    if(mins===0&&!m._alertedStart){
      m._alertedStart=true; save();
      sendNotif('Meeting Starting Now! 📅', m.title);
      showAlert(`<div class="sa-badge postpone">📅 Now</div>
        <div class="sa-title">${esc(m.title)}</div>
        <div class="sa-meta">${m.dur} min · ${esc(m.desc||MTG_LABELS[m.type]||'')}${m.loc?' · 📍 '+esc(m.loc):''}</div>
        <div class="sa-btns"><button class="sa-snooze" onclick="removeAlert(this.closest('.sess-alert'))">Dismiss</button></div>`);
    }
  });
}

function focusAddMeeting(){
  go('calendar');
  setTimeout(()=>{ const el=gv('mt-date'); if(el){ el.scrollIntoView({behavior:'smooth'}); el.focus(); } },200);
}

let calD=new Date();
function chMonth(d){calD.setMonth(calD.getMonth()+d);renderCal();}

function renderCal(){
  if(!D)return;
  if(!D.calTests) D.calTests=[];
  const y=calD.getFullYear(),m=calD.getMonth();
  sv('cal-lbl',new Date(y,m,1).toLocaleDateString('en-IN',{month:'long',year:'numeric'}));
  gv('cal-hdrs').innerHTML=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map(d=>`<div class="cal-hdr">${d}</div>`).join('');
  const first=new Date(y,m,1).getDay(),days=new Date(y,m+1,0).getDate();
  let h='';
  for(let i=0;i<first;i++) h+=`<div class="cal-day empty"></div>`;
  for(let d=1;d<=days;d++){
    const ds=`${y}-${String(m+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    const hasSess=D.sess.some(s=>s.date===ds);
    const hasTest=D.calTests.some(ct=>ct.date===ds);
    const it=ds===today();
    let cls='cal-day';
    if(it) cls+=' today';
    if(hasSess&&hasTest) cls+=' has has-both';
    else if(hasSess)     cls+=' has';
    else if(hasTest)     cls+=' has has-test';
    h+=`<div class="${cls}" onclick="showDay('${ds}')">${d}</div>`;
  }
  gv('cal-grid').innerHTML=h;

  // Render upcoming tests list card
  const listEl=gv('cal-tests-list');
  const countEl=gv('cal-tests-count');
  if(listEl){
    const t=today();
    const upcoming=[...D.calTests].filter(ct=>ct.date>=t).sort((a,b)=>a.date.localeCompare(b.date));
    const past=[...D.calTests].filter(ct=>ct.date<t).sort((a,b)=>b.date.localeCompare(a.date)).slice(0,3);
    const all=[...upcoming,...past];
    if(countEl) countEl.textContent=upcoming.length+' upcoming';
    listEl.innerHTML=all.length?all.map(calTestHTML).join(''):'<div class="empty"><div class="empty-icon" style="font-size:24px">📝</div><p>No tests scheduled yet.</p></div>';
  }
}

function showDay(ds){
  if(!D.calTests) D.calTests=[];
  sv('cal-sel', fmtD(ds));
  const addBtn=gv('cal-day-add'); if(addBtn) addBtn.style.display='block';
  const ss  = D.sess.filter(s=>s.date===ds);
  const cts = [...D.calTests].filter(ct=>ct.date===ds).sort((a,b)=>(a.time||'').localeCompare(b.time||''));
  let html  = '';
  if(ss.length)  html+=`<div class="section-divider"><div class="sd-line"></div><div class="sd-label">📚 Study Sessions</div><div class="sd-line"></div></div>`+ss.map(sHTML).join('');
  if(cts.length) html+=`<div class="section-divider"><div class="sd-line"></div><div class="sd-label">📝 Tests & Exams</div><div class="sd-line"></div></div>`+cts.map(calTestHTML).join('');
  if(!ss.length&&!cts.length) html=`<div class="empty"><p>Nothing scheduled on this day.<br>Add a study session from the Planner, or schedule a test above.</p></div>`;
  if(!gv('ct-date').value||!ss.length&&!cts.length) { const ctd=gv('ct-date'); if(ctd) ctd.value=ds; }
  gv('cal-day').innerHTML=html;
}
let tMode='focus',tRun=false,tInt=null,tRem=25*60;
function setMode(m,el){tMode=m;clearInterval(tInt);tRun=false;gv('t-btn').textContent='▶ Start';gv('t-disp').className='timer-disp';document.querySelectorAll('#page-timer .chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');const nm={focus:'🎯 Focus Time',short:'☕ Short Break',long:'🌿 Long Break'};sv('t-mode',nm[m]);tRem=getMins()*60;renderT();}
function getMins(){return tMode==='focus'?(parseInt(gv('fl').value)||25):tMode==='short'?(parseInt(gv('sl').value)||5):(parseInt(gv('ll').value)||15);}
function toggleT(){
  if(tRun){clearInterval(tInt);tRun=false;gv('t-btn').textContent='▶ Resume';gv('t-disp').className='timer-disp pau';}
  else{tRun=true;gv('t-btn').textContent='⏸ Pause';gv('t-disp').className='timer-disp run';
    tInt=setInterval(()=>{tRem--;renderT();if(tRem<=0){clearInterval(tInt);tRun=false;gv('t-disp').className='timer-disp';gv('t-btn').textContent='▶ Start';
    if(tMode==='focus'&&D){const t=today();if(D.timer.d!==t){D.timer.n=0;D.timer.m=0;}D.timer.n++;D.timer.m+=getMins();D.timer.d=t;save();sv('t-sess',D.timer.n);gv('t-total').textContent=D.timer.m+' min';const lk=gv('t-link').value;if(lk)toggleD(lk);}
    alert(tMode==='focus'?'🎉 Focus session complete! Take a break.':'⚡ Break over! Back to studying.');resetT();}},1000);}
}
function resetT(){clearInterval(tInt);tRun=false;gv('t-btn').textContent='▶ Start';gv('t-disp').className='timer-disp';tRem=getMins()*60;renderT();}
function renderT(){const m=Math.floor(tRem/60),s=tRem%60;sv('t-disp',String(m).padStart(2,'0')+':'+String(s).padStart(2,'0'));}

// ── SMART SESSION TIMING ENGINE ──────────────
let activeSessionId = null;   // session currently running
let activeCountdown = null;   // countdown interval
let checkInterval   = null;   // periodic session check
let postponingSessId= null;   // session being postponed
let notifGranted    = false;

// Request browser notification permission
function requestNotifPerm(){
  if(!('Notification' in window)) return;
  if(Notification.permission==='granted'){notifGranted=true;return;}
  if(Notification.permission!=='denied') Notification.requestPermission().then(p=>{notifGranted=p==='granted';});
}

function sendNotif(title, body){
  if(notifGranted && Notification.permission==='granted'){
    new Notification(title, {body, icon:'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>📚</text></svg>'});
  }
}

// Get current datetime as comparable string YYYY-MM-DDTHH:MM
function nowDT(){
  const n=new Date();
  return n.toISOString().slice(0,16);
}
function sessDT(s){ return s.date+'T'+(s.time||'00:00'); }
function sessEndDT(s){
  if(!s.time) return null;
  const [h,m]=s.time.split(':').map(Number);
  const d=new Date(s.date+'T'+s.time);
  d.setMinutes(d.getMinutes()+(s.dur||60));
  return d.toISOString().slice(0,16);
}

// Format time nicely
function fmtTime(t){
  if(!t) return '';
  const parts = t.split(':');
  if(parts.length < 2) return t;
  const hr = parseInt(parts[0],10);
  const mn = parts[1].padStart(2,'0');
  const h12 = (hr % 12) || 12;
  const ampm = hr < 12 ? 'AM' : 'PM';
  return h12 + ':' + mn + ' ' + ampm;
}
function minsUntil(dt){ return Math.round((new Date(dt)-new Date())/60000); }

// ── Show alert popup ──
function showAlert(html){
  const c=gv('alerts-container');
  const el=document.createElement('div');
  el.className='sess-alert';
  el.innerHTML=html;
  c.appendChild(el);
  // auto-remove after 30s
  setTimeout(()=>{ el.classList.add('hiding'); setTimeout(()=>el.remove(),400); }, 30000);
}
function removeAlert(el){ el.classList.add('hiding'); setTimeout(()=>el.remove(),400); }

// ── Start a session (launches countdown) ──
function startSession(id){
  if(activeSessionId) return; // one at a time
  const s=D.sess.find(x=>x.id===id);
  if(!s||s.done) return;
  activeSessionId=id;
  let remaining=s.dur*60;

  // remove any alert for this session
  document.querySelectorAll('.sess-alert').forEach(el=>el.remove());

  renderActiveBanner(s, remaining);

  activeCountdown=setInterval(()=>{
    remaining--;
    const ab=gv('active-timer-'+id);
    if(ab){ const m=Math.floor(remaining/60), sc=remaining%60; ab.textContent=String(m).padStart(2,'0')+':'+String(sc).padStart(2,'0')+' remaining'; }
    if(remaining<=0){
      clearInterval(activeCountdown);
      activeSessionId=null;
      toggleD(id); // mark done
      sendNotif('Session Complete! 🎉', s.topic+' — great work!');
      showAlert(`<div class="sa-badge now">✓ Complete</div>
        <div class="sa-title">${esc(s.topic)}</div>
        <div class="sa-meta">Session finished! Well done 🎉</div>
        <div class="sa-btns"><button class="sa-start" onclick="this.closest('.sess-alert').remove()">Close</button></div>`);
      renderOverdueBanners();
      renderActiveBanner(null);
    }
  },1000);
  refresh();
}

// ── Done button on active banner ──
function endActiveSession(id){
  clearInterval(activeCountdown);
  activeSessionId=null;
  toggleD(id);
  renderActiveBanner(null);
  sendNotif('Session Marked Done ✓', D.sess.find(x=>x.id===id)?.topic||'');
}

// ── Render active banner ──
function renderActiveBanner(s, rem){
  const el=gv('active-area');
  if(!s){ el.innerHTML=''; return; }
  const m=Math.floor((rem||0)/60), sc=(rem||0)%60;
  el.innerHTML=`<div class="active-banner">
    <div class="ab-icon">🟢</div>
    <div class="ab-info">
      <div class="ab-title">Session In Progress — ${esc(s.topic)}</div>
      <div class="ab-timer" id="active-timer-${s.id}">${String(m).padStart(2,'0')}:${String(sc).padStart(2,'0')} remaining</div>
    </div>
    <button class="ab-done" onclick="endActiveSession('${s.id}')">Mark Done ✓</button>
  </div>`;
}

// ── Render overdue banners on dashboard ──
function renderOverdueBanners(){
  if(!D) return;
  const el=gv('overdue-area');
  const now=nowDT();
  const overdue=D.sess.filter(s=>
    !s.done && s.time && s.id!==activeSessionId &&
    sessDT(s) < now &&
    (s.date===today() || s.date < today())
  ).sort((a,b)=>sessDT(a).localeCompare(sessDT(b)));

  el.innerHTML=overdue.map(s=>{
    const sub=D.subs.find(x=>x.id===s.sid);
    const minsLate=Math.abs(minsUntil(sessDT(s)));
    const hoursLate=minsLate>=60?`${Math.floor(minsLate/60)}h ${minsLate%60}m`:minsLate+'m';
    return`<div class="overdue-banner">
      <div class="ob-icon">🚨</div>
      <div class="ob-info">
        <div class="ob-title">OVERDUE — Start Now! &nbsp;<span class="overdue-pill">⚠ ${hoursLate} late</span></div>
        <div class="ob-meta">${esc(s.topic)} &nbsp;·&nbsp; ${sub?sub.n:''} &nbsp;·&nbsp; Was due at ${fmtTime(s.time)} &nbsp;·&nbsp; ${s.dur}min session</div>
      </div>
      <button class="ob-start" onclick="startSession('${s.id}')">Start Now →</button>
    </div>`;
  }).join('');
}

// ── The main periodic check (runs every 30s) ──
function runSessionCheck(){
  if(!D) return;
  const now=nowDT();

  D.sess.forEach(s=>{
    if(s.done || !s.time || s.id===activeSessionId) return;
    const dt=sessDT(s);
    const mins=minsUntil(dt);

    // Remind 5 mins before
    if(mins===5 && !s._notif5){
      s._notif5=true; save();
      sendNotif('Session Starting Soon 🔔', s.topic+' starts in 5 minutes');
      showAlert(`<div class="sa-badge now">⏰ In 5 mins</div>
        <div class="sa-title">${esc(s.topic)}</div>
        <div class="sa-meta">Starting at ${fmtTime(s.time)} · ${s.dur} min session</div>
        <div class="sa-btns">
          <button class="sa-snooze" onclick="removeAlert(this.closest('.sess-alert'))">Dismiss</button>
        </div>`);
    }

    // Exactly at start time
    if(mins===0 && !s._alertedStart){
      s._alertedStart=true; save();
      sendNotif('Time to Study! 📚', s.topic+' is starting now');
      showAlert(`<div class="sa-badge now">🔔 Starting Now</div>
        <div class="sa-title">${esc(s.topic)}</div>
        <div class="sa-meta">${s.dur} min session &nbsp;·&nbsp; ${D.subs.find(x=>x.id===s.sid)?.n||''}</div>
        <div class="sa-btns">
          <button class="sa-start" onclick="startSession('${s.id}');this.closest('.sess-alert').remove()">Start Session →</button>
          <button class="sa-snooze" onclick="openPostpone('${s.id}');this.closest('.sess-alert').remove()">Postpone</button>
        </div>`);
    }

    // Postponed reminder
    if(s._postponedTo && minsUntil(s._postponedTo)===0 && !s._postponeNotified){
      s._postponeNotified=true; save();
      sendNotif('Postponed Session Reminder 🔔', s.topic+' — it\'s time!');
      showAlert(`<div class="sa-badge postpone">🔔 Postpone Reminder</div>
        <div class="sa-title">${esc(s.topic)}</div>
        <div class="sa-meta">Your postponed session is ready to start!</div>
        <div class="sa-btns">
          <button class="sa-start" onclick="startSession('${s.id}');this.closest('.sess-alert').remove()">Start Now →</button>
          <button class="sa-snooze" onclick="this.closest('.sess-alert').remove()">Dismiss</button>
        </div>`);
    }
  });

  renderOverdueBanners();
  checkTestReminders();
}

// ── Postpone logic ──
function openPostpone(id){
  postponingSessId=id;
  const s=D.sess.find(x=>x.id===id);
  const sub=D.subs.find(x=>x.id===s?.sid);
  gv('pt-sub').textContent=`Moving "${s?.topic||'Session'}" (${sub?.n||''}) to a new time. We'll remind you when it's ready.`;
  // default to 30 mins from now
  const d=new Date(); d.setMinutes(d.getMinutes()+30);
  gv('pt-time').value=d.toTimeString().slice(0,5);
  gv('pt-date').value=today();
  gv('postpone-modal').classList.add('open');
}
function closePostpone(){ gv('postpone-modal').classList.remove('open'); postponingSessId=null; }
function confirmPostpone(){
  if(!postponingSessId) return;
  const s=D.sess.find(x=>x.id===postponingSessId);
  if(!s){ closePostpone(); return; }
  const newTime=gv('pt-time').value;
  const newDate=gv('pt-date').value||today();
  if(!newTime){ alert('Please choose a new time.'); return; }
  const newDT=newDate+'T'+newTime;
  if(minsUntil(newDT)<=0){ alert('Please choose a future time.'); return; }
  s._postponedTo=newDT;
  s._postponeNotified=false;
  s._alertedStart=false; // reset so new time can trigger
  s.time=newTime; s.date=newDate;
  save(); closePostpone(); refresh();
  sendNotif('Session Postponed ✓', `"${esc(s.topic)}" rescheduled to ${fmtTime(newTime)}`);
  showAlert(`<div class="sa-badge postpone">✓ Rescheduled</div>
    <div class="sa-title">${esc(s.topic)}</div>
    <div class="sa-meta">Reminder set for ${fmtTime(newTime)} · We'll notify you then.</div>
    <div class="sa-btns"><button class="sa-snooze" onclick="removeAlert(this.closest('.sess-alert'))">Got it</button></div>`);
}

// ── Enhanced sHTML with overdue indicator ──
function sHTML(s){
  const sub=D.subs.find(x=>x.id===s.sid);
  const c=sub?(COLORS[sub.c]||COLORS.gold):COLORS.gold;
  const now=nowDT();
  const isOverdue=!s.done && s.time && sessDT(s)<now;
  const isNow=!s.done && s.time && Math.abs(minsUntil(sessDT(s)))<=2;
  const mLate=isOverdue?Math.abs(minsUntil(sessDT(s))):0;
  const lateTxt=mLate>=60?`${Math.floor(mLate/60)}h ${mLate%60}m late`:`${mLate}m late`;

  return`<div class="si ${s.done?'done':''} ${isNow&&!s.done?'upcoming-now':''}">
    <div class="si-chk ${s.done?'chk':''}" onclick="toggleD('${s.id}')">✓</div>
    <div class="si-info">
      <div class="si-title">${esc(s.topic)}${isOverdue&&!s.done?' <span class="overdue-pill">⚠ '+lateTxt+'</span>':''}</div>
      <div class="si-meta">
        <span style="color:${c.tx};font-weight:600">${sub?sub.e+' '+sub.n:'No subject'}</span>
        ${s.time?' · '+fmtTime(s.time):''} · ${s.dur}min
        ${s.priority==='high'||isOverdue?' · <span style="color:var(--red);font-weight:700">'+(isOverdue?'🚨 URGENT':'⚡ High')+'</span>':''}
        ${s._postponedTo&&!s.done?' · <span style="color:var(--blue);font-size:11px">⏰ Postponed to '+fmtTime(s._postponedTo.slice(11,16))+'</span>':''}
      </div>
    </div>
    <div class="si-acts">
      ${!s.done&&s.time&&!activeSessionId?`<button class="btn btn-sm" style="background:rgba(201,168,76,0.15);color:var(--gold2);border:1px solid rgba(201,168,76,0.3);font-size:11px;padding:5px 10px" onclick="startSession('${s.id}')">▶ Start</button>`:''}
      <button class="btn btn-danger btn-ico" onclick="delSess('${s.id}')">🗑</button>
    </div>
  </div>`;
}

// BOOT
(async function(){
  checkOnline(); // check internet on load
  await migrateOldAccounts();
  const u = getCU();
  if (u) {
    const us = getU();
    if (us[u] && !us[u].needsReset) { launch(u, us[u].name); return; }
    clrCU();
  }
  gv('auth-screen').style.display = 'flex';
})();
renderT();
requestNotifPerm();