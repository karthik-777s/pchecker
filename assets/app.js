/* assets/app.js
   Frontend for Phish-Defender.
   UPDATE: set WORKER_BASE to your worker URL (no trailing slash)
*/
const WORKER_BASE = 'https://phish-checker-api.phisher.workers.dev/'; // e.g. https://phish-proxy.YOUR.workers.dev

// DOM helpers
const $ = id => document.getElementById(id);
const qs = sel => document.querySelector(sel);

// Theme toggle
const themeToggle = $('theme-toggle');
function loadTheme(){
  const t = localStorage.getItem('pd_theme') || 'dark';
  document.body.classList.toggle('theme-light', t === 'light');
}
themeToggle.onclick = () => {
  const isLight = document.body.classList.toggle('theme-light');
  localStorage.setItem('pd_theme', isLight ? 'light' : 'dark');
};
loadTheme();

// Tabs
document.querySelectorAll('.tab').forEach(b => {
  b.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    const tab = b.dataset.tab;
    document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
    document.getElementById(tab).classList.remove('hidden');
  });
});

// utility: show provider block
function renderProviders(container, providers, featureFilter) {
  container.innerHTML = '';
  // Group providers by feature relevance using a small mapping
  const featureMap = {
    url: ['VirusTotal','urlscan.io','URLHaus','AlienVault OTX','Filescan.io','MalShare','RapidAPI','Arya.io'],
    email: ['AbuseIPDB','AlienVault OTX'],
    file: ['VirusTotal','Filescan.io','MalShare']
  };

  // Keep providers only relevant to the selected feature
  const filtered = providers.filter(p => {
    if (!featureFilter) return true;
    const list = featureMap[featureFilter] || [];
    return list.includes(p.name) || (p.name && p.name.toLowerCase().includes(featureFilter));
  });

  filtered.forEach(p => {
    const div = document.createElement('div');
    div.className = 'provider';
    const verdict = inferVerdict(p);
    div.innerHTML = `
      <div>
        <div class="title"><strong>${escapeHtml(p.name || 'unknown')}</strong></div>
        <div class="meta">${escapeHtml(providerSummaryText(p))}</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <div class="badge ${verdict}">${verdict}</div>
        <button class="btn raw-btn">Raw</button>
      </div>
    `;
    // raw btn
    div.querySelector('.raw-btn').addEventListener('click', () => {
      $('raw-output').textContent = JSON.stringify(p, null, 2);
      // switch to raw tab
      document.querySelector('[data-tab="tab-raw"]').click();
    });
    container.appendChild(div);
  });
}

// Combined percent calculation
function scoreFromProviders(providers){
  if(!providers || providers.length===0) return 0;
  // map verdict to number: safe=0, suspicious=50, malicious=100
  const mapV = v => v === 'malicious' ? 100 : v === 'suspicious' ? 50 : 0;
  const scores = providers.map(p => mapV(inferVerdict(p)));
  const avg = Math.round(scores.reduce((a,b)=>a+b,0)/scores.length);
  return avg;
}

// small helpers
function escapeHtml(s){ if(s==null) return ''; return String(s).replace(/[&<>"']/g, (m)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[m]));}
function inferVerdict(p){
  if(!p) return 'suspicious';
  if(p.error) return 'suspicious';
  // virusTotal
  if(p.name && /virus/i.test(p.name)){
    const stats = p.analysis?.data?.attributes?.stats || p.raw?.data?.attributes?.last_analysis_stats;
    if(stats){
      if(stats.malicious && stats.malicious>0) return 'malicious';
      if(stats.suspicious && stats.suspicious>0) return 'suspicious';
      return 'safe';
    }
  }
  if(p.name && /urlscan/i.test(p.name)){
    const r = p.result || p.raw;
    if(r && (r.verdicts || r.verdict || (r.page && r.page.verdicts))) {
      // best-effort -> check textual content for 'malicious' or 'phish'
      const txt = JSON.stringify(r).toLowerCase();
      if(txt.includes('malicious')||txt.includes('phish')) return 'malicious';
      return 'safe';
    }
  }
  if(p.name && /urlhaus/i.test(p.name)){
    const raw = p.raw;
    if(raw && typeof raw === 'object' && raw.query_status && /ok|found/i.test(raw.query_status)) return 'malicious';
  }
  if(p.name && /abuseipdb/i.test(p.name)){
    const raw = p.raw;
    if(raw && raw.data && raw.data.abuseConfidenceScore && raw.data.abuseConfidenceScore>30) return 'suspicious';
    return 'safe';
  }
  if(p.name && /filescan|malshare/i.test(p.name)){
    const txt = JSON.stringify(p.raw||'').toLowerCase();
    if(txt.includes('malicious')||txt.includes('trojan')||txt.includes('phish')) return 'malicious';
    return 'safe';
  }
  if(p.ok === false) return 'suspicious';
  if(p.note && /not configured|skip/i.test(p.note)) return 'suspicious';
  if(p.raw || p.analysis) return 'safe';
  return 'suspicious';
}
function providerSummaryText(p){
  if(!p) return '';
  if(p.error) return 'Error: ' + p.error;
  if(p.note) return p.note;
  if(p.name && /virus/i.test(p.name)){
    const stats = p.analysis?.data?.attributes?.stats || p.raw?.data?.attributes?.last_analysis_stats;
    if(stats) return `malicious:${stats.malicious||0} suspicious:${stats.suspicious||0} undetected:${stats.undetected||0}`;
  }
  if(p.name && /urlscan/i.test(p.name)){
    if(p.result?.page?.title) return p.result.page.title;
    if(p.raw?.task?.url) return p.raw.task.url;
  }
  if(p.raw && typeof p.raw === 'string') return p.raw.slice(0,200);
  if(p.raw && p.raw.message) return p.raw.message;
  return '';
}

// Generic fetch wrapper
async function postJSON(path, body){
  const url = WORKER_BASE + path;
  const resp = await fetch(url, {
    method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify(body)
  });
  if(!resp.ok) throw new Error('HTTP '+resp.status+' '+resp.statusText);
  return resp.json();
}

/* ----------------------
   Single URL scan flow
   ---------------------- */
$('check-url').addEventListener('click', async () => {
  const rawUrl = $('url-input').value.trim();
  if(!rawUrl) return alert('Enter a URL');
  let url = rawUrl;
  if(!/^https?:\/\//i.test(url)) url = 'http://' + url;

  // UI reset
  $('results-url').innerHTML = '';
  $('combined-fill').style.width = '0%';
  $('combined-percent').textContent = '—';
  $('raw-output').textContent = '';

  try {
    // call worker
    const j = await postJSON('/api/check/url', { url });

    // group providers by feature and render only URL-relevant providers
    const providers = j.providers || [];
    renderProviders($('results-url'), providers, 'url');

    // combined score
    const percent = scoreFromProviders(providers);
    $('combined-fill').style.width = percent + '%';
    $('combined-percent').textContent = percent + '%';

    // also place raw output in debug
    $('raw-output').textContent = JSON.stringify({ queried: j.queried, providers }, null, 2);

  } catch (err) {
    console.error(err);
    $('results-url').innerHTML = '<div class="provider"><div>Error contacting worker</div><div class="meta">'+escapeHtml(String(err))+'</div></div>';
  }
});

/* ----------------------
   Bulk CSV scanning
   ---------------------- */
$('sample-csv').addEventListener('click', (e) => {
  // provide a sample CSV payload
  const sample = `https://example.com\nhttps://www.amtso.org/check-phishing-page/\npaypal.com.secure-login-update.verify-account.info\n`;
  const blob = new Blob([sample], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  $('sample-csv').href = url;
  setTimeout(()=> URL.revokeObjectURL(url), 20000);
});

function parseCSVLines(text){
  return text.split(/\r?\n/).map(l => l.trim()).filter(l => l.length>0);
}

$('bulk-start').addEventListener('click', async () => {
  const file = $('csv-file').files?.[0];
  if(!file) return alert('Select a CSV or click "Download sample.csv" to get a template.');
  const text = await file.text();
  const lines = parseCSVLines(text);
  if(lines.length===0) return alert('CSV is empty.');

  $('bulk-results').innerHTML = '';
  $('bulk-progress').classList.remove('hidden');
  $('download-results').classList.add('hidden');

  const results = [];
  for(let i=0;i<lines.length;i++){
    const rawUrl = lines[i];
    let url = rawUrl;
    if(!/^https?:\/\//i.test(url)) url = 'http://' + url;

    $('bulk-status').textContent = `Checking ${i+1}/${lines.length} — ${url}`;
    $('bulk-bar').style.width = Math.round(((i+1)/lines.length)*100)+'%';

    try {
      const j = await postJSON('/api/check/url', { url });
      const providers = j.providers || [];
      const verdict = (() => {
        const p = providers.map(inferVerdict);
        if(p.includes('malicious')) return 'malicious';
        if(p.includes('suspicious')) return 'suspicious';
        return 'safe';
      })();
      results.push({ url, verdict, providers });

      const li = document.createElement('li');
      li.innerHTML = `<div>${escapeHtml(url)}</div><div><span class="badge ${verdict}">${verdict}</span> <button class="btn raw-btn">Raw</button></div>`;
      li.querySelector('.raw-btn').addEventListener('click', ()=> { $('raw-output').textContent = JSON.stringify(j, null, 2); document.querySelector('[data-tab="tab-raw"]').click(); });
      $('bulk-results').appendChild(li);

    } catch (err) {
      const li = document.createElement('li');
      li.innerHTML = `<div>${escapeHtml(url)}</div><div><span class="badge suspicious">error</span></div>`;
      $('bulk-results').appendChild(li);
      results.push({ url, verdict:'error', error:String(err) });
    }
  }

  $('bulk-status').textContent = `Finished ${lines.length} URLs`;
  $('download-results').classList.remove('hidden');

  $('download-results').onclick = () => {
    const csv = results.map(r => `"${r.url}","${r.verdict}"`).join('\n');
    const blob = new Blob([csv], { type:'text/csv' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'pd_results.csv'; a.click();
    URL.revokeObjectURL(a.href);
  };
});

/* ----------------------
   Email scan (domain checks via DNS DoH + OTX if available)
   ---------------------- */
$('check-email').addEventListener('click', async () => {
  const email = $('email-input').value.trim();
  if(!email || !/@/.test(email)) return alert('Enter a valid email');
  const domain = email.split('@')[1];

  $('results-email').innerHTML = '';
  $('raw-output').textContent = '';

  try {
    const j = await postJSON('/api/check/email', { email });
    // show only email-relevant providers
    renderProviders($('results-email'), j.providers || [], 'email');
    $('raw-output').textContent = JSON.stringify(j, null, 2);
  } catch (err) {
    $('results-email').innerHTML = `<div class="provider"><div>Error</div><div class="meta">${escapeHtml(String(err))}</div></div>`;
  }
});

/* ----------------------
   OCR Image upload and scanning
   ---------------------- */
const OCR_MAX_BYTES = 2 * 1024 * 1024; // 2MB

$('ocr-run').addEventListener('click', async () => {
  const file = $('ocr-file').files?.[0];
  if(!file) return alert('Choose an image first');
  if(file.size > OCR_MAX_BYTES) return alert('Image too large (max 2 MB)');

  $('ocr-output').innerHTML = `<div class="provider"><div>Running OCR…</div></div>`;
  try {
    // Run Tesseract in-browser
    const { data: { text } } = await Tesseract.recognize(file, 'eng', { logger: m => {/* optional logs */} });
    const found = Array.from(new Set((text.match(/https?:\/\/[^\s)'"<>]+/ig)||[])));
    $('ocr-output').innerHTML = `<div class="provider"><div>OCR extracted ${found.length} URLs</div></div>`;
    if(found.length===0) return;

    // For each extracted URL, call the worker
    const providersContainer = document.createElement('div');
    providersContainer.className = 'results';
    $('ocr-output').appendChild(providersContainer);

    for(const u of found){
      const j = await postJSON('/api/check/url', { url: u });
      const box = document.createElement('div');
      box.className = 'provider';
      const verdict = (() => { const v = (j.providers||[]).map(inferVerdict); if(v.includes('malicious')) return 'malicious'; if(v.includes('suspicious')) return 'suspicious'; return 'safe'; })();
      box.innerHTML = `<div><strong>${escapeHtml(u)}</strong><div class="meta">OCR found link</div></div><div><span class="badge ${verdict}">${verdict}</span><button class="btn raw-btn">Raw</button></div>`;
      box.querySelector('.raw-btn').addEventListener('click', ()=> { $('raw-output').textContent = JSON.stringify(j, null, 2); document.querySelector('[data-tab="tab-raw"]').click();});
      providersContainer.appendChild(box);
    }

  } catch (err) {
    $('ocr-output').innerHTML = `<div class="provider"><div>Error</div><div class="meta">${escapeHtml(String(err))}</div></div>`;
  }
});

/* ----------------------
   Key status / debug
   ---------------------- */
$('key-status').addEventListener('click', async () => {
  $('raw-output').textContent = 'Querying worker…';
  try {
    const resp = await fetch(WORKER_BASE + '/api/key-status');
    if(!resp.ok) throw new Error('HTTP '+resp.status);
    const j = await resp.json();
    $('raw-output').textContent = JSON.stringify(j, null, 2);
  } catch (err) {
    $('raw-output').textContent = String(err);
  }
});
