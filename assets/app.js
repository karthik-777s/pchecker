/* Frontend for Phish Defender recon console
 * Set WORKER_BASE to your Cloudflare Worker URL (no trailing slash)
 * Example: https://phish-defender-api.yourname.workers.dev
 */
const WORKER_BASE = 'https://phish-checker-api.phisher.workers.dev';

// DOM helpers
const $ = id => document.getElementById(id);
const qs = sel => document.querySelector(sel);

// Theme toggle
const themeToggle = $('theme-toggle');
function loadTheme(){
  const t = localStorage.getItem('pd_theme') || 'dark';
  document.body.classList.toggle('theme-light', t === 'light');
}
themeToggle.addEventListener('click', () => {
  const isLight = document.body.classList.toggle('theme-light');
  localStorage.setItem('pd_theme', isLight ? 'light' : 'dark');
});
loadTheme();

// Tabs
document.querySelectorAll('.tab').forEach(b => {
  b.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    const tab = b.dataset.tab;
    document.querySelectorAll('.panel').forEach(p => {
      if (p.id && p.id.startsWith('tab-')) {
        p.classList.add('hidden');
      }
    });
    $(tab).classList.remove('hidden');
  });
});

// ---------- Shared helpers ----------

async function postJSON(path, body){
  const res = await fetch(WORKER_BASE + path, {
    method:'POST',
    headers:{ 'Content-Type':'application/json' },
    body: JSON.stringify(body || {})
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch(e){ json = { raw:text, parseError:String(e) }; }
  if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + res.statusText);
  return json;
}

// Very lightweight verdict inference using simple keyword heuristics.
// This is intentionally conservative and just for scoring / badges.
function inferVerdict(provider){
  const name = provider.name || '';
  if (provider.ok === false && provider.error) return 'error';

  const payload = JSON.stringify(provider.raw || provider.analysis || provider.result || provider).toLowerCase();

  let maliciousHits = 0;
  let suspiciousHits = 0;

  if (payload.includes('malicious') || payload.includes('"phishing"') || payload.includes('malware')) maliciousHits++;
  if (payload.includes('suspicious') || payload.includes('grayware') || payload.includes('unknown')) suspiciousHits++;

  if (maliciousHits > 0) return 'malicious';
  if (suspiciousHits > 0) return 'suspicious';

  // Some feeds encode severity numerically; basic hinting
  if (payload.includes('"high"') || payload.includes('"critical"')) return 'suspicious';

  return 'safe';
}

// Combined score: average weight of all non-error providers.
function updateCombinedScore(providers){
  if (!providers || !providers.length){
    $('combined-fill').style.width = '0%';
    $('combined-percent').textContent = 'No data';
    return;
  }
  let scores = [];
  for (const p of providers){
    const v = inferVerdict(p);
    if (v === 'error') continue;
    if (v === 'malicious') scores.push(95);
    else if (v === 'suspicious') scores.push(60);
    else scores.push(10);
  }
  if (!scores.length){
    $('combined-fill').style.width = '0%';
    $('combined-percent').textContent = 'No reliable providers';
    return;
  }
  const avg = Math.round(scores.reduce((a,b)=>a+b,0) / scores.length);
  $('combined-fill').style.width = avg + '%';
  let label = 'Low risk';
  if (avg >= 66) label = 'High risk';
  else if (avg >= 31) label = 'Suspicious';
  $('combined-percent').textContent = `Final risk score: ${avg}% (${label})`;
}

// Render providers into a container, filtering by feature.
function renderProviders(container, providers, feature){
  container.innerHTML = '';

  const featureMap = {
    url: ['VirusTotal','urlscan.io','URLHaus','AlienVault OTX','AbuseIPDB','Filescan.io','MalShare'],
    bulk: ['VirusTotal','URLHaus','AlienVault OTX','Filescan.io','MalShare'],
    email: ['DNS TXT (DoH)','AlienVault OTX'],
    file: ['VirusTotal','Filescan.io','MalShare']
  };

  const allowed = feature ? (featureMap[feature] || []) : null;

  const filtered = allowed
    ? providers.filter(p => allowed.includes(p.name || ''))
    : providers.slice();

  filtered.forEach(p => {
    const div = document.createElement('div');
    div.className = 'provider';

    const verdict = inferVerdict(p);
    const badge = document.createElement('span');
    badge.classList.add('badge');
    if (verdict === 'safe') badge.classList.add('safe');
    else if (verdict === 'suspicious') badge.classList.add('suspicious');
    else if (verdict === 'malicious') badge.classList.add('malicious');
    else badge.classList.add('error');

    badge.textContent =
      verdict === 'safe' ? 'SAFE' :
      verdict === 'suspicious' ? 'SUSPICIOUS' :
      verdict === 'malicious' ? 'MALICIOUS' :
      'ERROR';

    const meta = document.createElement('div');
    meta.className = 'meta';
    const extra = p.note || p.error || '';
    meta.innerHTML = `
      <div class="provider-name">${p.name || 'Unknown provider'}</div>
      <div class="provider-extra">${extra || (p.ok === false ? 'No signal / not configured' : 'OK')}</div>
    `;

    div.appendChild(meta);
    div.appendChild(badge);
    container.appendChild(div);
  });

  updateCombinedScore(filtered.length ? filtered : providers);
}

// Basic CSV parser for small, simple CSV files.
function parseCsv(text){
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (!lines.length) return [];
  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const urlIdx = headers.indexOf('url');
  const labelIdx = headers.indexOf('label');
  if (urlIdx === -1) throw new Error('CSV must contain a "url" header in the first row');

  return lines.slice(1).map(line => {
    const cols = line.split(',');
    if (!cols[urlIdx]) return null;
    return {
      url: cols[urlIdx].trim(),
      label: labelIdx >= 0 ? (cols[labelIdx] || '').trim() : ''
    };
  }).filter(Boolean);
}

function downloadCsv(filename, rows, headers){
  if (!rows || !rows.length) return;
  const head = headers.join(',');
  const body = rows.map(r => headers.map(h => {
    const val = (r[h] ?? '').toString().replace(/"/g,'""');
    if (/[",\n]/.test(val)) return `"${val}"`;
    return val;
  }).join(',')).join('\n');
  const blob = new Blob([head + '\n' + body], { type:'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// Hash file with SHA-256 using Web Crypto.
async function hashFileSha256(file){
  const buf = await file.arrayBuffer();
  const hash = await crypto.subtle.digest('SHA-256', buf);
  const bytes = Array.from(new Uint8Array(hash));
  return bytes.map(b => b.toString(16).padStart(2,'0')).join('');
}

// ---------- Single URL scan ----------

let lastUrlProviders = [];
let lastBulkRows = [];
let lastEmailProviders = [];

const urlInput = $('url-input');
const btnUrlScan = $('btn-url-scan');
const urlProvidersEl = $('url-providers');
const btnUrlDownload = $('btn-url-download');
const rawOutput = $('raw-output');

btnUrlScan.addEventListener('click', async () => {
  const target = urlInput.value.trim();
  if (!target) return;

  btnUrlScan.disabled = true;
  btnUrlScan.textContent = 'Scanning…';

  try {
    const data = await postJSON('/api/check/url', { url: target });
    lastUrlProviders = data.providers || [];
    renderProviders(urlProvidersEl, lastUrlProviders, 'url');

    rawOutput.textContent = JSON.stringify(data, null, 2);
    rawOutput.classList.remove('hidden');

    btnUrlDownload.disabled = !lastUrlProviders.length;
  } catch (e){
    urlProvidersEl.innerHTML = `<div class="small-note">Error: ${e.message}</div>`;
  } finally {
    btnUrlScan.disabled = false;
    btnUrlScan.textContent = 'Scan URL';
  }
});

btnUrlDownload.addEventListener('click', () => {
  if (!lastUrlProviders.length) return;
  const rows = lastUrlProviders.map(p => ({
    provider: p.name || '',
    verdict: inferVerdict(p),
    ok: String(p.ok),
    note: p.note || p.error || ''
  }));
  downloadCsv('url_scan_results.csv', rows, ['provider','verdict','ok','note']);
});

// ---------- Bulk CSV scan ----------

const bulkFileInput = $('bulk-file');
const btnBulkScan = $('btn-bulk-scan');
const bulkBar = $('bulk-bar');
const bulkPercent = $('bulk-percent');
const bulkResultsEl = $('bulk-results');
const btnBulkDownload = $('btn-bulk-download');

btnBulkScan.addEventListener('click', async () => {
  const file = bulkFileInput.files && bulkFileInput.files[0];
  if (!file) return;

  btnBulkScan.disabled = true;
  btnBulkScan.textContent = 'Parsing…';
  bulkResultsEl.innerHTML = '';
  bulkBar.style.width = '0%';
  bulkPercent.textContent = '0%';
  lastBulkRows = [];

  try {
    const text = await file.text();
    const rows = parseCsv(text);
    if (!rows.length) throw new Error('No URLs found in CSV');

    const total = rows.length;
    let completed = 0;

    for (const row of rows){
      completed++;
      const pct = Math.round((completed / total) * 100);
      bulkBar.style.width = pct + '%';
      bulkPercent.textContent = pct + '%';

      let li = document.createElement('li');
      li.textContent = `[Pending] ${row.url}`;
      bulkResultsEl.appendChild(li);

      try {
        const data = await postJSON('/api/check/url', { url: row.url });
        const providers = data.providers || [];
        const vList = providers
          .filter(p => p.ok !== false)
          .map(p => inferVerdict(p));
        const worst =
          vList.includes('malicious') ? 'malicious' :
          vList.includes('suspicious') ? 'suspicious' :
          'safe';

        li.textContent = `${row.url} — ${worst.toUpperCase()}${row.label ? ' ('+row.label+')' : ''}`;

        lastBulkRows.push({
          url: row.url,
          label: row.label || '',
          verdict: worst
        });
      } catch (e){
        li.textContent = `${row.url} — ERROR: ${e.message}`;
      }
    }

    btnBulkDownload.disabled = !lastBulkRows.length;
    // The combined bar is updated from the last response implicitly through renderProviders;
    // for bulk we keep combined as-is from URL/email scans.
  } catch (e){
    bulkResultsEl.innerHTML = `<li class="small-note">Error: ${e.message}</li>`;
  } finally {
    btnBulkScan.disabled = false;
    btnBulkScan.textContent = 'Scan CSV';
  }
});

btnBulkDownload.addEventListener('click', () => {
  if (!lastBulkRows.length) return;
  downloadCsv('bulk_url_results.csv', lastBulkRows, ['url','label','verdict']);
});

// ---------- Email domain & OCR hash ----------

const emailInput = $('email-input');
const btnEmailScan = $('btn-email-scan');
const emailBar = $('email-bar');
const emailStatus = $('email-status');
const emailProvidersEl = $('email-providers');
const btnEmailDownload = $('btn-email-download');

const ocrFileInput = $('ocr-file');
const btnOcrScan = $('btn-ocr-scan');

btnEmailScan.addEventListener('click', async () => {
  const email = emailInput.value.trim();
  if (!email) return;

  btnEmailScan.disabled = true;
  btnEmailScan.textContent = 'Scanning…';
  emailBar.style.width = '25%';
  emailStatus.textContent = 'Querying DNS / OTX…';

  try {
    const data = await postJSON('/api/check/email', { email });
    lastEmailProviders = data.providers || [];
    renderProviders(emailProvidersEl, lastEmailProviders, 'email');

    rawOutput.textContent = JSON.stringify(data, null, 2);
    rawOutput.classList.remove('hidden');

    emailBar.style.width = '100%';
    emailStatus.textContent = 'Completed';
    btnEmailDownload.disabled = !lastEmailProviders.length;
  } catch (e){
    emailProvidersEl.innerHTML = `<div class="small-note">Error: ${e.message}</div>`;
    emailStatus.textContent = 'Error';
  } finally {
    btnEmailScan.disabled = false;
    btnEmailScan.textContent = 'Scan email domain';
    setTimeout(() => { emailBar.style.width = '0%'; }, 1500);
  }
});

btnOcrScan.addEventListener('click', async () => {
  const file = ocrFileInput.files && ocrFileInput.files[0];
  if (!file) return;

  // Enforce size limit ~5MB
  if (file.size > 5 * 1024 * 1024){
    emailStatus.textContent = 'File too large (max 5MB)';
    return;
  }

  btnOcrScan.disabled = true;
  btnOcrScan.textContent = 'Hashing…';
  emailBar.style.width = '30%';
  emailStatus.textContent = 'Hashing attachment (SHA-256)…';

  try {
    const sha256 = await hashFileSha256(file);
    emailBar.style.width = '60%';
    emailStatus.textContent = 'Querying file hash feeds…';

    const data = await postJSON('/api/check/image', { sha256 });
    const providers = data.providers || [];

    // Merge into email providers section but filtered as file
    renderProviders(emailProvidersEl, providers, 'file');

    rawOutput.textContent = JSON.stringify(data, null, 2);
    rawOutput.classList.remove('hidden');

    emailBar.style.width = '100%';
    emailStatus.textContent = 'Completed';
    lastEmailProviders = providers;
    btnEmailDownload.disabled = !lastEmailProviders.length;
  } catch (e){
    emailProvidersEl.innerHTML = `<div class="small-note">Error: ${e.message}</div>`;
    emailStatus.textContent = 'Error';
  } finally {
    btnOcrScan.disabled = false;
    btnOcrScan.textContent = 'Scan attachment hash (OCR feed)';
    setTimeout(() => { emailBar.style.width = '0%'; }, 1500);
  }
});

btnEmailDownload.addEventListener('click', () => {
  if (!lastEmailProviders.length) return;
  const rows = lastEmailProviders.map(p => ({
    provider: p.name || '',
    verdict: inferVerdict(p),
    ok: String(p.ok),
    note: p.note || p.error || ''
  }));
  downloadCsv('email_ocr_results.csv', rows, ['provider','verdict','ok','note']);
});
