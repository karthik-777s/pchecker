/* Phish Defender frontend
 * Set WORKER_BASE to your Cloudflare Worker URL (no trailing slash)
 * Example: https://phish-defender-api.yourname.workers.dev
 */
const WORKER_BASE = 'https://phish-checker-api.phisher.workers.dev';

// ---------- Tiny DOM helpers ----------
const $  = id  => document.getElementById(id);
const qs = sel => document.querySelector(sel);

// Run after DOM is ready to avoid null elements
document.addEventListener('DOMContentLoaded', () => {

  // =========================
  // Theme toggle
  // =========================
  const themeToggle = $('theme-toggle');

  function loadTheme(){
    const t = localStorage.getItem('pd_theme') || 'dark';
    document.body.classList.toggle('theme-light', t === 'light');
  }

  if (themeToggle){
    themeToggle.addEventListener('click', () => {
      const isLight = document.body.classList.toggle('theme-light');
      localStorage.setItem('pd_theme', isLight ? 'light' : 'dark');
    });
  }

  loadTheme();

  // =========================
  // Tabs
  // =========================
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
      btn.classList.add('active');

      const targetId = btn.dataset.tab; // e.g. tab-url
      document.querySelectorAll('.panel').forEach(p => {
        if (p.id && p.id.startsWith('tab-')){
          p.classList.add('hidden');
        }
      });
      const panel = $(targetId);
      if (panel) panel.classList.remove('hidden');
    });
  });

  // =========================
  // Shared helpers
  // =========================

  async function postJSON(path, body){
    const res = await fetch(WORKER_BASE + path, {
      method:'POST',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify(body || {})
    }); // standard fetch POST JSON usage [web:113][web:114]
    const text = await res.text();
    let json;
    try { json = text ? JSON.parse(text) : null; }
    catch(e){ json = { raw:text, parseError:String(e) }; }
    if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + res.statusText);
    return json;
  }

  // Very lightweight verdict inference from provider payload
  function inferVerdict(provider){
    if (!provider) return 'safe';
    if (provider.ok === false && provider.error) return 'error';

    const payload = JSON.stringify(
      provider.raw || provider.analysis || provider.result || provider
    ).toLowerCase();

    let maliciousHits = 0;
    let suspiciousHits = 0;

    if (payload.includes('malicious') || payload.includes('"phishing"') || payload.includes('malware'))
      maliciousHits++;
    if (payload.includes('suspicious') || payload.includes('grayware') || payload.includes('unknown'))
      suspiciousHits++;

    if (maliciousHits > 0) return 'malicious';
    if (suspiciousHits > 0) return 'suspicious';
    if (payload.includes('"high"') || payload.includes('"critical"')) return 'suspicious';

    return 'safe';
  }

  // Combined risk score from providers
  function updateCombinedScore(providers){
    const fill = $('combined-fill');
    const label = $('combined-percent');
    if (!fill || !label) return;

    if (!providers || !providers.length){
      fill.style.width = '0%';
      label.textContent = 'No data';
      return;
    }

    const scores = [];
    for (const p of providers){
      const v = inferVerdict(p);
      if (v === 'error') continue;
      if (v === 'malicious') scores.push(95);
      else if (v === 'suspicious') scores.push(60);
      else scores.push(10);
    }
    if (!scores.length){
      fill.style.width = '0%';
      label.textContent = 'No reliable providers';
      return;
    }
    const avg = Math.round(scores.reduce((a,b)=>a+b,0) / scores.length);
    fill.style.width = avg + '%';

    let bucket = 'Low risk';
    if (avg >= 66) bucket = 'High risk';
    else if (avg >= 31) bucket = 'Suspicious';

    label.textContent = `Final risk score: ${avg}% (${bucket})`;
  }

  // Feature‑specific provider filtering
  function renderProviders(container, providers, feature){
    if (!container){
      updateCombinedScore(providers || []);
      return;
    }
    container.innerHTML = '';

    const featureMap = {
      url:   ['VirusTotal','urlscan.io','URLHaus','AlienVault OTX','AbuseIPDB','Filescan.io','MalShare'],
      bulk:  ['VirusTotal','URLHaus','AlienVault OTX','Filescan.io','MalShare'],
      email: ['DNS TXT (DoH)','AlienVault OTX'],
      file:  ['VirusTotal','Filescan.io','MalShare']
    };

    const allowed = feature ? (featureMap[feature] || []) : null;
    const filtered = allowed
      ? (providers || []).filter(p => allowed.includes(p.name || ''))
      : (providers || []);

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

    updateCombinedScore(filtered.length ? filtered : providers || []);
  }

  // Simple CSV parsing for bulk upload
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
      return /[",\n]/.test(val) ? `"${val}"` : val;
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

  // Hash file with SHA‑256 using Web Crypto API
  async function hashFileSha256(file){
    const buf = await file.arrayBuffer();
    const hash = await crypto.subtle.digest('SHA-256', buf);
    const bytes = Array.from(new Uint8Array(hash));
    return bytes.map(b => b.toString(16).padStart(2,'0')).join('');
  }

  // =========================
  // Single URL scan
  // =========================

  let lastUrlProviders = [];
  let lastBulkRows = [];
  let lastEmailProviders = [];

  const urlInput       = $('url-input');
  const btnUrlScan     = $('btn-url-scan');
  const urlProvidersEl = $('url-providers');
  const btnUrlDownload = $('btn-url-download');

  if (btnUrlScan){
    btnUrlScan.addEventListener('click', async () => {
      const target = urlInput ? urlInput.value.trim() : '';
      if (!target) return;

      btnUrlScan.disabled = true;
      btnUrlScan.textContent = 'Scanning…';

      try {
        const data = await postJSON('/api/check/url', { url: target });
        lastUrlProviders = data.providers || [];
        renderProviders(urlProvidersEl, lastUrlProviders, 'url');
        btnUrlDownload.disabled = !lastUrlProviders.length;
      } catch (e){
        if (urlProvidersEl){
          urlProvidersEl.innerHTML = `<div class="small-note">Error: ${e.message}</div>`;
        }
      } finally {
        btnUrlScan.disabled = false;
        btnUrlScan.textContent = 'Scan URL';
      }
    });
  }

  if (btnUrlDownload){
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
  }

  // =========================
  // Bulk CSV scan
  // =========================

  const bulkFileInput  = $('bulk-file');
  const btnBulkScan    = $('btn-bulk-scan');
  const bulkBar        = $('bulk-bar');
  const bulkPercent    = $('bulk-percent');
  const bulkResultsEl  = $('bulk-results');
  const btnBulkDownload= $('btn-bulk-download');

  if (btnBulkScan){
    btnBulkScan.addEventListener('click', async () => {
      const file = bulkFileInput && bulkFileInput.files && bulkFileInput.files[0];
      if (!file) return;

      btnBulkScan.disabled = true;
      btnBulkScan.textContent = 'Parsing…';
      if (bulkResultsEl) bulkResultsEl.innerHTML = '';
      if (bulkBar) bulkBar.style.width = '0%';
      if (bulkPercent) bulkPercent.textContent = '0%';
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
          if (bulkBar) bulkBar.style.width = pct + '%';
          if (bulkPercent) bulkPercent.textContent = pct + '%';

          let li = document.createElement('li');
          li.textContent = `[Pending] ${row.url}`;
          if (bulkResultsEl) bulkResultsEl.appendChild(li);

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
        // combined score is left from last single/email scan
      } catch (e){
        if (bulkResultsEl){
          bulkResultsEl.innerHTML = `<li class="small-note">Error: ${e.message}</li>`;
        }
      } finally {
        btnBulkScan.disabled = false;
        btnBulkScan.textContent = 'Scan CSV';
      }
    });
  }

  if (btnBulkDownload){
    btnBulkDownload.addEventListener('click', () => {
      if (!lastBulkRows.length) return;
      downloadCsv('bulk_url_results.csv', lastBulkRows, ['url','label','verdict']);
    });
  }

  // =========================
  // Email domain & OCR hash
  // =========================

  const emailInput       = $('email-input');
  const btnEmailScan     = $('btn-email-scan');
  const emailBar         = $('email-bar');
  const emailStatus      = $('email-status');
  const emailProvidersEl = $('email-providers');
  const btnEmailDownload = $('btn-email-download');

  const ocrFileInput     = $('ocr-file');
  const btnOcrScan       = $('btn-ocr-scan');

  if (btnEmailScan){
    btnEmailScan.addEventListener('click', async () => {
      const email = emailInput ? emailInput.value.trim() : '';
      if (!email) return;

      btnEmailScan.disabled = true;
      btnEmailScan.textContent = 'Scanning…';
      if (emailBar) emailBar.style.width = '25%';
      if (emailStatus) emailStatus.textContent = 'Querying DNS / OTX…';

      try {
        const data = await postJSON('/api/check/email', { email });
        lastEmailProviders = data.providers || [];
        renderProviders(emailProvidersEl, lastEmailProviders, 'email');

        if (emailBar) emailBar.style.width = '100%';
        if (emailStatus) emailStatus.textContent = 'Completed';
        btnEmailDownload.disabled = !lastEmailProviders.length;
      } catch (e){
        if (emailProvidersEl){
          emailProvidersEl.innerHTML = `<div class="small-note">Error: ${e.message}</div>`;
        }
        if (emailStatus) emailStatus.textContent = 'Error';
      } finally {
        btnEmailScan.disabled = false;
        btnEmailScan.textContent = 'Scan email domain';
        if (emailBar){
          setTimeout(() => { emailBar.style.width = '0%'; }, 1500);
        }
      }
    });
  }

  if (btnOcrScan){
    btnOcrScan.addEventListener('click', async () => {
      const file = ocrFileInput && ocrFileInput.files && ocrFileInput.files[0];
      if (!file) return;

      if (file.size > 5 * 1024 * 1024){
        if (emailStatus) emailStatus.textContent = 'File too large (max 5MB)';
        return;
      }

      btnOcrScan.disabled = true;
      btnOcrScan.textContent = 'Hashing…';
      if (emailBar) emailBar.style.width = '30%';
      if (emailStatus) emailStatus.textContent = 'Hashing attachment (SHA-256)…';

      try {
        const sha256 = await hashFileSha256(file);
        if (emailBar) emailBar.style.width = '60%';
        if (emailStatus) emailStatus.textContent = 'Querying file hash feeds…';

        const data = await postJSON('/api/check/image', { sha256 });
        const providers = data.providers || [];

        renderProviders(emailProvidersEl, providers, 'file');

        if (emailBar) emailBar.style.width = '100%';
        if (emailStatus) emailStatus.textContent = 'Completed';
        lastEmailProviders = providers;
        btnEmailDownload.disabled = !lastEmailProviders.length;
      } catch (e){
        if (emailProvidersEl){
          emailProvidersEl.innerHTML = `<div class="small-note">Error: ${e.message}</div>`;
        }
        if (emailStatus) emailStatus.textContent = 'Error';
      } finally {
        btnOcrScan.disabled = false;
        btnOcrScan.textContent = 'Scan attachment hash (OCR feed)';
        if (emailBar){
          setTimeout(() => { emailBar.style.width = '0%'; }, 1500);
        }
      }
    });
  }

  if (btnEmailDownload){
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
  }

}); // end DOMContentLoaded
