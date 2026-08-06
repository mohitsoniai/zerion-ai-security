// popup.js - Handles Zerion UI Interactions
const API_URL = 'https://zerion-ai-security-api.onrender.com';
const ZERION_API_KEY = 'zerion_secret_key_v2';
let activeScanData = null;

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initialize Tabs
  document.getElementById('tab-scan').addEventListener('click', () => switchTab('scan'));
  document.getElementById('tab-history').addEventListener('click', () => switchTab('history'));
  document.getElementById('tab-controls').addEventListener('click', () => switchTab('controls'));

  // 2. Load Data on Startup
  requestScan();
  loadHistory();

  // Load Auto-Scan state
  chrome.storage.local.get({ autoScan: true }, (data) => {
    const checkbox = document.getElementById('toggle-autoscan');
    if (checkbox) checkbox.checked = data.autoScan;
  });

  // Load Dark/Light mode theme
  chrome.storage.local.get({ darkMode: true }, (data) => {
    const checkbox = document.getElementById('toggle-darkmode');
    if (checkbox) checkbox.checked = data.darkMode;
    if (!data.darkMode) {
      document.body.classList.add('light-mode');
    }
  });

  const toggleDarkmode = document.getElementById('toggle-darkmode');
  if (toggleDarkmode) {
    toggleDarkmode.addEventListener('change', (e) => {
      chrome.storage.local.set({ darkMode: e.target.checked }, () => {
        if (e.target.checked) {
          document.body.classList.remove('light-mode');
        } else {
          document.body.classList.add('light-mode');
        }
      });
    });
  }

  // Security Report Drawer Listeners
  const reportDrawer = document.getElementById('report-drawer');
  const viewReportBtn = document.getElementById('view-report-btn');
  const closeReportBtn = document.getElementById('close-report-btn');

  if (viewReportBtn && reportDrawer) {
    viewReportBtn.addEventListener('click', () => {
      if (activeScanData) {
        populateReportDrawer(activeScanData);
        reportDrawer.classList.add('open');
      }
    });
  }

  if (closeReportBtn && reportDrawer) {
    closeReportBtn.addEventListener('click', () => {
      reportDrawer.classList.remove('open');
    });
  }

  // Populate Domain for Quick Report
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.url) {
      try {
        const domain = new URL(tabs[0].url).hostname;
        const reportInput = document.getElementById('report-domain-input');
        if (reportInput) reportInput.value = domain;
      } catch (e) {
        console.debug('Failed to extract domain', e);
      }
    }
  });

  // Toggle Auto-Scan Switch
  const toggleAutoscan = document.getElementById('toggle-autoscan');
  if (toggleAutoscan) {
    toggleAutoscan.addEventListener('change', (e) => {
      chrome.storage.local.set({ autoScan: e.target.checked });
    });
  }

  // Settings Drawer toggle
  const openDrawerBtn = document.getElementById('open-drawer-btn');
  const closeDrawerBtn = document.getElementById('close-drawer-btn');
  const drawer = document.getElementById('settings-drawer');
  
  if (openDrawerBtn && closeDrawerBtn && drawer) {
    openDrawerBtn.addEventListener('click', () => drawer.classList.add('open'));
    closeDrawerBtn.addEventListener('click', () => drawer.classList.remove('open'));
  }

  // Quick Threat Report Submission
  const btnReport = document.getElementById('btn-submit-report');
  if (btnReport) {
    btnReport.addEventListener('click', () => {
      const domain = document.getElementById('report-domain-input').value;
      const type = document.getElementById('report-type').value;
      const comment = document.getElementById('report-comment').value;
      const status = document.getElementById('report-status');

      if (!domain) {
        if (status) {
          status.style.color = '#ff003c';
          status.innerText = 'No domain to report.';
        }
        return;
      }

      if (status) {
        status.style.color = '#888';
        status.innerText = 'Submitting report...';
      }

      fetch(`${API_URL}/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-ZERION-API-KEY': ZERION_API_KEY
        },
        body: JSON.stringify({ domain: domain, report_type: type, comment: comment })
      })
      .then(res => res.json())
      .then(() => {
        if (status) {
          status.style.color = '#00ff66';
          status.innerText = '🚀 Report submitted successfully!';
        }
        document.getElementById('report-comment').value = '';
        setTimeout(() => {
          if (status) status.innerText = '';
        }, 3000);
      })
      .catch(() => {
        if (status) {
          status.style.color = '#ff003c';
          status.innerText = '❌ Submission failed.';
        }
      });
    });
  }

  // 3. Re-Scan Button
  document.getElementById('scan-btn').addEventListener('click', requestScan);

  // Trust Domain Button
  const btnTrust = document.getElementById('trust-domain-btn');
  if (btnTrust) {
    btnTrust.addEventListener('click', () => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.url) {
          try {
            const domain = new URL(tabs[0].url).hostname;
            chrome.storage.local.get({ userTrust: {} }, (result) => {
              let trust = result.userTrust;
              trust[domain] = 2;
              chrome.storage.local.set({ userTrust: trust }, () => {
                btnTrust.innerText = '✅ SITE TRUSTED';
                setTimeout(() => {
                  btnTrust.innerText = '✅ TRUST ACTIVE DOMAIN';
                }, 2000);
              });
            });
          } catch (e) {
            console.debug('Failed to trust site', e);
          }
        }
      });
    });
  }

  // 4. Clear Visual Logs Only
  document.getElementById('clear-history').addEventListener('click', () => {
    document.getElementById('history-list').innerHTML =
      "<div style='text-align:center; color:#555;'>Logs cleared.</div>";
  });

  // 5. OPEN DASHBOARD BUTTON
  document.getElementById('open-dashboard').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
  });

  // 6. RESET MEMORY BUTTON
  document.getElementById('btn-reset').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'RESET_MEMORY' }, (response) => {
      if (response && response.success) {
        const btn = document.getElementById('btn-reset');
        btn.innerText = '✅ MEMORY WIPED';
        btn.style.borderColor = '#00ff00';
        btn.style.color = '#00ff00';

        setTimeout(() => {
          loadHistory();
          btn.innerText = '⚠️ RESET TRUST EXCLUSIONS';
          btn.style.borderColor = '#ff003c';
          btn.style.color = '#ff003c';
        }, 2000);
      }
    });
  });
});

// --- UI HELPERS ---

function switchTab(viewName) {
  document.querySelectorAll('.view').forEach((el) => el.classList.remove('active'));
  document.querySelectorAll('.tab').forEach((el) => el.classList.remove('active'));

  document.getElementById(`view-${viewName}`).classList.add('active');
  document.getElementById(`tab-${viewName}`).classList.add('active');

  if (viewName === 'history') loadHistory();
}

function requestScan() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.url) {
      // Toggle skeleton loading
      document.getElementById('scan-real-data').style.display = 'none';
      document.getElementById('scan-skeleton').style.display = 'flex';
      
      const hostname = new URL(tabs[0].url).hostname;
      document.getElementById('domain-name').innerText = hostname;
      
      chrome.runtime.sendMessage({ action: 'ANALYZE_URL', url: tabs[0].url }, (response) => {
        if (response && response.success && response.data) {
          updateDashboard(response.data);
        }
      });
    }
  });
}

function animateScoreCount(target) {
  const numEl = document.getElementById('score-num');
  let current = 0;
  if (target === 0) {
    numEl.innerText = 0;
    return;
  }
  const step = Math.ceil(target / 15);
  const timer = setInterval(() => {
    current += step;
    if (current >= target) {
      numEl.innerText = target;
      clearInterval(timer);
    } else {
      numEl.innerText = current;
    }
  }, 25);
}

function updateDashboard(data) {
  // Hide skeleton, show data
  document.getElementById('scan-skeleton').style.display = 'none';
  document.getElementById('scan-real-data').style.display = 'block';

  if (!data) return;

  // Score Ring
  const score = data.risk_score || 0;
  animateScoreCount(score);

  const circle = document.getElementById('progress-circle');
  circle.style.strokeDasharray = `${score}, 100`;

  let color = 'var(--cyan)';
  if (score > 30) color = 'var(--orange)';
  if (score > 75) color = 'var(--red)';
  circle.style.stroke = color;

  // Meter Update
  const fill = document.getElementById('meter-fill');
  fill.style.width = `${score}%`;
  fill.style.backgroundColor = color;

  const levelText = document.getElementById('meter-level-text');
  if (score > 75) levelText.innerText = 'High Risk';
  else if (score > 30) levelText.innerText = 'Suspicious';
  else levelText.innerText = 'Safe';

  // Details
  const domain = data.target_domain || (data.url ? new URL(data.url).hostname : 'unknown');
  document.getElementById('domain-name').innerText = domain;
  document.getElementById('domain-name').style.color = color;
  document.getElementById('domain-age').innerText = data.domain_age > 0 ? `${data.domain_age} Days` : (data.domain_age === 0 ? 'New Domain' : 'Age Unknown');

  const vtDisplay = data.vt_verdict || (data.vt_data ? `Flagged: ${data.vt_data.malicious}/${data.vt_data.total}` : '0 Matches');
  document.getElementById('vt-data').innerText = vtDisplay;

  // Store raw scan payload and reveal the View Report button
  activeScanData = data;
  const viewReportBtn = document.getElementById('view-report-btn');
  if (viewReportBtn) {
    viewReportBtn.style.display = 'block';
  }
}

function populateReportDrawer(data) {
  const url = data.url || (data.target_domain ? 'https://' + data.target_domain : 'Unknown URL');
  document.getElementById('rep-url').innerText = url;
  
  const score = data.risk_score !== undefined ? data.risk_score : 0;
  document.getElementById('rep-score').innerText = `${score} / 100`;

  let verdict = data.verdict || (score > 75 ? 'MALICIOUS' : score > 30 ? 'SUSPICIOUS' : 'SAFE');
  const verdictEl = document.getElementById('rep-verdict');
  verdictEl.innerText = verdict;
  
  // Style verdict coloring
  if (score > 75) {
    verdictEl.style.color = 'var(--red)';
    verdictEl.style.textShadow = '0 0 8px rgba(255, 77, 77, 0.4)';
  } else if (score > 30) {
    verdictEl.style.color = 'var(--orange)';
    verdictEl.style.textShadow = '0 0 8px rgba(255, 170, 0, 0.4)';
  } else {
    verdictEl.style.color = 'var(--green)';
    verdictEl.style.textShadow = '0 0 8px rgba(34, 197, 94, 0.4)';
  }

  const confidence = data.confidence_score !== undefined ? data.confidence_score : (score > 0 ? score : 90);
  document.getElementById('rep-confidence').innerText = `${confidence}%`;

  const category = data.risk_category || data.threat_category || 'Safe';
  document.getElementById('rep-category').innerText = category;

  const ssl = data.ssl_analysis || 'Unknown';
  document.getElementById('rep-ssl').innerText = ssl;

  const age = data.domain_age;
  document.getElementById('rep-age').innerText = age > 0 ? `${age} Days` : (age === 0 ? 'New Domain' : 'Age Unknown');

  const vt = data.vt_data ? `Flagged: ${data.vt_data.malicious} / ${data.vt_data.total}` : '0 Matches';
  document.getElementById('rep-vt').innerText = vt;

  const intel = (data.threat_labels && data.threat_labels.length > 0) ? data.threat_labels.join(', ') : 'None';
  document.getElementById('rep-intel').innerText = intel;

  const whois = data.whois_summary || 'Unknown';
  document.getElementById('rep-whois').innerText = whois;

  const explanation = data.explanation || 'Clean browse logs. No threat anomalies identified.';
  document.getElementById('rep-analysis').innerText = explanation;

  // Set recommendation block
  const recBox = document.getElementById('rep-recommendation');
  const recText = document.getElementById('rep-rec-text');
  recBox.className = 'recommendation-box';

  if (score > 75) {
    recBox.classList.add('rec-avoid');
    recText.innerText = 'AVOID WEBSITE - Terminate connection. Avoid submitting login credentials or sharing sensitive files.';
  } else if (score > 30) {
    recBox.classList.add('rec-caution');
    recText.innerText = 'PROCEED WITH CAUTION - The platform detected suspicious metadata anomalies. Avoid downloads.';
  } else {
    recBox.classList.add('rec-safe');
    recText.innerText = 'SAFE TO BROWSE - No phishing, malware signature matches, or malicious payload signatures matched.';
  }
}

function loadHistory() {
  const list = document.getElementById('history-list');
  list.innerHTML = '';

  chrome.storage.local.get({ scanHistory: [] }, (result) => {
    const history = result.scanHistory.reverse();

    if (history.length === 0) {
      list.innerHTML =
        "<div style='text-align:center; color:var(--text-muted); margin-top:20px; font-size:11px;'>No recent scans.</div>";
      return;
    }

    history.forEach((item) => {
      const div = document.createElement('div');
      div.className = 'history-item';

      let colorClass = 'safe';
      if (item.score > 30) colorClass = 'sus';
      if (item.score > 75) colorClass = 'danger';

      const shortUrl = item.url.replace('https://', '').replace('http://', '');
      const displayUrl = shortUrl.length > 25 ? shortUrl.substring(0, 25) + '...' : shortUrl;

      div.innerHTML = `
        <div>
          <div class="h-url" style="color:white; font-weight:600;">${displayUrl}</div>
          <div style="font-size:9px; color:var(--text-muted);">${item.reason || 'Scan'} | ${item.date}</div>
        </div>
        <div class="h-score ${colorClass}" style="font-size:12px; font-weight:bold;">${item.score}</div>
      `;
      list.appendChild(div);
    });
  });
}

// Live Listener
chrome.runtime.onMessage.addListener((req) => {
  if (req.action === 'SCAN_RESULT') {
    updateDashboard(req.data);
  }
});
