// popup.js - Handles WADE UI Interactions
const API_URL = 'http://localhost:7860';
const WADE_API_KEY = 'wade_secret_key_v2';

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

  // Populate Domain for Quick Report
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.url) {
      try {
        const domain = new URL(tabs[0].url).hostname;
        const reportInput = document.getElementById('report-domain-input');
        if (reportInput) reportInput.value = domain;
      } catch (e) {
        console.debug('Failed to extract domain age', e);
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
          'X-WADE-API-KEY': WADE_API_KEY
        },
        body: JSON.stringify({ domain: domain, report_type: type, comment: comment })
      })
      .then(res => res.json())
      .then(data => {
        if (status) {
          status.style.color = '#00ff66';
          status.innerText = '🚀 Report submitted successfully!';
        }
        document.getElementById('report-comment').value = '';
        setTimeout(() => {
          if (status) status.innerText = '';
        }, 3000);
      })
      .catch(err => {
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
                  btnTrust.innerText = '✅ TRUST THIS SITE';
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
          btn.innerText = '⚠️ RESET TRUSTED SITES';
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
      document.getElementById('domain-name').innerText = new URL(tabs[0].url).hostname;
      chrome.runtime.sendMessage({ action: 'ANALYZE_URL', url: tabs[0].url }, (response) => {
        // Ignore the response here if we're relying on the background script to send SCAN_RESULT
        if (response && response.success && response.data) {
          updateDashboard(response.data);
        }
      });
    }
  });
}

function updateDashboard(data) {
  if (!data) return;

  // Score Ring
  const score = data.risk_score || 0;
  const ring = document.getElementById('score-ring');
  const scoreNum = document.getElementById('score-num');

  scoreNum.innerText = score;

  let color = '#00f3ff'; // Cyan
  if (score > 30) color = '#ffa500'; // Orange
  if (score > 75) color = '#ff003c'; // Red

  ring.style.borderColor = color;
  scoreNum.style.color = color;

  // Harm Box (Threat Info)
  const harmBox = document.getElementById('harm-display');
  if (score > 50) {
    harmBox.style.display = 'block';
    document.getElementById('harm-cause').innerText = data.threat_type || 'Unknown Threat';
    document.getElementById('harm-effect').innerText = data.harm || 'Potential Security Risk';
  } else {
    harmBox.style.display = 'none';
  }

  // Details
  if (data.target_domain) {
    document.getElementById('domain-name').innerText = data.target_domain;
  }
  document.getElementById('domain-name').style.color = color;
  document.getElementById('domain-age').innerText = data.domain_age || '--';

  // Fallback if vt_verdict isn't explicitly passed, use the total to show it scanned
  const vtDisplay =
    data.vt_verdict || (data.vt_data ? `Vendors Flagged: ${data.vt_data.malicious}` : '--');
  document.getElementById('vt-data').innerText = vtDisplay;
}

function loadHistory() {
  const list = document.getElementById('history-list');
  list.innerHTML = '';

  chrome.storage.local.get({ scanHistory: [] }, (result) => {
    const history = result.scanHistory.reverse();

    if (history.length === 0) {
      list.innerHTML =
        "<div style='text-align:center; color:#555; margin-top:20px;'>No recent scans.</div>";
      return;
    }

    history.forEach((item) => {
      const div = document.createElement('div');
      div.className = 'history-item';

      let colorClass = 'safe';
      if (item.score > 30) colorClass = 'sus';
      if (item.score > 75) colorClass = 'danger';

      div.innerHTML = `
                <div>
                    <div class="h-url" style="color:white;">${item.url.substring(0, 25)}...</div>
                    <div style="font-size:9px; color:#666;">${item.reason || 'Scan'} | ${item.date}</div>
                </div>
                <div class="h-score ${colorClass}">${item.score}</div>
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
