// dashboard.js - Handles WADE Extension Dashboard Interactions
const API_URL = 'http://localhost:7860';
let fullScanHistory = [];
let activeTimeline = 'weekly';

document.addEventListener('DOMContentLoaded', () => {
  loadDashboardData();
  init3DTilt();

  const searchInput = document.getElementById('dashboard-search');
  if (searchInput) searchInput.addEventListener('input', applyFilters);

  const vFilter = document.getElementById('filter-verdict');
  if (vFilter) vFilter.addEventListener('change', applyFilters);

  const sFilter = document.getElementById('filter-severity');
  if (sFilter) sFilter.addEventListener('change', applyFilters);

  // Timeline Tab Switchers
  const btnDaily = document.getElementById('btn-timeline-daily');
  const btnWeekly = document.getElementById('btn-timeline-weekly');
  const btnMonthly = document.getElementById('btn-timeline-monthly');
  
  if (btnDaily && btnWeekly && btnMonthly) {
    btnDaily.addEventListener('click', () => {
      activeTimeline = 'daily';
      updateTimelineTabStyles();
      loadDashboardData();
    });
    btnWeekly.addEventListener('click', () => {
      activeTimeline = 'weekly';
      updateTimelineTabStyles();
      loadDashboardData();
    });
    btnMonthly.addEventListener('click', () => {
      activeTimeline = 'monthly';
      updateTimelineTabStyles();
      loadDashboardData();
    });
  }

  function updateTimelineTabStyles() {
    btnDaily.classList.toggle('active', activeTimeline === 'daily');
    btnWeekly.classList.toggle('active', activeTimeline === 'weekly');
    btnMonthly.classList.toggle('active', activeTimeline === 'monthly');
    
    [btnDaily, btnWeekly, btnMonthly].forEach(btn => {
      if (btn.classList.contains('active')) {
        btn.style.backgroundColor = 'var(--cyan)';
        btn.style.color = '#000';
      } else {
        btn.style.backgroundColor = 'transparent';
        btn.style.color = 'var(--text-muted)';
      }
    });
  }
  if (btnDaily) updateTimelineTabStyles();

  // Export CSV
  const btnCsv = document.getElementById('btn-export-csv');
  if (btnCsv) {
    btnCsv.addEventListener('click', () => {
      if (fullScanHistory.length === 0) return alert('No history logs to export.');
      const headers = ['Timestamp', 'URL', 'Threat Score', 'Verdict', 'Category', 'Severity', 'Reason'];
      const rows = fullScanHistory.map((scan) => [
        scan.timestamp || scan.date,
        `"${scan.url.replace(/"/g, '""')}"`,
        scan.score,
        scan.score > 75 ? 'BLOCKED' : scan.score > 30 ? 'WARNING' : 'SAFE',
        scan.category || (scan.score > 75 ? 'Phishing' : 'Safe'),
        scan.severity || 'Informational',
        `"${(scan.reason || '').replace(/"/g, '""')}"`,
      ]);
      const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      triggerDownload(blob, `wade_threat_logs.csv`);
    });
  }

  // Export JSON
  const btnJson = document.getElementById('btn-export-json');
  if (btnJson) {
    btnJson.addEventListener('click', () => {
      if (fullScanHistory.length === 0) return alert('No history logs to export.');
      const jsonContent = JSON.stringify(fullScanHistory, null, 2);
      const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
      triggerDownload(blob, `wade_threat_logs.json`);
    });
  }

  function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  // URL extraction utility
  function extractHostname(input) {
    let cleanInput = input.trim().toLowerCase();
    if (!cleanInput) return '';
    try {
      if (cleanInput.startsWith('http://') || cleanInput.startsWith('https://')) {
        return new URL(cleanInput).hostname;
      }
      return new URL('https://' + cleanInput).hostname;
    } catch (e) {
      return cleanInput;
    }
  }

  // Whitelist manual input
  document.getElementById('add-whitelist').addEventListener('click', () => {
    const domain = extractHostname(document.getElementById('whitelist-input').value);
    if (domain) modifyList('whitelist', 'add', domain);
    document.getElementById('whitelist-input').value = '';
  });

  // Ignored manual input
  const addIgnoredBtn = document.getElementById('add-ignored');
  if (addIgnoredBtn) {
    addIgnoredBtn.addEventListener('click', () => {
      const domain = extractHostname(document.getElementById('ignored-input').value);
      if (domain) modifyList('ignored', 'add', domain);
      document.getElementById('ignored-input').value = '';
    });
  }

  // Blacklist manual input
  document.getElementById('add-blacklist').addEventListener('click', () => {
    const domain = extractHostname(document.getElementById('blacklist-input').value);
    if (domain) modifyList('blacklist', 'add', domain);
    document.getElementById('blacklist-input').value = '';
  });

  // Tranco Search Engine
  document.getElementById('btn-search-tranco').addEventListener('click', () => {
    const query = extractHostname(document.getElementById('tranco-input').value);
    const resultBox = document.getElementById('tranco-result');
    if (!query) return;

    chrome.storage.local.get({ globalTrusted: [] }, (data) => {
      const isTrusted = data.globalTrusted.some((d) => query === d || query.endsWith('.' + d));
      if (isTrusted) {
        resultBox.innerHTML = `✅ <span style="color:#00ff66; text-shadow: 0 0 10px #00ff66;">${query}</span> is in the Tranco Database!`;
      } else {
        resultBox.innerHTML = `⚠️ <span style="color:#ffa500; text-shadow: 0 0 10px #ffa500;">${query}</span> requires AI Scan.`;
      }
    });
  });

  // Event delegation
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('dynamic-btn')) {
      const list = e.target.getAttribute('data-list');
      const action = e.target.getAttribute('data-action');
      const domain = e.target.getAttribute('data-domain');
      modifyList(list, action, domain);
    }
  });
});

function renderScansTable(scans) {
  const historyTable = document.getElementById('history-table-body');
  if (!historyTable) return;
  historyTable.innerHTML = '';
  if (scans.length === 0) {
    historyTable.innerHTML = `<tr><td colspan="5" class="empty-state">No matching scans logged.</td></tr>`;
  } else {
    scans.forEach((scan) => {
      let hostname = 'unknown';
      try {
        hostname = new URL(scan.url).hostname;
      } catch (e) {
        console.debug(e);
      }

      const tr = document.createElement('tr');
      let badgeClass = scan.score > 75 ? 'danger' : scan.score > 30 ? 'warning' : 'safe';
      let badgeText = scan.score > 75 ? 'BLOCKED' : scan.score > 30 ? 'WARNING' : 'SAFE';
      const displayUrl = scan.url.length > 35 ? scan.url.substring(0, 35) + '...' : scan.url;

      tr.innerHTML = `
        <td style="color: var(--text-muted);">${scan.date}</td>
        <td title="${scan.url}" style="font-weight:bold;">${displayUrl}</td>
        <td style="color: var(--cyan); font-weight:bold; text-shadow: 0 0 5px var(--cyan-glow);">${scan.score}</td>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td>
          <button class="btn-action btn-remove dynamic-btn" data-list="whitelist" data-action="add" data-domain="${hostname}">Trust</button>
          <button class="btn-action btn-remove dynamic-btn" style="border-color:var(--danger-red); color:var(--danger-red);" data-list="blacklist" data-action="add" data-domain="${hostname}">Block</button>
        </td>
      `;
      historyTable.appendChild(tr);
    });
  }
}

function applyFilters() {
  const searchQuery = document.getElementById('dashboard-search').value.toLowerCase().trim();
  const verdictFilter = document.getElementById('filter-verdict').value;
  const severityFilter = document.getElementById('filter-severity').value;

  const filtered = fullScanHistory.filter((scan) => {
    if (searchQuery && !scan.url.toLowerCase().includes(searchQuery)) return false;
    if (verdictFilter !== 'ALL') {
      let badgeText = scan.score > 75 ? 'BLOCKED' : scan.score > 30 ? 'WARNING' : 'SAFE';
      if (badgeText !== verdictFilter) return false;
    }
    if (severityFilter !== 'ALL') {
      const sev =
        scan.severity ||
        (scan.score > 90
          ? 'Critical'
          : scan.score > 75
            ? 'High'
            : scan.score > 30
              ? 'Medium'
              : 'Informational');
      if (sev !== severityFilter) return false;
    }
    return true;
  });

  renderScansTable(filtered);
}

function init3DTilt() {
  const cards = document.querySelectorAll('.interactive-3d');
  cards.forEach((card) => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const centerX = rect.width / 2;
      const centerY = rect.height / 2;
      const rotateX = ((y - centerY) / centerY) * -6;
      const rotateY = ((x - centerX) / centerX) * 6;
      card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`;
    });
    card.addEventListener('mouseleave', () => {
      card.style.transform = `perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)`;
    });
  });
}

function loadDashboardData() {
  // Check if API is running
  fetch(`${API_URL}/dashboard/stats`)
    .then(res => res.json())
    .then(stats => {
      // Backend active
      fetch(`${API_URL}/dashboard/recent`)
        .then(res => res.json())
        .then(recentScans => {
          chrome.storage.local.get({ userTrust: {}, userBlacklist: [], ignoredDomains: [] }, (localData) => {
            renderDashboardWithData({
              scans: recentScans.map(s => ({
                url: s.url,
                score: s.risk_score,
                date: new Date(s.timestamp).toLocaleDateString(),
                category: s.risk_category,
                severity: s.severity,
                reason: s.detection_reason
              })),
              stats: stats,
              userTrust: localData.userTrust,
              userBlacklist: localData.userBlacklist,
              ignoredDomains: localData.ignoredDomains
            });
          });
        });
    })
    .catch(() => {
      // Offline fallback
      loadDashboardFromLocalStorage();
    });
}

function loadDashboardFromLocalStorage() {
  chrome.storage.local.get({ scanHistory: [], userTrust: {}, userBlacklist: [], ignoredDomains: [] }, (data) => {
    const history = data.scanHistory.reverse();
    const total = history.length;
    const safe = history.filter(s => s.score <= 30).length;
    const suspicious = history.filter(s => s.score > 30 && s.score <= 75).length;
    const phishing = history.filter(s => s.score > 75).length;
    
    const categories = { Phishing: 0, Malware: 0, XSS: 0, 'Social Engineering': 0, Safe: 0 };
    history.forEach(s => {
      const cat = s.category || (s.score > 75 ? 'Phishing' : 'Safe');
      if (cat in categories) categories[cat]++;
    });

    const severities = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
    history.forEach(s => {
      const sev = s.severity || (s.score > 90 ? 'Critical' : s.score > 75 ? 'High' : s.score > 30 ? 'Medium' : 'Informational');
      if (sev in severities) severities[sev]++;
    });

    // Create daily, weekly, monthly timeline data
    const timeline_weekly = [];
    const dates = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      dates[d.toLocaleDateString()] = 0;
    }
    history.forEach(s => {
      for (let key in dates) {
        if (s.date && s.date.includes(key)) dates[key]++;
      }
    });
    for (let key in dates) {
      timeline_weekly.push({ label: key, count: dates[key] });
    }

    renderDashboardWithData({
      scans: history.map(s => ({ url: s.url, score: s.score, date: s.date, category: s.category, severity: s.severity, reason: s.reason })),
      stats: {
        total_scans: total,
        safe: safe,
        suspicious: suspicious,
        phishing: phishing,
        success_rate: total > 0 ? ((safe / total) * 100).toFixed(1) : '100.0',
        categories: categories,
        severities: severities,
        timeline_daily: timeline_weekly,
        timeline_weekly: timeline_weekly,
        timeline_monthly: timeline_weekly
      },
      userTrust: data.userTrust,
      userBlacklist: data.userBlacklist,
      ignoredDomains: data.ignoredDomains
    });
  });
}

function renderDashboardWithData(data) {
  const history = data.scans;
  const stats = data.stats;
  const trustData = data.userTrust;
  const blacklistData = data.userBlacklist;
  const ignoredData = data.ignoredDomains;

  // 1. Set values
  const trustedDomains = Object.keys(trustData).filter((d) => trustData[d] >= 2);
  document.getElementById('stat-total-scans').innerText = stats.total_scans;
  document.getElementById('stat-blocked').innerText = blacklistData.length;
  document.getElementById('stat-trusted').innerText = trustedDomains.length;
  document.getElementById('stat-success-rate').innerText = stats.success_rate + '%';

  // 2. Render Donut Chart
  renderConicDonut(stats);

  // 3. Render Timeline Chart (CSS-based bar layout for MV3 offline compliance)
  const timelineContainer = document.getElementById('timeline-container');
  if (timelineContainer) {
    timelineContainer.innerHTML = '';
    let timelineData = stats.timeline_weekly || [];
    if (activeTimeline === 'daily') timelineData = stats.timeline_daily || [];
    else if (activeTimeline === 'monthly') timelineData = stats.timeline_monthly || [];

    const maxCount = Math.max(...timelineData.map(d => d.count), 1);
    
    // Create inner wrapper with flex styling
    const wrapper = document.createElement('div');
    wrapper.style.display = 'flex';
    wrapper.style.justifyContent = 'space-around';
    wrapper.style.alignItems = 'flex-end';
    wrapper.style.height = '180px';
    wrapper.style.paddingTop = '20px';
    wrapper.style.width = '100%';

    timelineData.forEach((item) => {
      const heightPct = Math.max(10, (item.count / maxCount) * 140);
      let label = item.label;
      if (activeTimeline === 'weekly' || activeTimeline === 'monthly') {
        const parts = label.split('/');
        if (parts.length >= 2) label = `${parts[0]}/${parts[1]}`;
        else {
          const partsDash = label.split('-');
          if (partsDash.length >= 3) label = `${partsDash[1]}/${partsDash[2]}`;
        }
      }
      const barWrapper = document.createElement('div');
      barWrapper.style.display = 'flex';
      barWrapper.style.flexDirection = 'column';
      barWrapper.style.alignItems = 'center';
      barWrapper.style.gap = '8px';
      barWrapper.style.flex = '1';
      barWrapper.innerHTML = `
        <span class="bar-count" style="font-size: 9px; font-weight: bold; color: var(--cyan);">${item.count}</span>
        <div class="timeline-bar" style="height: ${heightPct}px; width: 14px; background: linear-gradient(180deg, var(--cyan) 0%, rgba(0, 243, 255, 0.2) 100%); box-shadow: 0 0 10px rgba(0, 243, 255, 0.2); border-radius: 4px 4px 0 0; transition: height 0.5s ease;"></div>
        <span class="timeline-label" style="font-size: 8px; color: var(--text-muted);">${label}</span>
      `;
      wrapper.appendChild(barWrapper);
    });
    timelineContainer.appendChild(wrapper);
  }

  // 4. Render Threat Categories
  const categoriesContainer = document.getElementById('categories-container');
  if (categoriesContainer) {
    categoriesContainer.innerHTML = '';
    const total = stats.total_scans || 1;
    const catColors = { Phishing: 'var(--danger-red)', Malware: '#a500ff', XSS: '#ffa500', 'Social Engineering': '#00f3ff', Safe: 'var(--safe-green)' };
    for (let cat in stats.categories) {
      const count = stats.categories[cat];
      const pct = ((count / total) * 100).toFixed(0);
      const color = catColors[cat] || 'var(--text-main)';
      const row = document.createElement('div');
      row.className = 'stat-row';
      row.innerHTML = `
        <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:4px;">
          <span>${cat}</span>
          <span style="color:${color}; font-weight:bold;">${count} (${pct}%)</span>
        </div>
        <div class="stat-progress-bg" style="background:#111; border-radius:3px; height:6px; width:100%; overflow:hidden; border: 1px solid rgba(255,255,255,0.05);">
          <div class="stat-progress-fill" style="width: ${pct}%; background-color: ${color}; height:100%; transition:width 0.3s;"></div>
        </div>
      `;
      categoriesContainer.appendChild(row);
    }
  }

  // 5. Render Severities
  const severityContainer = document.getElementById('severity-container');
  if (severityContainer) {
    severityContainer.innerHTML = '';
    const total = stats.total_scans || 1;
    const sevColors = { Critical: 'var(--danger-red)', High: '#ffa500', Medium: '#ffff00', Low: '#00ffc4', Informational: 'var(--safe-green)' };
    for (let sev in stats.severities) {
      const count = stats.severities[sev];
      const pct = ((count / total) * 100).toFixed(0);
      const color = sevColors[sev] || 'var(--text-main)';
      const row = document.createElement('div');
      row.className = 'stat-row';
      row.innerHTML = `
        <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:4px;">
          <span>${sev}</span>
          <span style="color:${color}; font-weight:bold;">${count} (${pct}%)</span>
        </div>
        <div class="stat-progress-bg" style="background:#111; border-radius:3px; height:6px; width:100%; overflow:hidden; border: 1px solid rgba(255,255,255,0.05);">
          <div class="stat-progress-fill" style="width: ${pct}%; background-color: ${color}; height:100%; transition:width 0.3s;"></div>
        </div>
      `;
      severityContainer.appendChild(row);
    }
  }

  // 6. Populate tables
  fullScanHistory = history;
  renderScansTable(history);

  // Whitelist Whitelist
  const whitelistTable = document.getElementById('whitelist-table-body');
  whitelistTable.innerHTML = '';
  if (trustedDomains.length === 0)
    whitelistTable.innerHTML = `<tr><td class="empty-state">No trusted domains.</td></tr>`;
  else {
    trustedDomains.forEach((domain) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="color: var(--safe-green); font-weight: bold; text-shadow: 0 0 5px rgba(0,255,102,0.4);">${domain}</td>
        <td style="text-align:right;">
          <button class="btn-action btn-remove dynamic-btn" data-list="whitelist" data-action="remove" data-domain="${domain}">Remove</button>
        </td>
      `;
      whitelistTable.appendChild(tr);
    });
  }

  // Populate Ignored Domains
  const ignoredTable = document.getElementById('ignored-table-body');
  if (ignoredTable) {
    ignoredTable.innerHTML = '';
    if (ignoredData.length === 0)
      ignoredTable.innerHTML = `<tr><td class="empty-state">No ignored domains.</td></tr>`;
    else {
      ignoredData.forEach((domain) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td style="color: var(--warn-orange); font-weight: bold; text-shadow: 0 0 5px rgba(255,165,0,0.4);">${domain}</td>
          <td style="text-align:right;">
            <button class="btn-action btn-remove dynamic-btn" data-list="ignored" data-action="remove" data-domain="${domain}">Remove</button>
          </td>
        `;
        ignoredTable.appendChild(tr);
      });
    }
  }

  // Blacklist Blacklist
  const blacklistTable = document.getElementById('blacklist-table-body');
  blacklistTable.innerHTML = '';
  if (blacklistData.length === 0)
    blacklistTable.innerHTML = `<tr><td class="empty-state">No custom blocks.</td></tr>`;
  else {
    blacklistData.forEach((domain) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="color: var(--danger-red); font-weight: bold; text-shadow: 0 0 5px var(--danger-glow);">${domain}</td>
        <td style="text-align:right;">
          <button class="btn-action btn-remove dynamic-btn" data-list="blacklist" data-action="remove" data-domain="${domain}">Remove</button>
        </td>
      `;
      blacklistTable.appendChild(tr);
    });
  }
}

function renderConicDonut(stats) {
  const total = stats.total_scans || 1;
  const safePct = ((stats.safe || 0) / total) * 100;
  const warnPct = ((stats.suspicious || 0) / total) * 100;

  const safeEnd = safePct;
  const warnEnd = safePct + warnPct;

  document.getElementById('count-safe').innerText = stats.safe || 0;
  document.getElementById('count-warn').innerText = stats.suspicious || 0;
  document.getElementById('count-danger').innerText = stats.phishing || 0;

  const chart = document.getElementById('traffic-chart');
  if (chart) {
    chart.style.background = `conic-gradient(
      var(--safe-green) 0% ${safeEnd}%, 
      var(--warn-orange) ${safeEnd}% ${warnEnd}%, 
      var(--danger-red) ${warnEnd}% 100%
    )`;
  }
}

function modifyList(listType, action, domain) {
  if (!domain || domain === 'unknown') return;

  chrome.storage.local.get({ userTrust: {}, userBlacklist: [], ignoredDomains: [] }, (data) => {
    let trustData = data.userTrust;
    let blacklistData = data.userBlacklist;
    let ignoredData = data.ignoredDomains;

    if (listType === 'whitelist') {
      if (action === 'add') {
        trustData[domain] = 3;
        blacklistData = blacklistData.filter((d) => d !== domain);
        ignoredData = ignoredData.filter((d) => d !== domain);
      } else if (action === 'remove') {
        delete trustData[domain];
      }
    } else if (listType === 'blacklist') {
      if (action === 'add') {
        if (!blacklistData.includes(domain)) blacklistData.push(domain);
        delete trustData[domain];
        ignoredData = ignoredData.filter((d) => d !== domain);
      } else if (action === 'remove') {
        blacklistData = blacklistData.filter((d) => d !== domain);
      }
    } else if (listType === 'ignored') {
      if (action === 'add') {
        if (!ignoredData.includes(domain)) ignoredData.push(domain);
        delete trustData[domain];
        blacklistData = blacklistData.filter((d) => d !== domain);
      } else if (action === 'remove') {
        ignoredData = ignoredData.filter((d) => d !== domain);
      }
    }

    chrome.storage.local.set({ userTrust: trustData, userBlacklist: blacklistData, ignoredDomains: ignoredData }, () => {
      loadDashboardData();
    });
  });
}
