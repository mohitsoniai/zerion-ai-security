// dashboard.js - Handles Zerion Command Center Interactions
const API_URL = 'https://zerion-ai-security-api.onrender.com';
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
      triggerDownload(blob, `zerion_threat_logs.csv`);
    });
  }

  // Export JSON
  const btnJson = document.getElementById('btn-export-json');
  if (btnJson) {
    btnJson.addEventListener('click', () => {
      if (fullScanHistory.length === 0) return alert('No history logs to export.');
      const jsonContent = JSON.stringify(fullScanHistory, null, 2);
      const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
      triggerDownload(blob, `zerion_threat_logs.json`);
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

  // Sidebar Close Triggers
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('overlay');
  const sidebarClose = document.getElementById('sidebar-close');

  if (sidebarClose && sidebar && overlay) {
    const closeSidebar = () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('active');
      overlay.style.display = 'none';
    };
    sidebarClose.addEventListener('click', closeSidebar);
    overlay.addEventListener('click', closeSidebar);
  }

  // Initialize Global Threat Map
  initThreatMap();

  // Initialize AI Copilot
  initAICopilot();
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

      tr.style.cursor = 'pointer';
      tr.addEventListener('click', (e) => {
        if (e.target.classList.contains('dynamic-btn')) return;
        openAnalysisSidebar(scan);
      });

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

function openAnalysisSidebar(scan) {
  activeCopilotScanContext = scan;
  let hostname = 'unknown';
  try {
    hostname = new URL(scan.url).hostname;
  } catch (e) {
    hostname = scan.url || 'unknown';
  }

  document.getElementById('sidebar-domain').innerText = hostname;
  document.getElementById('sidebar-url').innerText = scan.url;
  document.getElementById('sidebar-score').innerText = scan.score + '%';
  document.getElementById('sidebar-confidence').innerText = (scan.confidence_score || scan.score || 90) + '%';
  document.getElementById('sidebar-severity').innerText = scan.severity || (scan.score > 90 ? 'Critical' : scan.score > 75 ? 'High' : scan.score > 30 ? 'Medium' : 'Informational');
  document.getElementById('sidebar-category').innerText = scan.category || 'Safe';

  // MITRE ATT&CK Mapping
  const mitreId = document.getElementById('mitre-id');
  const mitreTactic = document.getElementById('mitre-tactic');
  const category = scan.category || 'Safe';
  
  const mappings = {
    'Phishing': { id: 'T1566', tactic: 'Initial Access: Phishing links or content designed to harvest client credentials.' },
    'Malware': { id: 'T1204', tactic: 'Execution: User execution of malicious payloads delivered via external scripts.' },
    'XSS': { id: 'T1189', tactic: 'Drive-by Compromise: Cross-site Scripting injection triggering unsanctioned code execution.' },
    'Social Engineering': { id: 'T1204.001', tactic: 'Credential Baiting: Luring client to execute actions via hostile page mimics.' },
    'Safe': { id: 'N/A', tactic: 'Clean Signature: Audited domain contains no matches matching MITRE enterprise matrices.' }
  };
  const mitre = mappings[category] || { id: 'T1583', tactic: 'Acquire Infrastructure: Uncategorized or suspicious domain indicators.' };
  mitreId.innerText = mitre.id;
  mitreTactic.innerText = mitre.tactic;

  // Executive Summary / Technical Analysis / Recommendations
  document.getElementById('sidebar-summary').innerText = scan.reason || 'Clean browse logs. No threat anomalies identified.';
  document.getElementById('sidebar-analysis').innerText = scan.detection_reason || 'AI Engine verified that the payload behaves consistent with standard white-listed policies.';
  
  // Registration & SSL status
  document.getElementById('sidebar-registrar').innerText = scan.whois_registrar || 'Unknown Registrar';
  document.getElementById('sidebar-age').innerText = scan.domain_age > 0 ? `${scan.domain_age} Days` : 'Age Unknown';
  document.getElementById('sidebar-ssl-status').innerText = scan.ssl_valid ? 'Valid SSL Cert' : 'Invalid / Expired';
  document.getElementById('sidebar-ssl-issuer').innerText = scan.ssl_issuer || 'N/A';

  // SVG Gauge Animation
  const circle = document.getElementById('sidebar-gauge-fill');
  const scorePct = scan.score || 0;
  circle.style.strokeDasharray = `${scorePct}, 100`;
  const strokeColor = scorePct > 75 ? 'var(--red)' : scorePct > 30 ? 'var(--orange)' : 'var(--green)';
  circle.style.stroke = strokeColor;

  // Set recommendation block
  const recBox = document.getElementById('sidebar-recommendation-box');
  const recText = document.getElementById('sidebar-recommendation-text');
  recBox.className = 'recommendation-box';

  if (scorePct > 75) {
    recBox.classList.add('rec-avoid');
    recText.innerText = 'AVOID WEBSITE - Terminate connection. Avoid submitting login credentials or sharing sensitive files.';
  } else if (scorePct > 30) {
    recBox.classList.add('rec-caution');
    recText.innerText = 'PROCEED WITH CAUTION - The platform detected suspicious metadata anomalies. Avoid downloads.';
  } else {
    recBox.classList.add('rec-safe');
    recText.innerText = 'SAFE TO BROWSE - No phishing, malware signature matches, or malicious payload signatures matched.';
  }

  // Open sidebar & overlay
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('overlay').classList.add('active');
  document.getElementById('overlay').style.display = 'block';
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
                category: s.risk_category || 'Safe',
                severity: s.severity || 'Informational',
                reason: s.explanation || 'Clean browse logs.',
                detection_reason: s.detection_reason || 'No anomalies detected.',
                whois_registrar: s.whois_summary || 'Unknown',
                domain_age: s.domain_age !== undefined ? s.domain_age : -1,
                ssl_valid: s.ssl_analysis ? s.ssl_analysis.includes("Valid") : false,
                ssl_issuer: s.ssl_analysis || 'Unknown',
                vt_data: s.vt_data || { malicious: 0, total: 0 },
                threat_labels: s.threat_labels || [],
                confidence_score: s.confidence_score || s.risk_score || 90
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
      scans: history.map(s => {
        const raw = s.rawData || {};
        return {
          url: s.url,
          score: s.score,
          date: s.date,
          category: s.category || raw.risk_category || 'Safe',
          severity: s.severity || raw.severity || 'Informational',
          reason: s.reason || raw.explanation || 'Clean browse logs.',
          detection_reason: raw.detection_reason || 'No anomalies detected.',
          whois_registrar: raw.whois_summary || 'Unknown',
          domain_age: raw.domain_age !== undefined ? raw.domain_age : -1,
          ssl_valid: raw.ssl_analysis ? raw.ssl_analysis.includes("Valid") : false,
          ssl_issuer: raw.ssl_analysis || 'Unknown',
          vt_data: raw.vt_data || { malicious: 0, total: 0 },
          threat_labels: raw.threat_labels || [],
          confidence_score: raw.confidence_score || s.score || 90
        };
      }),
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
// ==========================================
// 6. GLOBAL THREAT MAP SYSTEM
// ==========================================
let threatMap;
const attackCountries = {
  'USA': [37.0902, -95.7129],
  'Russia': [61.5240, 105.3188],
  'China': [35.8617, 104.1954],
  'India': [20.5937, 78.9629],
  'Germany': [51.1657, 10.4515],
  'UK': [55.3781, -3.4360],
  'Brazil': [-14.2350, -51.9253],
  'Australia': [-25.2744, 133.7751],
  'South Africa': [-30.5595, 22.9375],
  'Japan': [36.2048, 138.2529],
  'Canada': [56.1304, -106.3468],
  'France': [46.2276, 2.2137],
  'Ukraine': [48.3794, 31.1656],
  'Iran': [32.4279, 53.6880],
  'North Korea': [40.3399, 127.5101],
  'Singapore': [1.3521, 103.8198]
};

const mapThreatTypes = [
  { type: 'Credential Phishing', severity: 'Critical', color: '#ff4d4d' },
  { type: 'Malware Delivery', severity: 'High', color: '#ff4d4d' },
  { type: 'Ransomware Beacon', severity: 'Critical', color: '#ff4d4d' },
  { type: 'Credential Stuffing', severity: 'High', color: '#ffaa00' },
  { type: 'DDoS Botnet Flood', severity: 'High', color: '#ffaa00' },
  { type: 'Command & Control Beaconing', severity: 'High', color: '#ffaa00' },
  { type: 'Safe Proxy Traffic', severity: 'Low', color: '#22c55e' },
  { type: 'Tor Exit Node Scan', severity: 'Medium', color: '#ffaa00' },
  { type: 'SQL Injection Probe', severity: 'Medium', color: '#ffaa00' }
];

function initThreatMap() {
  const mapElement = document.getElementById('threat-map');
  if (!mapElement) return;

  try {
    threatMap = L.map('threat-map', {
      center: [20, 0],
      zoom: 2,
      minZoom: 1.5,
      maxZoom: 10,
      zoomControl: false,
      attributionControl: false
    });

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 20
    }).addTo(threatMap);
    
    // Disable double click zoom for better embedded feel
    threatMap.doubleClickZoom.disable();
  } catch (e) {
    console.error('Failed to initialize Leaflet map:', e);
    return;
  }

  // Setup Threat Map Counters
  let activeThreats = 142;
  let countriesMonitored = 74;
  let threatsBlocked = 3280;
  let predictions = 894;
  let avgDetection = 1.24;

  function updateCounters() {
    activeThreats += Math.floor(Math.random() * 5) - 2;
    if (activeThreats < 100) activeThreats = 100;
    
    threatsBlocked += Math.floor(Math.random() * 3);
    predictions += Math.floor(Math.random() * 2);
    avgDetection = (1.1 + Math.random() * 0.3).toFixed(2);
    
    document.getElementById('map-active-threats').innerText = activeThreats;
    document.getElementById('map-countries').innerText = countriesMonitored;
    document.getElementById('map-blocked-today').innerText = threatsBlocked;
    document.getElementById('map-predictions').innerText = predictions;
    document.getElementById('map-avg-time').innerText = avgDetection + 's';
  }
  updateCounters();
  setInterval(updateCounters, 4000);

  const activityList = document.getElementById('activity-list-container');
  
  function triggerSimulatedAttack() {
    if (!threatMap) return;
    
    const countryNames = Object.keys(attackCountries);
    const sourceIdx = Math.floor(Math.random() * countryNames.length);
    let targetIdx = Math.floor(Math.random() * countryNames.length);
    while (targetIdx === sourceIdx) {
      targetIdx = Math.floor(Math.random() * countryNames.length);
    }
    
    const source = countryNames[sourceIdx];
    const target = countryNames[targetIdx];
    const threat = mapThreatTypes[Math.floor(Math.random() * mapThreatTypes.length)];
    
    animateMapAttack(attackCountries[source], attackCountries[target], threat.color);
    
    const item = document.createElement('div');
    item.className = 'activity-item';
    
    let severityBadge = '';
    if (threat.severity === 'Critical') {
      severityBadge = `<span class="badge danger" style="font-size:8px; padding:2px 6px;">CRITICAL</span>`;
    } else if (threat.severity === 'High') {
      severityBadge = `<span class="badge warning" style="font-size:8px; padding:2px 6px; border-color:var(--orange); color:var(--orange);">HIGH</span>`;
    } else if (threat.severity === 'Medium') {
      severityBadge = `<span class="badge warning" style="font-size:8px; padding:2px 6px; border-color:var(--orange); color:var(--orange);">MEDIUM</span>`;
    } else {
      severityBadge = `<span class="badge safe" style="font-size:8px; padding:2px 6px;">LOW</span>`;
    }
    
    const timeStr = new Date().toLocaleTimeString();
    item.innerHTML = `
      <div class="activity-top">
        <span class="activity-path">${source} → ${target}</span>
        ${severityBadge}
      </div>
      <div class="activity-bottom">
        <span class="activity-threat">${threat.type}</span>
        <span class="activity-time">${timeStr}</span>
      </div>
    `;
    
    activityList.insertBefore(item, activityList.firstChild);
    if (activityList.children.length > 15) {
      activityList.removeChild(activityList.lastChild);
    }
  }

  for(let i=0; i<3; i++) {
    setTimeout(triggerSimulatedAttack, i * 1200);
  }
  setInterval(triggerSimulatedAttack, 6000);
}

function getMapCurvePoints(start, end, numPoints = 30) {
  const points = [];
  const startLatLng = L.latLng(start);
  const endLatLng = L.latLng(end);
  
  const midLat = (startLatLng.lat + endLatLng.lat) / 2;
  const midLng = (startLatLng.lng + endLatLng.lng) / 2;
  
  const dLat = endLatLng.lat - startLatLng.lat;
  const dLng = endLatLng.lng - startLatLng.lng;
  
  const offset = 0.25;
  const controlLat = midLat + dLng * offset;
  const controlLng = midLng - dLat * offset;
  
  for (let i = 0; i <= numPoints; i++) {
    const t = i / numPoints;
    const lat = (1 - t) * (1 - t) * startLatLng.lat + 2 * (1 - t) * t * controlLat + t * t * endLatLng.lat;
    const lng = (1 - t) * (1 - t) * startLatLng.lng + 2 * (1 - t) * t * controlLng + t * t * endLatLng.lng;
    points.push([lat, lng]);
  }
  return points;
}

function animateMapAttack(start, end, color) {
  if (!threatMap) return;
  
  const points = getMapCurvePoints(start, end);
  const path = L.polyline(points, { color: color, weight: 1.5, opacity: 0.5 }).addTo(threatMap);
  
  const dot = L.circleMarker(start, {
    radius: 3,
    color: color,
    fillColor: color,
    fillOpacity: 1,
    className: 'pulsing-attack-dot'
  }).addTo(threatMap);
  
  let step = 0;
  const numSteps = points.length;
  
  const interval = setInterval(() => {
    if (step >= numSteps) {
      clearInterval(interval);
      if (threatMap && threatMap.hasLayer(dot)) threatMap.removeLayer(dot);
      setTimeout(() => {
        if (threatMap && threatMap.hasLayer(path)) threatMap.removeLayer(path);
      }, 1000);
      
      const targetMarker = L.circleMarker(end, {
        radius: 6,
        color: color,
        fillColor: color,
        fillOpacity: 0.8
      }).addTo(threatMap);
      
      let pulseStep = 0;
      const pulseInterval = setInterval(() => {
        pulseStep++;
        targetMarker.setRadius(6 + pulseStep);
        targetMarker.setStyle({ fillOpacity: 0.8 - (pulseStep * 0.1) });
        if (pulseStep >= 8) {
          clearInterval(pulseInterval);
          if (threatMap && threatMap.hasLayer(targetMarker)) threatMap.removeLayer(targetMarker);
        }
      }, 50);
      
      return;
    }
    if (threatMap && threatMap.hasLayer(dot)) {
      dot.setLatLng(points[step]);
    }
    step++;
  }, 35);
}

// ==========================================
// 7. AI COPILOT CHATBOT SYSTEM
// ==========================================
let activeCopilotScanContext = null;

function initAICopilot() {
  const panel = document.getElementById('copilot-panel');
  const btnOpen = document.getElementById('copilot-btn');
  const btnClose = document.getElementById('copilot-close');
  const btnSend = document.getElementById('copilot-send-btn');
  const inputEl = document.getElementById('copilot-input');
  const messagesBox = document.getElementById('copilot-messages');
  const chipsContainer = document.getElementById('copilot-chips');

  if (!panel || !btnOpen || !btnClose || !btnSend || !inputEl || !messagesBox) return;

  // Toggle Panel open/close
  btnOpen.addEventListener('click', () => {
    panel.classList.toggle('active');
    if (panel.classList.contains('active')) {
      inputEl.focus();
    }
  });

  btnClose.addEventListener('click', () => {
    panel.classList.remove('active');
  });

  // Send message handler
  const sendMessage = (text = '') => {
    const prompt = text.trim() || inputEl.value.trim();
    if (!prompt) return;

    if (!text.trim()) inputEl.value = '';

    appendMessageBubble(prompt, 'user');
    const loadingId = appendMessageBubble('*Analyzing signatures and loading context...*', 'ai');

    fetch(`${API_URL}/copilot`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        prompt: prompt,
        scan_context: activeCopilotScanContext ? {
          url: activeCopilotScanContext.url,
          verdict: activeCopilotScanContext.score > 75 ? 'MALICIOUS' : activeCopilotScanContext.score > 30 ? 'SUSPICIOUS' : 'SAFE',
          risk_score: activeCopilotScanContext.score,
          severity: activeCopilotScanContext.severity,
          risk_category: activeCopilotScanContext.category,
          explanation: activeCopilotScanContext.reason,
          whois_summary: activeCopilotScanContext.whois_registrar,
          domain_age: activeCopilotScanContext.domain_age,
          ssl_analysis: activeCopilotScanContext.ssl_issuer,
          vt_data: activeCopilotScanContext.vt_data,
          threat_labels: activeCopilotScanContext.threat_labels
        } : null
      })
    })
    .then(res => {
      if (!res.ok) throw new Error('Copilot Service degraded.');
      return res.json();
    })
    .then(data => {
      removeLoadingBubble(loadingId);
      appendMessageBubble(data.response, 'ai');
    })
    .catch(err => {
      console.error(err);
      removeLoadingBubble(loadingId);
      appendMessageBubble('⚠️ **Connection Timeout**. Threat intelligence network is unresponsive. Please retry.', 'ai');
    });
  };

  btnSend.addEventListener('click', () => sendMessage());
  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendMessage();
  });

  // Chips click handler
  if (chipsContainer) {
    chipsContainer.addEventListener('click', (e) => {
      if (e.target.classList.contains('chip-btn')) {
        const question = e.target.getAttribute('data-question');
        sendMessage(question);
      }
    });
  }

  function appendMessageBubble(text, sender) {
    const bubble = document.createElement('div');
    bubble.className = `message ${sender}`;
    
    // Parse simple bold/markdown elements
    let formattedText = text
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\n/g, '<br/>');

    bubble.innerHTML = formattedText;
    messagesBox.appendChild(bubble);
    messagesBox.scrollTop = messagesBox.scrollHeight;
    
    const randomId = 'msg-' + Math.random().toString(36).substring(2, 9);
    bubble.id = randomId;
    return randomId;
  }

  function removeLoadingBubble(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
  }
}
