// ============================================================
// Shunya Spam - Popup Script
// ============================================================

// ── Tab Switching ─────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));

  document.querySelector(`.tab[onclick="switchTab('${name}')"]`).classList.add("active");
  document.getElementById(`panel-${name}`).classList.add("active");
}

// ── Load Stats ────────────────────────────────────────────────
function loadStats() {
  chrome.runtime.sendMessage({ type: "GET_STATS" }, (stats) => {
    if (!stats) return;
    document.getElementById("stat-scanned").textContent  = stats.scanned  || 0;
    document.getElementById("stat-blocked").textContent  = stats.blocked  || 0;
    document.getElementById("stat-phishing").textContent = stats.phishing || 0;
    document.getElementById("stat-spam").textContent     = stats.spam     || 0;
  });
}

// ── Load Settings ─────────────────────────────────────────────
function loadSettings() {
  chrome.storage.local.get(["settings", "apiKey"], (data) => {
    const s = data.settings || { autoscan: true, banners: true, ai: true };
    
    Object.keys(s).forEach(key => {
      const el = document.getElementById(`toggle-${key}`);
      if (el) el.classList.toggle("on", !!s[key]);
    });

    if (data.apiKey) {
      document.getElementById("api-key-input").value = data.apiKey;
    }
  });
}

function toggleSetting(key) {
  chrome.storage.local.get(["settings"], (data) => {
    const s = data.settings || { autoscan: true, banners: true, ai: true };
    s[key] = !s[key];
    chrome.storage.local.set({ settings: s });
    document.getElementById(`toggle-${key}`).classList.toggle("on", s[key]);
  });
}

function saveApiKey() {
  const key = document.getElementById("api-key-input").value.trim();
  if (!key) return;
  chrome.storage.local.set({ apiKey: key });

  const btn = document.querySelector(".save-btn");
  btn.textContent = "Saved ✓";
  btn.style.color = "#00ff88";
  setTimeout(() => { btn.textContent = "Save API Key"; btn.style.color = ""; }, 2000);
}

// ── Link Scanner ──────────────────────────────────────────────
async function scanLink() {
  const url = document.getElementById("link-input").value.trim();
  if (!url) return;

  const btn = document.getElementById("link-btn");
  const resultBox = document.getElementById("link-result");
  btn.disabled = true;
  btn.textContent = "...";

  chrome.runtime.sendMessage({ type: "SCAN_LINK", url }, (result) => {
    btn.disabled = false;
    btn.textContent = "Scan";
    if (!result) return;

    const cls = { safe: "verdict-safe", suspicious: "verdict-suspicious", dangerous: "verdict-dangerous" };
    const icon = { safe: "✅", suspicious: "⚠️", dangerous: "🚨" };

    resultBox.innerHTML = `
      <div class="result-verdict ${cls[result.verdict]}">
        ${icon[result.verdict]} ${result.verdict.toUpperCase()} · Risk: ${result.risk_score}/100
      </div>
      <div class="result-flags">
        ${result.flags.length
          ? result.flags.map(f => `<div class="flag-item">${f}</div>`).join("")
          : '<div class="flag-item">No threats detected.</div>'}
      </div>
    `;
    resultBox.classList.add("visible");
  });
}

// ── Email Text Scanner ────────────────────────────────────────
async function scanEmail() {
  const body = document.getElementById("email-input").value.trim();
  const sender = document.getElementById("email-sender").value.trim();
  if (!body) return;

  const btn = document.getElementById("email-btn");
  const resultBox = document.getElementById("email-result");
  btn.disabled = true;
  btn.textContent = "...";

  const linkRegex = /https?:\/\/[^\s]+/g;
  const links = body.match(linkRegex) || [];

  chrome.runtime.sendMessage({
    type: "ANALYZE_EMAIL",
    data: { subject: "Manual Scan", sender, body, links, attachments: "" }
  }, (result) => {
    btn.disabled = false;
    btn.textContent = "Analyze";
    if (!result) return;

    const clr = result.risk_score >= 70 ? "#ff3333" : result.risk_score >= 40 ? "#ffaa00" : "#00ff88";
    resultBox.innerHTML = `
      <div class="result-verdict" style="color:${clr};">
        ${result.threat_type.toUpperCase().replace("_", " ")} · ${result.risk_score}/100 risk
      </div>
      <div class="result-flags" style="margin-top:4px;">
        <div>${result.summary}</div>
        ${result.red_flags.slice(0, 5).map(f => `<div class="flag-item">${f}</div>`).join("")}
      </div>
      <div style="font-size:8px; color:var(--muted); margin-top:6px;">${result.ai_powered ? "🤖 AI-powered" : "⚙️ Heuristic"} · ${result.confidence}% confidence</div>
    `;
    resultBox.classList.add("visible");
  });
}

// ── Allow Enter key in link input ────────────────────────────
document.getElementById("link-input")?.addEventListener("keydown", e => {
  if (e.key === "Enter") scanLink();
});

// ── Init ──────────────────────────────────────────────────────
loadStats();
loadSettings();
