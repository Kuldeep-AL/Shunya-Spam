// ============================================================
// Shunya Spam - Content Script
// Injected into Gmail & Outlook to extract and analyze emails
// ============================================================

let lastAnalyzedEmail = null;
let analysisInProgress = false;

// ── Email Extractors ─────────────────────────────────────────

function extractGmailData() {
  try {
    const subject = document.querySelector('h2[data-legacy-thread-id], .hP')?.textContent?.trim() || "";
    const sender = document.querySelector('.gD')?.getAttribute("email") || 
                   document.querySelector('.go')?.textContent?.trim() || "";
    const body = document.querySelector('.a3s.aiL')?.textContent?.trim() || 
                 document.querySelector('[data-message-id] .ii.gt')?.textContent?.trim() || "";
    
    const links = Array.from(document.querySelectorAll('.a3s a[href]'))
      .map(a => a.href)
      .filter(h => h.startsWith("http"));

    const attachments = Array.from(document.querySelectorAll('.aZo, .aQH'))
      .map(el => el.textContent.trim())
      .filter(Boolean);

    return { subject, sender, body, links, attachments: attachments.join(", ") };
  } catch (e) {
    return null;
  }
}

function extractOutlookData() {
  try {
    const subject = document.querySelector('[aria-label*="Subject"] span, .allowTextSelection')?.textContent?.trim() || "";
    const sender = document.querySelector('.XHRZb span, [class*="sender"]')?.textContent?.trim() || "";
    const body = document.querySelector('[role="main"] [aria-label] p, .ReadMsgBody')?.textContent?.trim() || "";
    
    const links = Array.from(document.querySelectorAll('[role="main"] a[href]'))
      .map(a => a.href)
      .filter(h => h.startsWith("http"));

    return { subject, sender, body, links, attachments: "" };
  } catch (e) {
    return null;
  }
}

function extractEmailData() {
  const host = window.location.hostname;
  if (host.includes("mail.google.com")) return extractGmailData();
  if (host.includes("outlook")) return extractOutlookData();
  return null;
}

// ── Banner Injection ─────────────────────────────────────────

function removeBanner() {
  document.querySelectorAll(".shunya-banner").forEach(el => el.remove());
}

function injectBanner(result) {
  removeBanner();

  const colors = {
    safe: { bg: "#0d1f1a", border: "#00ff88", text: "#00ff88", badge: "#003d1f" },
    spam: { bg: "#1f1800", border: "#ffaa00", text: "#ffaa00", badge: "#3d2800" },
    phishing: { bg: "#1f0000", border: "#ff3333", text: "#ff4444", badge: "#3d0000" },
    malware: { bg: "#1a001f", border: "#cc44ff", text: "#cc44ff", badge: "#2d0040" },
    scam: { bg: "#1f0a00", border: "#ff6600", text: "#ff6600", badge: "#3d1500" },
    social_engineering: { bg: "#1f0a00", border: "#ff6600", text: "#ff6600", badge: "#3d1500" },
  };

  const c = colors[result.threat_type] || colors.safe;
  const icon = { safe: "✅", spam: "⚠️", phishing: "🚨", malware: "☠️", scam: "🎭", social_engineering: "🎭" };
  const actionLabel = {
    safe_to_open: "Safe to Open",
    mark_as_spam: "Mark as Spam",
    delete_immediately: "Delete Immediately",
    report_phishing: "Report Phishing"
  };

  const banner = document.createElement("div");
  banner.className = "shunya-banner";
  banner.innerHTML = `
    <div class="shunya-inner">
      <div class="shunya-header">
        <span class="shunya-icon">${icon[result.threat_type] || "🛡️"}</span>
        <div class="shunya-title-group">
          <span class="shunya-title">SHUNYA SPAM</span>
          <span class="shunya-badge">${result.threat_type.toUpperCase().replace("_", " ")}</span>
        </div>
        <div class="shunya-risk">
          <span class="shunya-score">${result.risk_score}</span>
          <span class="shunya-score-label">RISK</span>
        </div>
        <button class="shunya-close" onclick="this.closest('.shunya-banner').remove()">✕</button>
      </div>
      <div class="shunya-body">
        <p class="shunya-summary">${result.summary}</p>
        ${result.red_flags.length > 0 ? `
          <div class="shunya-flags">
            ${result.red_flags.slice(0, 4).map(f => `<span class="shunya-flag">⚡ ${f}</span>`).join("")}
          </div>` : ""}
        <div class="shunya-footer">
          <span class="shunya-action">→ ${actionLabel[result.recommended_action] || result.recommended_action}</span>
          <span class="shunya-ai">${result.ai_powered ? "🤖 AI-Powered" : "⚙️ Heuristic"} · ${result.confidence}% confidence</span>
        </div>
      </div>
    </div>
  `;

  // Inject CSS variables for this banner
  banner.style.cssText = `
    --sh-bg: ${c.bg};
    --sh-border: ${c.border};
    --sh-text: ${c.text};
    --sh-badge: ${c.badge};
  `;

  // Find best injection point
  const targets = [
    document.querySelector('.adn.ads'), // Gmail
    document.querySelector('[role="main"]'), // Outlook
    document.querySelector('.ii.gt'), // Gmail fallback
    document.body
  ];

  const target = targets.find(Boolean);
  if (target) target.insertBefore(banner, target.firstChild);
}

// ── Main Analysis Trigger ────────────────────────────────────

async function analyzeCurrentEmail() {
  if (analysisInProgress) return;

  const emailData = extractEmailData();
  if (!emailData || !emailData.subject) return;

  // Skip if same email
  const fingerprint = `${emailData.subject}::${emailData.sender}`;
  if (fingerprint === lastAnalyzedEmail) return;
  lastAnalyzedEmail = fingerprint;

  analysisInProgress = true;

  // Show loading banner
  const loadBanner = document.createElement("div");
  loadBanner.className = "shunya-banner shunya-loading";
  loadBanner.innerHTML = `
    <div class="shunya-inner">
      <div class="shunya-header">
        <span class="shunya-spinner">◐</span>
        <span class="shunya-title">SHUNYA SPAM — Analyzing email security...</span>
      </div>
    </div>
  `;
  document.querySelector('.adn.ads, [role="main"], body')?.insertBefore(loadBanner, null);

  try {
    const result = await chrome.runtime.sendMessage({
      type: "ANALYZE_EMAIL",
      data: emailData
    });

    loadBanner.remove();
    if (result) injectBanner(result);
  } catch (err) {
    loadBanner.remove();
    console.error("Shunya analysis error:", err);
  }

  analysisInProgress = false;
}

// ── Mutation Observer ────────────────────────────────────────
// Watches for email open events in Gmail/Outlook (SPAs)

let debounceTimer;
const observer = new MutationObserver(() => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    const isEmailOpen = document.querySelector('.adn.ads, .ii.gt, [role="main"] .allowTextSelection');
    if (isEmailOpen) analyzeCurrentEmail();
  }, 800);
});

observer.observe(document.body, { childList: true, subtree: true });

// Initial check
setTimeout(analyzeCurrentEmail, 2000);

console.log("🛡️ Shunya Spam content script loaded on", window.location.hostname);
