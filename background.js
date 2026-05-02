// ============================================================
// Shunya Spam - Background Service Worker
// Handles AI-powered analysis using Claude API
// ============================================================

const ANTHROPIC_API_KEY = "YOUR_ANTHROPIC_API_KEY_HERE"; // Replace with your key
const MODEL = "claude-sonnet-4-20250514";

// ── Threat Intelligence Database (offline heuristics) ───────
const KNOWN_MALICIOUS_PATTERNS = [
  /paypa1\.com/i, /amaz0n\.com/i, /g00gle\.com/i,
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // raw IPs
  /bit\.ly|tinyurl|goo\.gl|t\.co\/[a-z0-9]+$/i,
  /free.*prize|you.*won|click.*here.*urgent/i,
];

const PHISHING_KEYWORDS = [
  "verify your account", "suspended account", "update your payment",
  "confirm your identity", "unusual sign-in", "click here immediately",
  "limited time offer", "you have been selected", "claim your reward",
  "act now", "expires today", "final warning", "security alert",
  "your account has been compromised", "unauthorized access detected"
];

const SPAM_KEYWORDS = [
  "buy now", "free offer", "make money fast", "work from home",
  "100% free", "no credit card", "million dollars", "lottery winner",
  "nigerian prince", "inheritance", "wire transfer", "bitcoin doubler"
];

// ── Risk Score Calculator ────────────────────────────────────
function calculateOfflineRiskScore(data) {
  let score = 0;
  const reasons = [];

  // Check links for malicious patterns
  if (data.links && data.links.length > 0) {
    for (const link of data.links) {
      for (const pattern of KNOWN_MALICIOUS_PATTERNS) {
        if (pattern.test(link)) {
          score += 25;
          reasons.push(`Suspicious link pattern: ${link.substring(0, 50)}`);
          break;
        }
      }
    }
    // Too many links = possible spam
    if (data.links.length > 10) {
      score += 10;
      reasons.push("Excessive number of links");
    }
  }

  // Check content for phishing keywords
  const lowerContent = (data.body || "").toLowerCase();
  for (const keyword of PHISHING_KEYWORDS) {
    if (lowerContent.includes(keyword)) {
      score += 15;
      reasons.push(`Phishing phrase detected: "${keyword}"`);
    }
  }

  // Check for spam keywords
  for (const keyword of SPAM_KEYWORDS) {
    if (lowerContent.includes(keyword)) {
      score += 10;
      reasons.push(`Spam phrase detected: "${keyword}"`);
    }
  }

  // Subject line checks
  const subject = (data.subject || "").toLowerCase();
  if (/urgent|immediate|alert|warning|suspended/i.test(subject)) {
    score += 10;
    reasons.push("Urgency tactics in subject line");
  }
  if (/\$\d+|free|won|prize|reward/i.test(subject)) {
    score += 15;
    reasons.push("Reward/money bait in subject");
  }

  // Sender domain checks
  if (data.sender) {
    const domain = data.sender.split("@")[1] || "";
    if (/\d{4,}/.test(domain)) {
      score += 20;
      reasons.push("Suspicious sender domain with excessive numbers");
    }
    if (domain.split(".").length > 3) {
      score += 10;
      reasons.push("Deeply nested suspicious domain");
    }
  }

  return { score: Math.min(score, 100), reasons };
}

// ── Claude AI Deep Analysis ──────────────────────────────────
async function analyzeWithClaude(emailData) {
  const prompt = `You are Shunya Spam, an expert cybersecurity AI. Analyze this email and return ONLY a JSON object.

Email Data:
- Subject: ${emailData.subject || "N/A"}
- Sender: ${emailData.sender || "N/A"}  
- Body Preview: ${(emailData.body || "").substring(0, 1000)}
- Links Found: ${(emailData.links || []).join(", ") || "None"}
- Attachments: ${emailData.attachments || "None"}

Return ONLY this JSON (no markdown, no explanation):
{
  "threat_type": "safe|spam|phishing|malware|social_engineering|scam",
  "confidence": 0-100,
  "risk_score": 0-100,
  "summary": "one sentence explanation",
  "red_flags": ["flag1", "flag2"],
  "recommended_action": "safe_to_open|mark_as_spam|delete_immediately|report_phishing",
  "explanation": "2-3 sentence detailed analysis"
}`;

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 500,
        messages: [{ role: "user", content: prompt }]
      })
    });

    if (!response.ok) throw new Error(`API Error: ${response.status}`);
    
    const data = await response.json();
    const text = data.content[0].text.trim();
    const clean = text.replace(/```json|```/g, "").trim();
    return JSON.parse(clean);
  } catch (err) {
    console.error("Claude analysis failed:", err);
    return null;
  }
}

// ── Link Scanner ─────────────────────────────────────────────
async function scanLink(url) {
  let riskScore = 0;
  const flags = [];

  // Check against offline patterns
  for (const pattern of KNOWN_MALICIOUS_PATTERNS) {
    if (pattern.test(url)) {
      riskScore += 35;
      flags.push("Matches known malicious URL pattern");
    }
  }

  // Protocol checks
  if (url.startsWith("http://") && !url.includes("localhost")) {
    riskScore += 15;
    flags.push("Unencrypted HTTP connection");
  }

  // URL shortener
  if (/bit\.ly|tinyurl|goo\.gl|ow\.ly|short\.link/i.test(url)) {
    riskScore += 20;
    flags.push("URL shortener hides real destination");
  }

  // Punycode/homograph attack
  if (/xn--/.test(url)) {
    riskScore += 40;
    flags.push("Possible homograph/punycode attack");
  }

  // Excessive subdomains
  try {
    const domain = new URL(url).hostname;
    if (domain.split(".").length > 4) {
      riskScore += 15;
      flags.push("Suspicious deeply nested subdomain");
    }
  } catch (_) {}

  return {
    url,
    risk_score: Math.min(riskScore, 100),
    flags,
    verdict: riskScore >= 70 ? "dangerous" : riskScore >= 40 ? "suspicious" : "safe"
  };
}

// ── Message Listener ─────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_EMAIL") {
    handleEmailAnalysis(message.data).then(sendResponse);
    return true; // async response
  }

  if (message.type === "SCAN_LINK") {
    scanLink(message.url).then(sendResponse);
    return true;
  }

  if (message.type === "GET_STATS") {
    chrome.storage.local.get(["stats"], (result) => {
      sendResponse(result.stats || { scanned: 0, blocked: 0, phishing: 0, spam: 0 });
    });
    return true;
  }
});

async function handleEmailAnalysis(emailData) {
  // Step 1: Fast offline analysis
  const offline = calculateOfflineRiskScore(emailData);

  // Step 2: AI deep analysis (if API key is set)
  let aiResult = null;
  if (ANTHROPIC_API_KEY !== "YOUR_ANTHROPIC_API_KEY_HERE") {
    aiResult = await analyzeWithClaude(emailData);
  }

  // Step 3: Combine results
  const finalRisk = aiResult
    ? Math.round((offline.score * 0.4) + (aiResult.risk_score * 0.6))
    : offline.score;

  const result = {
    risk_score: finalRisk,
    threat_type: aiResult?.threat_type || (finalRisk > 60 ? "phishing" : finalRisk > 30 ? "spam" : "safe"),
    confidence: aiResult?.confidence || 70,
    summary: aiResult?.summary || (finalRisk > 60 ? "High-risk email detected" : finalRisk > 30 ? "Potential spam detected" : "Email appears safe"),
    red_flags: [...offline.reasons, ...(aiResult?.red_flags || [])],
    recommended_action: aiResult?.recommended_action || (finalRisk > 60 ? "delete_immediately" : finalRisk > 30 ? "mark_as_spam" : "safe_to_open"),
    explanation: aiResult?.explanation || "Analysis based on heuristic patterns.",
    ai_powered: !!aiResult
  };

  // Update stats
  chrome.storage.local.get(["stats"], (data) => {
    const stats = data.stats || { scanned: 0, blocked: 0, phishing: 0, spam: 0 };
    stats.scanned++;
    if (result.threat_type === "phishing") stats.phishing++;
    if (result.threat_type === "spam") stats.spam++;
    if (finalRisk > 60) stats.blocked++;
    chrome.storage.local.set({ stats });
  });

  return result;
}

console.log("🛡️ Shunya Spam background worker active");
