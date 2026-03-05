// ===============================
// SecureSurf Background Script
// Central controller for ML API calls and data management
// ===============================

const ML_API_URL = "http://localhost:5000";
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes cache

// Cache storage
const predictionCache = new Map();

// ===============================
// Extension Installation
// ===============================
chrome.runtime.onInstalled.addListener(() => {
  console.log("🛡️ SecureSurf Extension Installed");
});

// ===============================
// ML API Communication
// ===============================

/**
 * Call URL prediction API
 */
async function callUrlMLApi(url, pageText, linksCount) {
  try {
    const response = await fetch(`${ML_API_URL}/predict/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        page_text: pageText.substring(0, 1000),
        links_count: linksCount,
        return_features: true,
      }),
    });
    if (!response.ok) throw new Error(`API error: ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error("❌ ML API call failed:", error);
    return null;
  }
}

/**
 * Call email prediction API
 */
async function callEmailMLApi(subject, body, links) {
  try {
    const response = await fetch(`${ML_API_URL}/predict/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        subject,
        body: body.substring(0, 2000),
        links,
        return_features: true,
      }),
    });
    if (!response.ok) throw new Error(`API error: ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error("❌ ML API call failed:", error);
    return null;
  }
}

// ===============================
// Heuristic Scoring
// ===============================

function calculateHeuristicScore(url, pageText, linksCount) {
  let score = 0;
  const ipPattern = /(\d{1,3}\.){3}\d{1,3}/;

  // URL-based heuristics
  if (url.includes("@")) score += 20;
  if (url.includes("login") || url.includes("verify")) score += 15;
  if (url.length > 75) score += 10;

  // IP check
  if (ipPattern.test(url)) score += 25;

  if (pageText?.length > 0) {
    ["urgent", "verify", "suspend", "limited time", "click now"].forEach((word) => {
      if (pageText.toLowerCase().includes(word)) score += 10;
    });
  }

  // Too many links
  if (linksCount > 50) score += 15;

  // Subdomains
  try {
    const subdomainCount = new URL(url).hostname.split(".").length - 2;
    if (subdomainCount > 2) score += 10;
  } catch (e) {}

  return Math.min(score, 100);
}

// ===============================
// Email Heuristic Scoring
// ===============================

function calculateEmailHeuristicScore(subject, body, links) {

  const text = (subject + " " + body).toLowerCase();

  let score = 0;

  function countOccurrences(text, word) {
    const regex = new RegExp(`\\b${word}\\b`, "gi");
    const matches = text.match(regex);
    return matches ? matches.length : 0;
  }

  const urgentWords = ["urgent", "immediately", "action required", "verify", "suspend"];
  const suspiciousWords = ["password", "login", "account", "bank", "security"];

  let urgentWordCount = 0;
  let suspiciousKeywordCount = 0;

  urgentWords.forEach(word => {
    const count = countOccurrences(text, word);
    urgentWordCount += count;
  });

  suspiciousWords.forEach(word => {
    const count = countOccurrences(text, word);
    suspiciousKeywordCount += count;
  });

  score += urgentWordCount * 10;
  score += suspiciousKeywordCount * 10;

  const capitalLetters = (body.match(/[A-Z]/g) || []).length;
  const capitalRatio = capitalLetters / Math.max(body.length, 1);

  if (capitalRatio > 0.5) score += 10;

  const exclamationCount = (body.match(/!/g) || []).length;
  if (exclamationCount > 3) score += 10;

  const linkCount = links.length;
  if (linkCount > 10) score += 10;

  return {
    score: Math.min(score, 100),
    urgentWordCount,
    suspiciousKeywordCount,
    capitalRatio,
    exclamationCount,
    linkCount
  };
}
// ===============================
// Combine Scores
// ===============================

function combineScores(heuristicScore, mlResult) {
  if (!mlResult) {
    return {
      final_score: heuristicScore,
      level: getRiskLevel(heuristicScore),
      source: "heuristic-only",
    };
  }

  // Weighted combination (40% heuristic, 60% ML)
  const finalScore = heuristicScore * 0.4 + mlResult.risk_score * 0.6;

  // Use ML level if scores disagree significantly
  let finalLevel;

  finalLevel =
    Math.abs(heuristicScore - mlResult.risk_score) > 30
      ? mlResult.risk_level
      : getRiskLevel(finalScore);

  return {
    final_score: Math.round(finalScore),
    level: finalLevel,
    heuristic_score: heuristicScore,
    ml_score: mlResult.risk_score,
    ml_probability: mlResult.probability,
    source: "combined",
  };
}

function getRiskLevel(score) {
  if (score <= 30) return "Safe";
  if (score <= 60) return "Suspicious";
  return "Dangerous";
}

// ===============================
// Cache Management
// ===============================

function getCachedResult(key) {
  const cached = predictionCache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION) return cached.data;
  predictionCache.delete(key);
  return null;
}

function cacheResult(key, data) {
  predictionCache.set(key, { timestamp: Date.now(), data });
}

// ===============================
// Main Analysis
// ===============================

async function analyzeUrl(url, pageText = "", linksCount = 0) {
  console.log("🔍 Analyzing URL:", url.substring(0, 50));

  // Create cache key
  const cacheKey = `url:${url}`;

  // Check cache first
  const cached = getCachedResult(cacheKey);
  if (cached) return cached;

  // Calculate heuristic score
  const heuristicScore = calculateHeuristicScore(url, pageText, linksCount);

  // Get ML prediction
  const mlResult = await callUrlMLApi(url, pageText, linksCount);

  // Combine scores
  const result = combineScores(heuristicScore, mlResult);

  const detailedReasons = {
    hasIP: /(\d{1,3}\.){3}\d{1,3}/.test(url) ? 1 : 0,
    hasSuspiciousKeyword: /login|verify/.test(url) ? 1 : 0,
    subdomainCount: (() => {
      try { return new URL(url).hostname.split(".").length - 2; } catch { return 0; }
    })(),
    urlLength: url.length,
    hasAtSymbol: url.includes("@") ? 1 : 0,
    urgentWordCount: (pageText.match(/urgent|verify|suspend|limited time|click now/gi) || []).length,
    suspiciousKeywordCount: 0,
    capitalRatio: (pageText.match(/[A-Z]/g)?.length || 0) / Math.max(1, pageText.length),
    exclamationCount: (pageText.match(/!/g) || []).length,
    linkCount: linksCount,
    ...mlResult?.features,
  };

  const finalData = {
    final_score: result.final_score,
    level: result.level,
    heuristic_score: result.heuristic_score,
    ml_score: result.ml_score,
    ml_probability: result.ml_probability,
    source: result.source,
    detailedReasons,
  };

  cacheResult(cacheKey, finalData);
  return finalData;
}

async function analyzeEmail(subject, body, links = []) {

  console.log("🔍 Analyzing Email");

  const cacheKey = `email:${subject}:${body.substring(0,100)}`;

  const cached = getCachedResult(cacheKey);
  if (cached) return cached;

  // Email heuristic scoring
  const heuristics = calculateEmailHeuristicScore(subject, body, links);
  const heuristicScore = heuristics.score;

  // ML prediction
  const mlResult = await callEmailMLApi(subject, body, links);

  let finalScore;
  let level;

  if (!mlResult) {

    finalScore = heuristicScore;
    level = getRiskLevel(finalScore);

  } else {

    finalScore = heuristicScore * 0.4 + mlResult.risk_score * 0.6;
    level = getRiskLevel(finalScore);

  }

  const finalData = {

    final_score: Math.round(finalScore),

    level: level,

    heuristic_score: heuristicScore,

    ml_score: mlResult?.risk_score,

    ml_probability: mlResult?.probability,

    source: mlResult ? "combined" : "heuristic-only",

    detailedReasons: {

      urgentWordCount: heuristics.urgentWordCount,
      suspiciousKeywordCount: heuristics.suspiciousKeywordCount,
      capitalRatio: heuristics.capitalRatio,
      exclamationCount: heuristics.exclamationCount,
      linkCount: heuristics.linkCount,

      ...mlResult?.features
    }

  };

  cacheResult(cacheKey, finalData);

  return finalData;
}

// ===============================
// Message Handler
// ===============================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log("📨 Message received:", request.action);

  if (request.action === "analyzeUrl") {
    analyzeUrl(request.url, request.pageText, request.linksCount)
      .then((result) => {
        // Store in chrome.storage for popup to access
        chrome.storage.local.set({
          riskData: { url: request.url, score: result.final_score, level: result.level, explanation: getExplanation(result), detailedReasons: result.detailedReasons },
        });
        sendResponse({ success: true, data: result });
      })
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (request.action === "analyzeEmail") {
    analyzeEmail(request.subject, request.body, request.links)
      .then((result) => {
        // Store in chrome.storage for popup to access
        chrome.storage.local.set({
          riskData: { url: "Gmail - Email Analysis", score: result.final_score, level: result.level, explanation: getExplanation(result), detailedReasons: result.detailedReasons },
        });
        sendResponse({ success: true, data: result });
      })
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (request.action === "checkAPI") {
    fetch(`${ML_API_URL}/health`)
      .then((res) => res.json())
      .then((data) => sendResponse({ status: "ok", data }))
      .catch((err) => sendResponse({ status: "error", error: err.message }));
    return true;
  }

  if (request.action === "clearCache") {
    predictionCache.clear();
    sendResponse({ success: true });
  }
});

// ===============================
// Tab Update Listener
// ===============================

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && !tab.url.startsWith("chrome://")) {
    console.log("📍 New page loaded:", tab.url);

    // We'll let the content script trigger the analysis
    // This avoids duplicate calls
  }
});

// ===============================
// Helper Functions
// ===============================

function getExplanation(result) {
  const sourceText =
    result.source === "combined" ? "AI + Heuristic" :
    result.source === "ml-only" ? "AI Analysis" : "Heuristic only";

  if (result.level === "Safe") return `✅ No major phishing indicators detected. (${sourceText})`;
  if (result.level === "Suspicious") return `⚠️ Some phishing indicators detected. Proceed with caution. (${sourceText})`;
  return `🔴 DANGEROUS: Multiple strong phishing indicators detected! (${sourceText})`;
}