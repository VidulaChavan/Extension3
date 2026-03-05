// ===============================
// SecureSurf Popup Script
// Screen 1: Risk Scorecard Dashboard
// ===============================

document.addEventListener("DOMContentLoaded", () => {
  // -------------------------------
  // DOM Elements
  // -------------------------------
  const elements = {
    closeBtn: document.getElementById("closePopup"),
    currentUrl: document.getElementById("currentUrl"),
    ipAddress: document.getElementById("ipAddress"),
    riskScore: document.getElementById("riskScore"),
    progressBar: document.getElementById("progressBar"),
    statusBadge: document.getElementById("statusBadge"),
    statusText: document.getElementById("statusText"),
    flagsList: document.getElementById("flagsList"),
    flagsSection: document.getElementById("flagsSection"),
    highlightBtn: document.getElementById("highlightBtn"),
    whyRiskyBtn: document.getElementById("whyRiskyBtn"),
    breakdownBtn: document.getElementById("breakdownBtn"),
    breakdownModal: document.getElementById("breakdownModal"),
    breakdownContent: document.getElementById("breakdownContent"),
    closeModalBtn: document.getElementById("closeModal"),
    apiStatus: document.getElementById("apiStatus"),
    apiStatusText: document.getElementById("apiStatusText"),
  };
// ===============================
// Risk Score Breakdown Button
// ===============================

document.getElementById("breakdownBtn")?.addEventListener("click", () => {
  console.log("📊 Breakdown button clicked");

  chrome.tabs.create({
    url: chrome.runtime.getURL("frontend/popup/breakdown.html")
  });
});
  // ===============================
  // Close Popup
  // ===============================
  elements.closeBtn.addEventListener("click", () => window.close());

  // ===============================
  // Get Risk Data from Storage
  // ===============================
  chrome.storage.local.get("riskData", ({ riskData }) => {
    if (!riskData) {
      showNoData();
      return;
    }

    console.log("📊 Risk Data:", riskData);
    updateUI(riskData);
  });

  // ===============================
  // Update UI with Risk Data
  // ===============================
  function updateUI(riskData) {
    // Update URL
    elements.currentUrl.textContent = riskData.url || "No URL";

    // Extract IP if present (simplified - in production, parse from URL)
    const ipMatch = riskData.url?.match(/(\d{1,3}\.){3}\d{1,3}/);
    elements.ipAddress.textContent = ipMatch ? `IP: ${ipMatch[0]}` : "";

    // Update Risk Score
    const score = riskData.score || 0;
    elements.riskScore.textContent = `${Math.round(score)}/100`;
    elements.progressBar.style.width = `${score}%`;

    // Set progress bar color based on score
    elements.progressBar.className = "progress-bar";
    if (score < 30) {
      elements.progressBar.classList.add("safe");
      elements.statusBadge.className = "status-badge safe";
      elements.statusText.textContent = "✅ Safe";
    } else if (score < 60) {
      elements.progressBar.classList.add("suspicious");
      elements.statusBadge.className = "status-badge suspicious";
      elements.statusText.textContent = "⚠️ Suspicious";
    } else {
      elements.progressBar.classList.add("dangerous");
      elements.statusBadge.className = "status-badge dangerous";
      elements.statusText.textContent = "🔴 Dangerous";
    }

    // Update Flags List
    updateFlagsList(riskData.detailedReasons);

    // Check API Status
    checkAPIStatus();
  }

  // ===============================
  // Flags
  // ===============================
  function updateFlagsList(reasons) {
    if (!reasons) {
      elements.flagsSection.style.display = "none";
      return;
    }

    const flags = generateFlags(reasons);

    if (flags.length === 0) {
      elements.flagsSection.style.display = "none";
      return;
    }

    elements.flagsSection.style.display = "block";
    elements.flagsList.innerHTML = flags
      .map(
        (flag) => `
        <div class="flag-item">
          <span class="flag-icon">🚩</span>
          <span class="flag-text">${flag}</span>
        </div>
      `
      )
      .join("");
  }

  // ===============================
  // Generate Flags from Reasons
  // ===============================
  function generateFlags(reasons) {
    const flags = [];
    if (reasons.hasIP) flags.push("IP-based URL detected");
    if (reasons.hasSuspiciousKeyword) flags.push("Suspicious keyword detected");
    if (reasons.subdomainCount > 2) flags.push(`Excessive subdomains (${reasons.subdomainCount})`);
    if (reasons.urlLength > 75) flags.push("Unusually long URL");
    if (reasons.hasAtSymbol) flags.push("URL contains @ symbol");
    if (reasons.urgentWordCount > 0) flags.push(`Urgent language detected (${reasons.urgentWordCount} words)`);
    if (reasons.suspiciousKeywordCount > 0) flags.push(`Suspicious keywords (${reasons.suspiciousKeywordCount})`);
    if (reasons.capitalRatio > 0.5) flags.push("Excessive capitalization");
    if (reasons.exclamationCount > 3) flags.push(`Multiple exclamation marks (${reasons.exclamationCount})`);
    if (reasons.linkCount > 10) flags.push(`Too many links (${reasons.linkCount})`);
    return flags;
  }

  // ===============================
  // Show No Data State
  // ===============================
  function showNoData() {
    elements.currentUrl.textContent = "No active scan";
    elements.riskScore.textContent = "--/100";
    elements.progressBar.style.width = "0%";
    elements.statusBadge.className = "status-badge";
    elements.statusText.textContent = "No Data";
    elements.flagsSection.style.display = "none";
  }

  // ===============================
  // Check API Status
  // ===============================
  function checkAPIStatus() {
    chrome.runtime.sendMessage({ action: "checkAPI" }, (response) => {
      if (response?.status === "ok") {
        elements.apiStatus.className = "api-status online";
        elements.apiStatusText.textContent = "🟢 ML API Connected";
      } else {
        elements.apiStatus.className = "api-status offline";
        elements.apiStatusText.textContent = "🔴 ML API Offline (Using Rules Only)";
      }
    });
  }

  // ===============================
  // Highlight / Why Risky Buttons
  // ===============================
  elements.highlightBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      chrome.tabs.sendMessage(tabs[0].id, { action: "toggleHighlights" });
    });
  });

  // ===============================
  // Why is this risky? Button
  // ===============================
  elements.whyRiskyBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      chrome.tabs.sendMessage(tabs[0].id, { action: "showEducational" }, (res) => {
        if (chrome.runtime.lastError) alert("Please open a webpage first to see risk analysis.");
      });
    });
  });

  // ===============================
  // ------------------------------
  // STRICTLY ADD BREAKDOWN LOGIC BELOW
  // ------------------------------
  // Nothing else touched. Original scanning + UI intact
  // ===============================

  elements.breakdownBtn.addEventListener("click", () => {
    chrome.storage.local.get("riskData", ({ riskData }) => {
      if (!riskData || !riskData.detailedReasons) {
        elements.breakdownContent.textContent = "No detailed breakdown available.";
      } else {
        const r = riskData.detailedReasons;
        const breakdownLines = [];

        if (r.hasIP) breakdownLines.push(`IP-based URL: Yes`);
        if (r.hasSuspiciousKeyword) breakdownLines.push(`Suspicious keyword in URL: Yes`);
        if (r.subdomainCount > 2) breakdownLines.push(`Subdomain count: ${r.subdomainCount}`);
        if (r.urlLength > 75) breakdownLines.push(`URL length: ${r.urlLength}`);
        if (r.hasAtSymbol) breakdownLines.push(`Contains @ symbol: Yes`);
        if (r.urgentWordCount > 0) breakdownLines.push(`Urgent words in email: ${r.urgentWordCount}`);
        if (r.suspiciousKeywordCount > 0) breakdownLines.push(`Suspicious keywords in email: ${r.suspiciousKeywordCount}`);
        if (r.capitalRatio > 0.5) breakdownLines.push(`Capital letters ratio: ${r.capitalRatio}`);
        if (r.exclamationCount > 3) breakdownLines.push(`Exclamation marks: ${r.exclamationCount}`);
        if (r.linkCount > 10) breakdownLines.push(`Link count: ${r.linkCount}`);

        for (let i = 11; i <= 17; i++) {
          if (r["feature" + i]) breakdownLines.push(`Feature ${i}: ${r["feature" + i]}`);
        }

        elements.breakdownContent.textContent =
          breakdownLines.length > 0 ? breakdownLines.join("\n") : "No significant features caused the risk.";

        elements.breakdownModal.style.display = "block";
      }
    });
  });

  elements.closeModalBtn.addEventListener("click", () => {
    elements.breakdownModal.style.display = "none";
  });

  window.addEventListener("click", (event) => {
    if (event.target === elements.breakdownModal) {
      elements.breakdownModal.style.display = "none";
    }
  });

  // ===============================
  // Listen for Updates from Background
  // ===============================
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.riskData) updateUI(changes.riskData.newValue);
  });
});
