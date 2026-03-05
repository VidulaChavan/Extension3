document.addEventListener("DOMContentLoaded", () => {
  const breakdownList = document.getElementById("breakdownList");
  const closeBtn = document.getElementById("closeBreakdown");

  // Get the risk data from storage
  chrome.storage.local.get("riskData", ({ riskData }) => {
    if (!riskData || !riskData.detailedReasons) {
      breakdownList.textContent = "No detailed breakdown available.";
      return;
    }

    const r = riskData.detailedReasons;
    let txt = "";
    txt += `1. IP-based URL: ${r.hasIP ? "Yes" : "No"}\n`;
    txt += `2. Suspicious keyword in URL: ${r.hasSuspiciousKeyword ? "Yes" : "No"}\n`;
    txt += `3. Subdomain count: ${r.subdomainCount || 0}\n`;
    txt += `4. URL length: ${r.urlLength || 0}\n`;
    txt += `5. Contains @ symbol: ${r.hasAtSymbol ? "Yes" : "No"}\n`;
    txt += `6. Urgent words in email: ${r.urgentWordCount || 0}\n`;
    txt += `7. Suspicious keywords in email: ${r.suspiciousKeywordCount || 0}\n`;
    txt += `8. Capital letters ratio: ${r.capitalRatio || 0}\n`;
    txt += `9. Exclamation marks: ${r.exclamationCount || 0}\n`;
    txt += `10. Link count: ${r.linkCount || 0}\n`;
    for (let i = 11; i <= 17; i++) {
      txt += `${i}. Feature ${i}: ${r["feature" + i] || "N/A"}\n`;
    }

    breakdownList.textContent = txt;
  });

  // Close the popup window
  closeBtn.addEventListener("click", () => {
    window.close();
  });
});