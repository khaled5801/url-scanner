/**
 * CyberScan Sentinel – Frontend Intelligence Module
 */

async function initiateAnalysis() {
    const urlInput = document.getElementById('urlInput').value.trim();
    const statusContainer = document.getElementById('statusContainer');
    const intelligenceReport = document.getElementById('intelligenceReport');
    const analyzeBtn = document.getElementById('analyzeBtn');

    // Clear previous messages
    statusContainer.innerHTML = '';
    intelligenceReport.classList.remove('active');

    // Validate input
    if (!urlInput) {
        displayError(statusContainer, 'Please enter a URL to analyze.');
        return;
    }

    // Disable button and show loading state
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = 'Analyzing...';
    analyzeBtn.style.opacity = '0.6';

    try {
        // Call backend API
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: urlInput })
        });

        const result = await response.json();

        if (!result.success) {
            displayError(statusContainer, result.error);
            return;
        }

        // Populate intelligence report
        const report = result.intelligence_report;
        renderIntelligenceReport(report, statusContainer);
        
        // Show report with animation
        intelligenceReport.classList.add('active');

    } catch (error) {
        displayError(statusContainer, `Network error: ${error.message}`);
    } finally {
        // Re-enable button
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = 'Initiate Threat Analysis';
        analyzeBtn.style.opacity = '1';
    }
}

function displayError(container, message) {
    container.innerHTML = `<div class="error-banner">${escapeHtml(message)}</div>`;
}

function displaySuccess(container, message) {
    container.innerHTML = `<div class="success-banner">${escapeHtml(message)}</div>`;
}

function renderIntelligenceReport(report, statusContainer) {
    const threatLevel = report.threat_level || 'UNKNOWN';
    const threatElement = document.getElementById('threatLevel');
    threatElement.className = `threat-indicator threat-${threatLevel.toLowerCase()}`;
    threatElement.textContent = threatLevel;

    // Update stats
    document.getElementById('hopCount').textContent = report.summary.total_hops;
    document.getElementById('vendorCount').textContent = report.summary.vendors_checked;
    document.getElementById('maliciousCount').textContent = report.summary.malicious_detections;
    document.getElementById('riskScore').textContent = report.summary.static_risk_score;

    // Update final URL
    document.getElementById('finalUrl').textContent = report.redirection_chain.final_url;

    // Render redirection chain
    renderRedirectionChain(report.redirection_chain);

    // Render VirusTotal analysis
    renderVirusTotalAnalysis(report.virustotal_analysis);

    // Render static analysis
    renderStaticAnalysis(report.static_analysis);

    // Render screenshot
    renderScreenshot(report.screenshot);

    // Display success message
    displaySuccess(statusContainer, 'Analysis completed successfully. Review the intelligence report below.');
}

function renderRedirectionChain(chain) {
    const chainContainer = document.getElementById('redirectionChain');
    
    if (chain.error) {
        chainContainer.innerHTML = `<div class="error-banner">Redirection tracking error: ${escapeHtml(chain.error)}</div>`;
        return;
    }

    if (!chain.chain || chain.chain.length === 0) {
        chainContainer.innerHTML = '<div class="no-findings">No redirection detected. URL is final destination.</div>';
        return;
    }

    let html = '';
    chain.chain.forEach((hop, index) => {
        html += `
            <div class="chain-item">
                <div class="chain-item-hop">Hop ${hop.hop}</div>
                <div class="chain-item-url">${escapeHtml(hop.url)}</div>
                <div style="color: #9ca3af; font-size: 10px; margin-top: 4px;">
                    Status: ${hop.status_code} | ${new Date(hop.timestamp).toLocaleTimeString()}
                </div>
            </div>
        `;
    });

    chainContainer.innerHTML = html;
}

function renderVirusTotalAnalysis(vt) {
    const container = document.getElementById('virustotalAnalysis');

    if (vt.error) {
        container.innerHTML = `<div class="error-banner">${escapeHtml(vt.error)}</div>`;
        return;
    }

    const html = `
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="stat-card">
                <div class="stat-value">${vt.vendors_checked}</div>
                <div class="stat-label">Total Vendors</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #fca5a5;">${vt.malicious}</div>
                <div class="stat-label">Malicious</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #fed7aa;">${vt.suspicious}</div>
                <div class="stat-label">Suspicious</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #a7f3d0;">${vt.harmless}</div>
                <div class="stat-label">Harmless</div>
            </div>
        </div>
    `;

    container.innerHTML = html;
}

function renderStaticAnalysis(analysis) {
    const container = document.getElementById('staticAnalysis');

    if (analysis.error) {
        container.innerHTML = `<div class="error-banner">${escapeHtml(analysis.error)}</div>`;
        return;
    }

    let html = `
        <div style="margin-bottom: 16px;">
            <div class="stat-card">
                <div class="stat-value" style="color: #fbbf24;">${analysis.risk_score}</div>
                <div class="stat-label">Risk Score (0-100)</div>
            </div>
        </div>
    `;

    // Obfuscated code
    if (analysis.obfuscated_code.length > 0) {
        html += '<div style="margin-bottom: 12px;"><div style="color: #f97316; font-size: 11px; font-weight: 600; margin-bottom: 6px;">⚠ Obfuscated Code Detected</div>';
        analysis.obfuscated_code.forEach(code => {
            html += `<div class="finding-item">${escapeHtml(code)}</div>`;
        });
        html += '</div>';
    }

    // Hidden iframes
    if (analysis.hidden_iframes.length > 0) {
        html += '<div style="margin-bottom: 12px;"><div style="color: #f97316; font-size: 11px; font-weight: 600; margin-bottom: 6px;">⚠ Hidden Iframes Detected</div>';
        analysis.hidden_iframes.forEach(iframe => {
            html += `<div class="finding-item">${escapeHtml(iframe)}</div>`;
        });
        html += '</div>';
    }

    // Auto-download
    if (analysis.auto_download.length > 0) {
        html += '<div style="margin-bottom: 12px;"><div style="color: #f97316; font-size: 11px; font-weight: 600; margin-bottom: 6px;">⚠ Auto-Download Behavior Detected</div>';
        analysis.auto_download.forEach(download => {
            html += `<div class="finding-item">${escapeHtml(download)}</div>`;
        });
        html += '</div>';
    }

    // Suspicious scripts
    if (analysis.suspicious_scripts.length > 0) {
        html += '<div style="margin-bottom: 12px;"><div style="color: #f97316; font-size: 11px; font-weight: 600; margin-bottom: 6px;">⚠ Suspicious Scripts Detected</div>';
        analysis.suspicious_scripts.forEach(script => {
            html += `<div class="finding-item">${escapeHtml(script)}</div>`;
        });
        html += '</div>';
    }

    if (analysis.obfuscated_code.length === 0 && 
        analysis.hidden_iframes.length === 0 && 
        analysis.auto_download.length === 0 && 
        analysis.suspicious_scripts.length === 0) {
        html += '<div class="no-findings">No malicious code patterns detected in static analysis.</div>';
    }

    container.innerHTML = html;
}

function renderScreenshot(screenshot) {
    const container = document.getElementById('screenshotContainer');

    if (!screenshot.success) {
        container.innerHTML = `<div class="screenshot-container"><div class="screenshot-fallback">Screenshot unavailable: ${escapeHtml(screenshot.error)}</div></div>`;
        return;
    }

    container.innerHTML = `
        <div class="screenshot-container">
            <img src="${escapeHtml(screenshot.screenshot_url)}" alt="Website Preview" class="screenshot-image">
        </div>
        <div style="color: #6b7280; font-size: 11px; margin-top: 8px; text-align: center;">
            Safe-Zone Sandbox Preview – No client-side code execution
        </div>
    `;
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Allow Enter key to trigger analysis
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('urlInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            initiateAnalysis();
        }
    });
});
