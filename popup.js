class SecurityPopup {
    constructor() {
        this.init();
    }

    async init() {
        try {
            const [tabAnalysis, pageAnalysis, stats] = await Promise.all([
                this.getTabAnalysis(),
                this.getPageAnalysis(),
                this.getAnalysisStats()
            ]);
            
            this.updateDisplay(tabAnalysis, pageAnalysis, stats);
        } catch (error) {
            console.error('Popup init error:', error);
            this.showError('Analysis failed. Please refresh the page and try again.');
        }
    }

    getTabAnalysis() {
        return new Promise((resolve) => {
            // Add timeout to prevent hanging
            const timeout = setTimeout(() => {
                resolve({
                    isSuspicious: false,
                    confidence: 0,
                    warnings: ['Analysis timeout'],
                    riskLevel: 'LOW',
                    analysisTime: 0,
                    vtData: null
                });
            }, 3000);

            chrome.runtime.sendMessage(
                {action: 'getCurrentAnalysis'},
                (response) => {
                    clearTimeout(timeout);
                    if (chrome.runtime.lastError) {
                        console.log('Background error:', chrome.runtime.lastError);
                        resolve({
                            isSuspicious: false,
                            confidence: 0,
                            warnings: ['Background service not ready'],
                            riskLevel: 'LOW',
                            analysisTime: 0
                        });
                    } else {
                        resolve(response || {
                            isSuspicious: false,
                            confidence: 0,
                            warnings: ['No analysis data'],
                            riskLevel: 'LOW',
                            analysisTime: 0
                        });
                    }
                }
            );
        });
    }

    getPageAnalysis() {
        return new Promise((resolve) => {
            // Add timeout to prevent hanging
            const timeout = setTimeout(() => {
                resolve({
                    cookies: {totalCookies: 0, insecureCookies: [], securityScore: 100},
                    overallRisk: {score: 0, level: 'LOW'},
                    scripts: {totalScripts: 0, externalScripts: 0},
                    forms: []
                });
            }, 3000);

            chrome.runtime.sendMessage(
                {action: 'getPageAnalysis'},
                (response) => {
                    clearTimeout(timeout);
                    if (chrome.runtime.lastError) {
                        console.log('Page analysis error:', chrome.runtime.lastError);
                        resolve({
                            cookies: {totalCookies: 0, insecureCookies: [], securityScore: 100},
                            overallRisk: {score: 0, level: 'LOW'},
                            scripts: {totalScripts: 0, externalScripts: 0},
                            forms: []
                        });
                    } else {
                        resolve(response || {
                            cookies: {totalCookies: 0, insecureCookies: [], securityScore: 100},
                            overallRisk: {score: 0, level: 'LOW'},
                            scripts: {totalScripts: 0, externalScripts: 0},
                            forms: []
                        });
                    }
                }
            );
        });
    }

    getAnalysisStats() {
        return new Promise((resolve) => {
            // Add timeout to prevent hanging
            const timeout = setTimeout(() => {
                resolve({
                    totalAnalyses: 0,
                    threatsFound: 0,
                    avgAnalysisTime: 0
                });
            }, 3000);

            chrome.runtime.sendMessage(
                {action: 'getAnalysisStats'},
                (response) => {
                    clearTimeout(timeout);
                    if (chrome.runtime.lastError) {
                        console.log('Stats error:', chrome.runtime.lastError);
                        resolve({
                            totalAnalyses: 0,
                            threatsFound: 0,
                            avgAnalysisTime: 0
                        });
                    } else {
                        resolve(response || {
                            totalAnalyses: 0,
                            threatsFound: 0,
                            avgAnalysisTime: 0
                        });
                    }
                }
            );
        });
    }

    updateDisplay(tabAnalysis, pageAnalysis, stats) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('content').style.display = 'block';
        
        // Update domain analysis
        this.updateDomainAnalysis(tabAnalysis);
        
        // Update cookie analysis
        this.updateCookieAnalysis(pageAnalysis.cookies);
        
        // Update security score - NOW USING ACCURATE SCORING
        this.updateSecurityScore(pageAnalysis.overallRisk);
        
        // Update statistics
        this.updateStats(stats, tabAnalysis.analysisTime);
    }

    updateDomainAnalysis(analysis) {
        document.getElementById('riskBadge').textContent = analysis.riskLevel;
        document.getElementById('riskBadge').className = `risk-badge risk-${analysis.riskLevel.toLowerCase()}`;
        document.getElementById('confidenceBar').style.width = analysis.confidence + '%';
        document.getElementById('confidenceText').textContent = analysis.confidence + '%';
        
        const warningList = document.getElementById('warningList');
        warningList.innerHTML = '';
        
        if (analysis.warnings && analysis.warnings.length > 0) {
            analysis.warnings.forEach(warning => {
                const li = document.createElement('li');
                li.className = 'warning-item';
                li.textContent = warning;
                warningList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.className = 'warning-item';
            li.style.background = '#d1edff';
            li.textContent = 'No domain threats detected';
            warningList.appendChild(li);
        }
    }

    updateCookieAnalysis(cookies) {
        const cookieList = document.getElementById('cookieList');
        const cookieSummary = document.getElementById('cookieSummary');
        
        cookieSummary.innerHTML = `Total: ${cookies.totalCookies} cookies • ` +
                                 `<span style="color: ${cookies.insecureCookies.length > 0 ? '#dc3545' : '#28a745'}">` +
                                 `${cookies.insecureCookies.length} insecure</span>`;
        
        if (cookies.insecureCookies.length > 0) {
            cookieList.innerHTML = cookies.insecureCookies.map(cookie => 
                `<div class="cookie-item">
                    <strong>${cookie.name}</strong><br>
                    <span style="color: #dc3545; font-size: 12px;">${cookie.issues.join(', ')}</span>
                </div>`
            ).join('');
        } else {
            cookieList.innerHTML = '<div style="text-align: center; color: #28a745; padding: 10px;">✅ All cookies secure</div>';
        }
    }

    updateSecurityScore(risk) {
        // NOW USING THE ACTUAL RISK SCORE (not inverted)
        const score = 100 - risk.score; // Invert for display (higher = better)
        document.getElementById('scoreCircle').style.setProperty('--score-percent', score + '%');
        document.getElementById('scoreValue').textContent = score;
        
        let levelText = 'Excellent';
        let color = '#000000';
        if (score < 70) { levelText = 'Good'; color = '#008000'; }
        if (score < 50) { levelText = 'Fair'; color = '#fd7e14'; }
        if (score < 30) { levelText = 'Poor'; color = '#dc3545'; }
        
        document.getElementById('scoreText').textContent = levelText + ' Security';
        document.getElementById('scoreText').style.color = color;
        document.getElementById('scoreValue').style.color = color;
    }

    updateStats(stats, currentAnalysisTime) {
        document.getElementById('totalAnalyses').textContent = stats.totalAnalyses;
        document.getElementById('threatsFound').textContent = stats.threatsFound;
        document.getElementById('avgTime').textContent = stats.avgAnalysisTime + 'ms';
        document.getElementById('currentTime').textContent = (currentAnalysisTime || 0) + 'ms';
    }

    showError(message) {
        document.getElementById('loading').innerHTML = 
            `<div style="color: #dc3545; text-align: center; padding: 20px;">${message}</div>`;
    }
}

document.addEventListener('DOMContentLoaded', () => new SecurityPopup());
