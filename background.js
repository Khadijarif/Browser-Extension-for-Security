// Background script for Security Sentinel with VirusTotal integration

const VIRUSTOTAL_API_KEY = 'Add_Your_Own_API';
const ANALYSIS_HISTORY_KEY = 'analysisHistory';

// Simple PhishingDetector for background script
class PhishingDetector {
    constructor() {
        this.suspiciousPatterns = [
            /login\.(?!google|microsoft|facebook|apple)/i,
            /verify-?account/i,
            /security-?update/i,
            /password-?reset/i,
            /banking-?login/i,
            /paypal.*security/i,
            /amazon.*verify/i
        ];
        this.suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq'];
        this.knownPhishingDomains = [
            'faceb00k-login.com', 'paypa1-secure.com', 'apple-verify.net',
            'google-security-update.com', 'microsoft-account-verify.com'
        ];
    }
    analyzeUrl(url) {
        const results = { isSuspicious: false, confidence: 0, warnings: [] };
        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname;
            const path = urlObj.pathname.toLowerCase();
            
            if (this.knownPhishingDomains.some(phish => domain.includes(phish))) {
                results.isSuspicious = true;
                results.confidence = 90;
                results.warnings.push(`Known phishing domain`);
            }
            if (this.suspiciousTlds.some(tld => domain.endsWith(tld))) {
                results.isSuspicious = true;
                results.confidence += 30;
                results.warnings.push('Suspicious domain extension');
            }
            this.suspiciousPatterns.forEach((pattern) => {
                if (pattern.test(url) || pattern.test(path)) {
                    results.isSuspicious = true;
                    results.confidence += 20;
                    results.warnings.push(`Suspicious pattern`);
                }
            });
            results.confidence = Math.min(results.confidence, 100);
        } catch (error) {
            console.error('Error analyzing URL:', error);
        }
        return results;
    }
}

// Simple StorageHelper for background script
class StorageHelper {
    static async get(key) {
        return new Promise((resolve) => {
            chrome.storage.local.get([key], (result) => {
                resolve(result[key]);
            });
        });
    }
    static async set(key, value) {
        return new Promise((resolve) => {
            chrome.storage.local.set({ [key]: value }, () => {
                resolve();
            });
        });
    }
}

// Store current analysis
let currentTabAnalysis = {};

// Initialize analysis history on first load
chrome.runtime.onStartup.addListener(async () => {
    const history = await StorageHelper.get(ANALYSIS_HISTORY_KEY);
    if (!history) {
        await StorageHelper.set(ANALYSIS_HISTORY_KEY, []);
    }
});

// VirusTotal API function
async function performVirusTotalAnalysis(domain) {
    try {
        console.log('🔍 Checking VirusTotal for:', domain);
        
        // Check cache first
        const cached = await getCachedVTAnalysis(domain);
        if (cached) {
            console.log('✅ Using cached VT data for:', domain);
            return cached;
        }
        
        console.log('🌐 Making VT API call for:', domain);
        const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
            headers: {
                'x-apikey': VIRUSTOTAL_API_KEY
            }
        });
        
        if (!response.ok) {
            throw new Error(`VT API error: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('📊 VT API response received');
        
        const stats = data.data.attributes.last_analysis_stats;
        const analysis = {
            detections: stats.malicious,
            total: stats.harmless + stats.malicious + stats.suspicious + stats.undetected,
            reputation: data.data.attributes.reputation || 0
        };
        
        let vtConfidence = 0;
        let vtWarnings = [];
        
        // Calculate confidence based on VT results
        if (analysis.detections > 0) {
            vtConfidence = Math.min(analysis.detections * 15, 60);
            vtWarnings.push(`🚨 VirusTotal: ${analysis.detections}/${analysis.total} vendors flagged this as malicious`);
        }
        
        if (analysis.reputation < 0) {
            vtConfidence += 20;
            vtWarnings.push(`⚠️ VirusTotal: Poor reputation score (${analysis.reputation})`);
        }
        
        const result = {
            confidence: vtConfidence,
            warnings: vtWarnings,
            detections: analysis.detections,
            total: analysis.total,
            reputation: analysis.reputation
        };
        
        // Cache the result
        await cacheVTAnalysis(domain, result);
        console.log('✅ VT analysis completed:', result);
        
        return result;
        
    } catch (error) {
        console.log('❌ VirusTotal analysis failed:', error.message);
        return null;
    }
}

// Cache functions
async function getCachedVTAnalysis(domain) {
    try {
        const cache = await StorageHelper.get('vtCache') || {};
        const cached = cache[domain];
        
        if (cached && (Date.now() - cached.timestamp) < 24 * 60 * 60 * 1000) {
            return cached.data;
        }
        return null;
    } catch (error) {
        return null;
    }
}

async function cacheVTAnalysis(domain, data) {
    try {
        const cache = await StorageHelper.get('vtCache') || {};
        cache[domain] = {
            timestamp: Date.now(),
            data: data
        };
        await StorageHelper.set('vtCache', cache);
    } catch (error) {
        console.log('Cache error:', error);
    }
}

// Analysis history functions
async function updateAnalysisHistory(analysisData) {
    try {
        let history = await StorageHelper.get(ANALYSIS_HISTORY_KEY) || [];
        
        history.unshift({
            ...analysisData,
            id: Date.now().toString()
        });
        
        // Keep only last 100 analyses
        if (history.length > 100) {
            history.splice(100);
        }
        
        await StorageHelper.set(ANALYSIS_HISTORY_KEY, history);
        console.log('📈 Analysis history updated. Total:', history.length);
        
    } catch (error) {
        console.log('History update error:', error);
    }
}

async function getAnalysisStats() {
    try {
        const history = await StorageHelper.get(ANALYSIS_HISTORY_KEY) || [];
        
        const totalAnalyses = history.length;
        const threatsFound = history.filter(item => item.confidence >= 40).length;
        const avgAnalysisTime = history.length > 0 
            ? Math.round(history.reduce((sum, item) => sum + (item.analysisTime || 0), 0) / history.length)
            : 0;
        
        return {
            totalAnalyses,
            threatsFound,
            avgAnalysisTime
        };
    } catch (error) {
        console.log('Stats error:', error);
        return {
            totalAnalyses: 0,
            threatsFound: 0,
            avgAnalysisTime: 0
        };
    }
}

// Main analysis function - FIXED LOGIC
async function analyzeUrl(url) {
    const startTime = Date.now();
    
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        
        // Perform local analysis
        const localAnalysis = performLocalAnalysis(url, domain);
        
        // Perform VirusTotal analysis
        const vtAnalysis = await performVirusTotalAnalysis(domain);
        
        // Combine results
        let threatScore = localAnalysis.confidence; // This is threat level
        let warnings = localAnalysis.warnings;
        
        if (vtAnalysis) {
            threatScore += vtAnalysis.confidence;
            warnings = warnings.concat(vtAnalysis.warnings);
            threatScore = Math.min(threatScore, 100);
        }
        
        const analysisTime = Date.now() - startTime;
        
        // FIXED: Higher threat score = Higher risk, Lower threat score = Lower risk
      const riskLevel = confidence >= 70 ? 'LOW' : confidence <= 30 ? 'HIGH' : 'MEDIUM';
        
        const finalAnalysis = {
            isSuspicious: threatScore > 40, // Based on threat level
            confidence: threatScore, // This is actually threat level (0-100)
            warnings: warnings,
            riskLevel: riskLevel,
            analysisTime: analysisTime,
            vtData: vtAnalysis
        };
        
        // Update history - FIXED: Count all analyses, not just threats
        await updateAnalysisHistory({
            url: url,
            domain: domain,
            timestamp: new Date().toISOString(),
            analysisTime: analysisTime,
            confidence: threatScore,
            riskLevel: riskLevel,
            vtDetections: vtAnalysis ? vtAnalysis.detections : 0,
            vtTotal: vtAnalysis ? vtAnalysis.total : 0
        });
        
        return finalAnalysis;
        
    } catch (error) {
        console.error('Analysis error:', error);
        return {
            isSuspicious: false,
            confidence: 0,
            warnings: ['Analysis error'],
            riskLevel: 'LOW',
            analysisTime: Date.now() - startTime,
            vtData: null
        };
    }
}

// Your existing local analysis function (KEEP THIS AS IS)
function performLocalAnalysis(url, domain) {
    let confidence = 0;
    let warnings = [];
    
    // 1. Check for HTTP instead of HTTPS (MAJOR security issue)
    if (url.startsWith('http:')) {
        confidence += 40;
        warnings.push("🚨 Website uses HTTP (not secure - data can be intercepted)");
    }
    
    // 2. Check for suspicious TLDs (often used in phishing)
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.loan', '.club'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
        confidence += 30;
        warnings.push("⚠️ Suspicious domain extension (often used for phishing)");
    }
    
    // 3. Check for excessive hyphens (common in phishing domains)
    const hyphenCount = (domain.match(/-/g) || []).length;
    if (hyphenCount > 2) {
        confidence += 20;
        warnings.push("⚠️ Too many hyphens in domain (phishing tactic)");
    }
    
    // 4. Check for numbers in domain (uncommon in legitimate sites)
    const numbersInDomain = (domain.match(/\d/g) || []).length;
    if (numbersInDomain > 2) {
        confidence += 15;
        warnings.push("⚠️ Suspicious: Numbers in domain name");
    }
    
    // 5. Check for very long domains (phishing tactic)
    if (domain.length > 30) {
        confidence += 10;
        warnings.push("⚠️ Very long domain name (suspicious)");
    }
    
    // 6. Check for IP addresses instead of domains
    const ipPattern = /^\d+\.\d+\.\d+\.\d+$/;
    if (ipPattern.test(domain.replace(/:\d+$/, ''))) {
        confidence += 50;
        warnings.push("🚨 Using IP address instead of domain (highly suspicious)");
    }
    
    // 7. Check for look-alike domains (basic homograph detection)
    const legitimateDomains = ['google', 'facebook', 'paypal', 'amazon', 'microsoft', 'apple', 'github', 'netflix'];
    legitimateDomains.forEach(legit => {
        if (domain.includes(legit) && !domain.endsWith(`${legit}.com`) && !domain.endsWith(`${legit}.org`)) {
            confidence += 35;
            warnings.push(`🚨 Possible homograph attack: mimics ${legit} but not the real domain`);
        }
    });
    
    // 8. Check against static phishing list
    const phishingDetector = new PhishingDetector();
    const staticAnalysis = phishingDetector.analyzeUrl(url);
    if (staticAnalysis.isSuspicious) {
        confidence += staticAnalysis.confidence;
        warnings = warnings.concat(staticAnalysis.warnings);
    }
    
    return {
        confidence: confidence,
        warnings: warnings
    };
}

// Tab monitoring (KEEP YOUR EXISTING CODE)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        analyzeUrl(tab.url).then(analysis => {
            currentTabAnalysis[tabId] = analysis;
            
            // Store in storage for popup
            chrome.storage.local.set({[`analysis_${tabId}`]: analysis});
            
            // Show badge for suspicious sites
            if (analysis.isSuspicious) {
                chrome.action.setBadgeText({
                    tabId: tabId,
                    text: '!'
                });
                chrome.action.setBadgeBackgroundColor({
                    tabId: tabId,
                    color: analysis.riskLevel === 'HIGH' ? '#FF0000' : '#FF9900'
                });
            } else {
                chrome.action.setBadgeText({tabId: tabId, text: ''});
            }
        });
    }
});

// Handle tab removal
chrome.tabs.onRemoved.addListener((tabId) => {
    delete currentTabAnalysis[tabId];
});

// Message handling (KEEP YOUR EXISTING CODE)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getCurrentAnalysis') {
        chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
            if (tabs[0]) {
                const tabId = tabs[0].id;
                const analysis = currentTabAnalysis[tabId] || {
                    isSuspicious: false,
                    confidence: 0,
                    warnings: ['Analysis in progress...'],
                    riskLevel: 'LOW',
                    analysisTime: 0,
                    vtData: null
                };
                sendResponse(analysis);
            } else {
                sendResponse({
                    isSuspicious: false,
                    confidence: 0,
                    warnings: ['No active tab'],
                    riskLevel: 'LOW',
                    analysisTime: 0,
                    vtData: null
                });
            }
        });
        return true;
    }
    
    if (request.action === 'getPageAnalysis') {
        chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, 
                    {action: 'getPageAnalysis'}, 
                    (response) => {
                        if (chrome.runtime.lastError) {
                            sendResponse({
                                cookies: {totalCookies: 0, insecureCookies: [], securityScore: 100},
                                overallRisk: {score: 0, level: 'LOW'},
                                scripts: {totalScripts: 0, externalScripts: 0},
                                forms: []
                            });
                        } else {
                            sendResponse(response);
                        }
                    }
                );
            } else {
                sendResponse({
                    cookies: {totalCookies: 0, insecureCookies: [], securityScore: 100},
                    overallRisk: {score: 0, level: 'LOW'},
                    scripts: {totalScripts: 0, externalScripts: 0},
                    forms: []
                });
            }
        });
        return true;
    }
    
    if (request.action === 'getAnalysisStats') {
        getAnalysisStats().then(stats => {
            sendResponse(stats);
        });
        return true;
    }
});

console.log('✅ Security Sentinel loaded with VirusTotal API');
