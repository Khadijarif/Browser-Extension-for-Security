class SecurityHelpers {
   static formatRiskLevel(confidence) {
    // confidence: 0-100 (0% = high risk, 100% = low risk)
    if (confidence >= 70) return { level: 'LOW', color: '#28a745', emoji: '✅' };
    if (confidence <= 30) return { level: 'HIGH', color: '#dc3545', emoji: '🚨' };
    return { level: 'MEDIUM', color: '#ffc107', emoji: '⚠️' };
}

    static truncateText(text, maxLength = 50) {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    static getDomainFromUrl(url) {
        try {
            return new URL(url).hostname;
        } catch (error) {
            return url;
        }
    }

    static formatAnalysisTime(ms) {
        if (ms < 1000) return `${ms}ms`;
        return `${(ms / 1000).toFixed(2)}s`;
    }

    static generateSecurityReport(phishingAnalysis, cookieAnalysis) {
        const timestamp = new Date().toLocaleString();
        const domain = this.getDomainFromUrl(window.location.href);
        
        return {
            timestamp,
            domain,
            overallScore: this.calculateOverallScore(phishingAnalysis, cookieAnalysis),
            phishing: phishingAnalysis,
            cookies: cookieAnalysis,
            summary: this.generateSummary(phishingAnalysis, cookieAnalysis)
        };
    }

    static calculateOverallScore(phishingAnalysis, cookieAnalysis) {
        let score = 100;
        
        if (phishingAnalysis.isSuspicious) {
            score -= phishingAnalysis.confidence * 0.6;
        }
        
        if (cookieAnalysis && cookieAnalysis.insecureCookies) {
            score -= cookieAnalysis.insecureCookies.length * 10;
        }
        
        return Math.max(0, Math.round(score));
    }

    static generateSummary(phishingAnalysis, cookieAnalysis) {
        const issues = [];
        
        if (phishingAnalysis.isSuspicious) {
            issues.push(`Phishing risk detected (${phishingAnalysis.confidence}% confidence)`);
        }
        
        if (cookieAnalysis && cookieAnalysis.insecureCookies) {
            issues.push(`${cookieAnalysis.insecureCookies.length} insecure cookies found`);
        }
        
        return issues.length === 0 
            ? 'No security issues detected' 
            : issues.join('; ');
    }

    static validateUrl(url) {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    }
}

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

    static async remove(key) {
        return new Promise((resolve) => {
            chrome.storage.local.remove([key], () => {
                resolve();
            });
        });
    }
}
