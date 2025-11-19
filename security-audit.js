// Reliable security audit content script
(function() {
    'use strict';
    
    class SecurityAuditor {
        constructor() {
            this.analysis = null;
            this.init();
        }
        
        init() {
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.analyzePage());
            } else {
                this.analyzePage();
            }
            
            chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
                if (request.action === 'getPageAnalysis') {
                    sendResponse(this.getAnalysis());
                }
                return true;
            });
        }
        
        analyzePage() {
            this.analysis = {
                cookies: this.analyzeCookies(),
                scripts: this.analyzeScripts(),
                forms: this.analyzeForms(),
                security: this.analyzeSecurity(),
                overallRisk: this.calculateRisk()
            };
            
            try {
                chrome.storage.local.set({
                    pageAnalysis: this.analysis
                });
            } catch (e) {
                console.log('Storage not available');
            }
        }
        
        analyzeCookies() {
            const cookies = document.cookie.split(';').filter(c => c.trim());
            const insecureCookies = [];
            
            cookies.forEach(cookie => {
                const [name, value] = cookie.split('=').map(c => c.trim());
                const issues = [];
                
                if (!cookie.toLowerCase().includes('secure') && location.protocol === 'https:') {
                    issues.push('No Secure flag');
                }
                if (!cookie.toLowerCase().includes('httponly')) {
                    issues.push('No HttpOnly flag');
                }
                if (!cookie.toLowerCase().includes('samesite')) {
                    issues.push('No SameSite flag');
                }
                
                if (issues.length > 0) {
                    insecureCookies.push({
                        name: name || 'unknown',
                        issues: issues
                    });
                }
            });
            
            return {
                totalCookies: cookies.length,
                insecureCookies: insecureCookies,
                securityScore: insecureCookies.length === 0 ? 100 : Math.max(0, 100 - (insecureCookies.length * 25))
            };
        }
        
        analyzeScripts() {
            const scripts = document.querySelectorAll('script');
            let externalCount = 0;
            
            scripts.forEach(script => {
                if (script.src && !script.src.includes(location.hostname)) {
                    externalCount++;
                }
            });
            
            return {
                totalScripts: scripts.length,
                externalScripts: externalCount,
                hasExternalScripts: externalCount > 0
            };
        }
        
        analyzeForms() {
            const forms = document.querySelectorAll('form');
            const formData = [];
            
            forms.forEach((form) => {
                const passwordFields = form.querySelectorAll('input[type="password"]');
                const sensitiveFields = form.querySelectorAll('input[type="password"], input[name*="pass"], input[name*="credit"], input[name*="card"]');
                
                formData.push({
                    hasPassword: passwordFields.length > 0,
                    hasSensitiveFields: sensitiveFields.length > 0,
                    action: form.action || 'self',
                    method: form.method || 'GET',
                    isExternal: form.action && !form.action.includes(location.hostname) && 
                               !form.action.startsWith('/') && !form.action.startsWith('#')
                });
            });
            
            return formData;
        }
        
        analyzeSecurity() {
            const issues = [];
            
            if (location.protocol === 'http:') {
                issues.push('Uses HTTP (not secure)');
            }
            
            if (location.protocol === 'http:' && document.querySelector('input[type="password"]')) {
                issues.push('Password fields on HTTP page');
            }
            
            const iframes = document.querySelectorAll('iframe');
            let externalIframes = 0;
            iframes.forEach(iframe => {
                if (iframe.src && !iframe.src.includes(location.hostname)) {
                    externalIframes++;
                }
            });
            if (externalIframes > 2) {
                issues.push('Multiple external iframes');
            }
            
            return {
                issues: issues,
                hasHTTPS: location.protocol === 'https:',
                issueCount: issues.length,
                externalIframes: externalIframes
            };
        }
        
        calculateRisk() {
            const cookies = this.analyzeCookies();
            const security = this.analyzeSecurity();
            const scripts = this.analyzeScripts();
            const forms = this.analyzeForms();
            
            let riskScore = 0;
            
            riskScore += (100 - cookies.securityScore) * 0.3;
            
            if (!security.hasHTTPS) {
                riskScore += 25;
                if (forms.some(f => f.hasPassword)) {
                    riskScore += 15;
                }
            }
            
            if (scripts.externalScripts > 5) {
                riskScore += 20;
            } else if (scripts.externalScripts > 2) {
                riskScore += 10;
            }
            
            const sensitiveForms = forms.filter(f => f.hasSensitiveFields).length;
            const externalForms = forms.filter(f => f.isExternal).length;
            
            if (sensitiveForms > 0) {
                riskScore += 10;
            }
            if (externalForms > 0) {
                riskScore += 10;
            }
            
            riskScore += security.issueCount * 5;
            if (security.externalIframes > 2) {
                riskScore += 10;
            }
            
            riskScore = Math.min(riskScore, 100);
            
            return {
                score: riskScore,
                level: riskScore >= 60 ? 'HIGH' : riskScore >= 30 ? 'MEDIUM' : 'LOW'
            };
        }
        
        getAnalysis() {
            return this.analysis || this.analyzePage();
        }
    }
    
    new SecurityAuditor();
})();
