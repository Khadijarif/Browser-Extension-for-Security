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
            'faceb00k-login.com',
            'paypa1-secure.com', 
            'apple-verify.net',
            'google-security-update.com',
            'microsoft-account-verify.com',
            'netflix-billing-update.com',
            'bankofamerica-securelogin.com',
            'wellsfargo-onlinebanking.com',
            'chase-online-login.com',
            'citibank-secure-access.com',
            'testphp.vulnweb.com',
            'secure-paypal-login.com',
            'amazon-account-verification.com',
            'ebay-security-update.com'
        ];
    }

    analyzeUrl(url) {
        const results = {
            isSuspicious: false,
            confidence: 0,
            warnings: [],
            detectedPatterns: [],
            staticMatches: []
        };

        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname;
            const path = urlObj.pathname.toLowerCase();

            // Check against known phishing domains
            const matchedPhishingDomain = this.knownPhishingDomains.find(phish => 
                domain.includes(phish) || phish.includes(domain)
            );
            
            if (matchedPhishingDomain) {
                results.isSuspicious = true;
                results.confidence = 90;
                results.warnings.push(`Known phishing domain: ${matchedPhishingDomain}`);
                results.staticMatches.push(matchedPhishingDomain);
            }

            // Check suspicious TLDs
            if (this.suspiciousTlds.some(tld => domain.endsWith(tld))) {
                results.isSuspicious = true;
                results.confidence += 30;
                results.warnings.push('Suspicious domain extension');
            }

            // Check for suspicious patterns in URL
            this.suspiciousPatterns.forEach((pattern) => {
                if (pattern.test(url) || pattern.test(path)) {
                    results.isSuspicious = true;
                    results.confidence += 20;
                    results.detectedPatterns.push(pattern.toString());
                    results.warnings.push(`Suspicious pattern: ${pattern.toString()}`);
                }
            });

            // Check for homograph attacks
            if (this.detectHomograph(domain)) {
                results.isSuspicious = true;
                results.confidence += 40;
                results.warnings.push('Possible homograph attack');
            }

            // Check for subdomain tricks
            if (this.detectSubdomainTrick(domain)) {
                results.isSuspicious = true;
                results.confidence += 25;
                results.warnings.push('Suspicious subdomain structure');
            }

            results.confidence = Math.min(results.confidence, 100);

        } catch (error) {
            console.error('Error analyzing URL:', error);
        }

        return results;
    }

    detectHomograph(domain) {
        const homographPatterns = [
            /[a-z0-9]rn[a-z0-9]/,
            /[a-z0-9]cl[i]/,
            /[a-z0-9]vv[ a-z0-9]/,
            /[a-z0-9]ii[i a-z0-9]/
        ];
        return homographPatterns.some(pattern => pattern.test(domain));
    }

    detectSubdomainTrick(domain) {
        const legitimateDomains = ['google', 'facebook', 'paypal', 'amazon', 'microsoft', 'apple', 'github', 'netflix', 'ebay'];
        const subdomains = domain.split('.');
        
        if (subdomains.length > 2) {
            const mainDomain = subdomains.slice(-2).join('.');
            const subdomainPart = subdomains.slice(0, -2).join('.');
            
            return legitimateDomains.some(legit => 
                subdomainPart.includes(legit) && !mainDomain.includes(legit)
            );
        }
        return false;
    }

    getRiskLevel(confidence) {
        if (confidence >= 70) return 'HIGH';
        if (confidence >= 40) return 'MEDIUM';
        return 'LOW';
    }
}
