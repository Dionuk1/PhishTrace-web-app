<?php
/**
 * Simple URL phishing detection helper.
 *
 * Checks:
 * - URL uses IP address instead of a domain
 * - URL contains suspicious words (login, verify, free, reward)
 * - URL uses http instead of https
 * - URL is a known shortener (bit.ly, tinyurl, etc.)
 *
 * Returns:
 * - risk_flags: array of flag codes
 * - explanations: map of flag_code => human explanation
 */

declare(strict_types=1);

class UrlPhishingDetector
{
    /** @var string[] */
    private array $suspiciousWords = ['login', 'verify', 'free', 'reward'];

    /** @var string[] */
    private array $shortenerDomains = [
        'bit.ly',
        'bitly.com',
        'tinyurl.com',
        't.co',
        'goo.gl',
        'ow.ly',
        'is.gd',
        'buff.ly',
        'rebrand.ly',
        'cutt.ly',
        'tiny.cc',
        'shorte.st',
        's.id',
    ];

    /**
     * Analyze a single URL.
     *
     * @return array{
     *   url: string,
     *   risk_flags: string[],
     *   explanations: array<string,string>
     * }
     */
    public function analyzeUrl(string $url): array
    {
        $riskFlags = [];
        $explanations = [];

        $parts = @parse_url($url);
        if (!is_array($parts)) {
            return [
                'url' => $url,
                'risk_flags' => [],
                'explanations' => []
            ];
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));

        // Check: http instead of https
        if ($scheme === 'http') {
            $this->addFlag(
                $riskFlags,
                $explanations,
                'uses_http',
                'URL uses http instead of https (traffic can be intercepted).'
            );
        }

        // Check: IP address instead of domain
        if ($host !== '' && filter_var($host, FILTER_VALIDATE_IP)) {
            $this->addFlag(
                $riskFlags,
                $explanations,
                'uses_ip_address',
                'URL host is an IP address instead of a domain (often used to hide identity).'
            );
        }

        // Check: known URL shortener
        $matchedShortener = $this->matchShortenerDomain($host);
        if ($matchedShortener !== null) {
            $this->addFlag(
                $riskFlags,
                $explanations,
                'is_shortened',
                'URL uses a known shortener domain (' . $matchedShortener . '), which can hide the real destination.'
            );
        }

        // Check: suspicious words in URL string
        $urlLower = strtolower($url);
        $foundWords = $this->findSuspiciousWords($urlLower);
        if (count($foundWords) > 0) {
            $this->addFlag(
                $riskFlags,
                $explanations,
                'contains_suspicious_words',
                'URL contains suspicious words: ' . implode(', ', $foundWords) . '.'
            );
        }

        return [
            'url' => $url,
            'risk_flags' => $riskFlags,
            'explanations' => $explanations
        ];
    }

    /**
     * Analyze a list of URLs.
     *
     * @param string[] $urls
     * @return array<int, array{url:string, risk_flags:string[], explanations:array<string,string>}>
     */
    public function analyzeUrls(array $urls): array
    {
        $results = [];

        foreach ($urls as $url) {
            if (!is_string($url)) {
                continue;
            }
            $results[] = $this->analyzeUrl($url);
        }

        return $results;
    }

    /**
     * @param string[] $riskFlags
     * @param array<string,string> $explanations
     */
    private function addFlag(array &$riskFlags, array &$explanations, string $flag, string $explanation): void
    {
        if (in_array($flag, $riskFlags, true)) {
            return;
        }

        $riskFlags[] = $flag;
        $explanations[$flag] = $explanation;
    }

    /**
     * @return string[]
     */
    private function findSuspiciousWords(string $urlLower): array
    {
        $found = [];

        foreach ($this->suspiciousWords as $word) {
            if (strpos($urlLower, $word) !== false) {
                $found[] = $word;
            }
        }

        return array_values(array_unique($found));
    }

    private function matchShortenerDomain(string $host): ?string
    {
        if ($host === '') {
            return null;
        }

        $host = rtrim($host, '.');

        foreach ($this->shortenerDomains as $domain) {
            $domain = strtolower($domain);
            if ($host === $domain || str_ends_with($host, '.' . $domain)) {
                return $domain;
            }
        }

        return null;
    }
}
