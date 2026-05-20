<?php
declare(strict_types=1);

/**
 * Extracts URLs and checks simple phishing URL rules.
 */
class UrlService
{
    /** @var string[] */
    private array $suspiciousWords = ['login', 'verify', 'free', 'reward'];

    /** @var string[] */
    private array $shorteners = ['bit.ly', 'tinyurl.com', 't.co'];

    /**
     * @return string[]
     */
    public function extract(string $message): array
    {
        $urls = [];
        $pattern = '#https?://[^\s<>"{}|\\^`\[\]]*[a-zA-Z0-9/]#i';

        if (preg_match_all($pattern, $message, $matches)) {
            $urls = array_values(array_unique($matches[0] ?? []));
        }

        return $urls;
    }

    /**
     * @param string[] $urls
     * @return array<int,array{url:string,flags:string[],explanation:string}>
     */
    public function analyze(array $urls): array
    {
        $results = [];

        foreach ($urls as $url) {
            $results[] = $this->analyzeOne($url);
        }

        return $results;
    }

    /**
     * @return array{url:string,flags:string[],explanation:string}
     */
    private function analyzeOne(string $url): array
    {
        $flags = [];
        $explanations = [];
        $parts = parse_url($url);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));

        if ($scheme === 'http') {
            $flags[] = 'uses_http';
            $explanations[] = 'Uses http instead of https.';
        }

        if ($host !== '' && filter_var($host, FILTER_VALIDATE_IP)) {
            $flags[] = 'ip_based_url';
            $explanations[] = 'Uses an IP address instead of a domain.';
        }

        foreach ($this->shorteners as $shortener) {
            if ($host === $shortener || str_ends_with($host, '.' . $shortener)) {
                $flags[] = 'shortened_link';
                $explanations[] = 'Uses a known shortened link service.';
                break;
            }
        }

        $urlLower = strtolower($url);
        foreach ($this->suspiciousWords as $word) {
            if (str_contains($urlLower, $word)) {
                $flags[] = 'suspicious_url_word';
                $explanations[] = 'Contains suspicious URL word: ' . $word . '.';
            }
        }

        return [
            'url' => $url,
            'flags' => array_values(array_unique($flags)),
            'explanation' => $explanations ? implode(' ', array_unique($explanations)) : 'No URL risk flags found.',
        ];
    }
}
