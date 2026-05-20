<?php
/**
 * Risk scoring system for honeypot messages.
 *
 * Rules:
 * - keyword detected = +10 each
 * - URL exists = +20
 * - suspicious URL = +30
 * - http (no https) = +20
 *
 * Risk level:
 * - 0-29 = LOW
 * - 30-59 = MEDIUM
 * - 60+ = HIGH
 */

declare(strict_types=1);

require_once __DIR__ . '/UrlPhishingDetector.php';

class HoneypotRiskScorer
{
    private const POINTS_PER_KEYWORD = 10;
    private const POINTS_URL_EXISTS = 20;
    private const POINTS_SUSPICIOUS_URL = 30;
    private const POINTS_USES_HTTP = 20;

    private UrlPhishingDetector $urlDetector;

    public function __construct(?UrlPhishingDetector $urlDetector = null)
    {
        $this->urlDetector = $urlDetector ?? new UrlPhishingDetector();
    }

    /**
     * Score a message based on already-extracted keywords and URLs.
     *
     * Assumptions (simple + predictable):
     * - URL exists points apply once if any URLs exist
     * - suspicious URL points apply once if any URL is suspicious
     * - http points apply once if any URL uses http
     *
     * @param string[] $detectedKeywords
     * @param string[] $extractedUrls
     *
     * @return array{total_score:int, risk_level:string}
     */
    public function score(array $detectedKeywords, array $extractedUrls): array
    {
        $keywordCount = $this->countStringItems($detectedKeywords);
        $urlCount = $this->countStringItems($extractedUrls);

        $totalScore = 0;

        // +10 each keyword (unique keywords are typically stored already)
        $totalScore += $keywordCount * self::POINTS_PER_KEYWORD;

        // +20 if any URL exists
        if ($urlCount > 0) {
            $totalScore += self::POINTS_URL_EXISTS;
        }

        // Analyze URLs only if we have any
        $urlAnalyses = $urlCount > 0 ? $this->urlDetector->analyzeUrls($extractedUrls) : [];

        // +30 if any suspicious URL detected (excluding plain http flag, since http has its own points)
        if ($this->hasSuspiciousUrl($urlAnalyses)) {
            $totalScore += self::POINTS_SUSPICIOUS_URL;
        }

        // +20 if any URL uses http
        if ($this->hasHttpUrl($urlAnalyses)) {
            $totalScore += self::POINTS_USES_HTTP;
        }

        return [
            'total_score' => $totalScore,
            'risk_level' => $this->riskLevelFromScore($totalScore)
        ];
    }

    private function riskLevelFromScore(int $score): string
    {
        if ($score >= 60) {
            return 'HIGH';
        }

        if ($score >= 30) {
            return 'MEDIUM';
        }

        return 'LOW';
    }

    /**
     * @param array<int, array{url:string, risk_flags:string[], explanations:array<string,string>}> $urlAnalyses
     */
    private function hasHttpUrl(array $urlAnalyses): bool
    {
        foreach ($urlAnalyses as $analysis) {
            if (!isset($analysis['risk_flags']) || !is_array($analysis['risk_flags'])) {
                continue;
            }

            if (in_array('uses_http', $analysis['risk_flags'], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Suspicious URL = any non-http risk flags.
     *
     * @param array<int, array{url:string, risk_flags:string[], explanations:array<string,string>}> $urlAnalyses
     */
    private function hasSuspiciousUrl(array $urlAnalyses): bool
    {
        foreach ($urlAnalyses as $analysis) {
            if (!isset($analysis['risk_flags']) || !is_array($analysis['risk_flags'])) {
                continue;
            }

            foreach ($analysis['risk_flags'] as $flag) {
                if (!is_string($flag)) {
                    continue;
                }

                if ($flag === 'uses_http') {
                    continue;
                }

                return true;
            }
        }

        return false;
    }

    /**
     * @param mixed[] $items
     */
    private function countStringItems(array $items): int
    {
        $count = 0;
        foreach ($items as $item) {
            if (is_string($item) && trim($item) !== '') {
                $count++;
            }
        }
        return $count;
    }
}
