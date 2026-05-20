<?php
declare(strict_types=1);

class HoneypotRiskService
{
    /**
     * Calculate risk score using the requested rule-based formula.
     *
     * @param string[] $keywords
     * @param string[] $urls
     * @param array<int,array{url:string,flags:string[],explanation:string}> $urlAnalysis
     * @return array{score:int,level:string}
     */
    public function score(array $keywords, array $urls, array $urlAnalysis): array
    {
        $score = count($keywords) * 10;

        if (count($urls) > 0) {
            $score += 20;
        }

        if ($this->hasSuspiciousUrl($urlAnalysis)) {
            $score += 30;
        }

        if ($this->hasHttpUrl($urlAnalysis)) {
            $score += 20;
        }

        return [
            'score' => $score,
            'level' => $this->level($score),
        ];
    }

    private function level(int $score): string
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
     * @param array<int,array{url:string,flags:string[],explanation:string}> $urlAnalysis
     */
    private function hasHttpUrl(array $urlAnalysis): bool
    {
        foreach ($urlAnalysis as $analysis) {
            if (in_array('uses_http', $analysis['flags'] ?? [], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<int,array{url:string,flags:string[],explanation:string}> $urlAnalysis
     */
    private function hasSuspiciousUrl(array $urlAnalysis): bool
    {
        foreach ($urlAnalysis as $analysis) {
            foreach (($analysis['flags'] ?? []) as $flag) {
                if ($flag !== 'uses_http') {
                    return true;
                }
            }
        }

        return false;
    }
}
