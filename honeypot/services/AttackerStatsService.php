<?php
declare(strict_types=1);

class HoneypotAttackerStatsService
{
    public function suspicionLevel(int $totalMessages, int $totalUrls, int $repeatedKeywordCount, int $highRiskCount): string
    {
        if ($highRiskCount > 0 || $totalUrls >= 3 || $repeatedKeywordCount >= 3 || $totalMessages >= 5) {
            return 'HIGH';
        }

        if ($totalUrls > 0 || $repeatedKeywordCount > 0 || $totalMessages >= 3) {
            return 'MEDIUM';
        }

        return 'LOW';
    }
}
