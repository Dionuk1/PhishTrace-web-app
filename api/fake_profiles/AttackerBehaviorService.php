<?php
declare(strict_types=1);

/**
 * Summarizes attacker behavior from stored fake profile messages.
 */
class AttackerBehaviorService
{
    /**
     * @param array<int,array<string,mixed>> $messages
     * @return array<int,array<string,mixed>>
     */
    public function topAttackers(array $messages, int $limit = 8): array
    {
        $attackers = [];

        foreach ($messages as $message) {
            $sender = (string) ($message['sender_username'] ?? 'unknown');
            $keywords = json_decode((string) ($message['keywords_json'] ?? '[]'), true);
            $urls = json_decode((string) ($message['urls_json'] ?? '[]'), true);
            $riskLevel = strtoupper((string) ($message['risk_level'] ?? 'LOW'));

            if (!isset($attackers[$sender])) {
                $attackers[$sender] = [
                    'sender_username' => $sender,
                    'message_count' => 0,
                    'url_count' => 0,
                    'high_risk_count' => 0,
                    'keyword_counts' => [],
                ];
            }

            $attackers[$sender]['message_count']++;
            $attackers[$sender]['url_count'] += is_array($urls) ? count($urls) : 0;
            $attackers[$sender]['high_risk_count'] += $riskLevel === 'HIGH' ? 1 : 0;

            if (is_array($keywords)) {
                foreach ($keywords as $keyword) {
                    $attackers[$sender]['keyword_counts'][$keyword] = ($attackers[$sender]['keyword_counts'][$keyword] ?? 0) + 1;
                }
            }
        }

        foreach ($attackers as &$attacker) {
            $attacker['repeated_keywords'] = $this->repeatedKeywords($attacker['keyword_counts']);
            $attacker['suspicious_level'] = $this->suspiciousLevel($attacker);
        }
        unset($attacker);

        usort($attackers, fn(array $a, array $b): int => $b['message_count'] <=> $a['message_count']);

        return array_slice(array_values($attackers), 0, $limit);
    }

    /**
     * @param array<string,int> $keywordCounts
     * @return string[]
     */
    private function repeatedKeywords(array $keywordCounts): array
    {
        $repeated = [];

        foreach ($keywordCounts as $keyword => $count) {
            if ($count >= 2) {
                $repeated[] = (string) $keyword;
            }
        }

        return $repeated;
    }

    /**
     * @param array<string,mixed> $attacker
     */
    private function suspiciousLevel(array $attacker): string
    {
        if (
            (int) $attacker['high_risk_count'] > 0 ||
            (int) $attacker['url_count'] >= 3 ||
            count($attacker['repeated_keywords'] ?? []) >= 3 ||
            (int) $attacker['message_count'] >= 5
        ) {
            return 'HIGH';
        }

        if (
            (int) $attacker['url_count'] > 0 ||
            count($attacker['repeated_keywords'] ?? []) > 0 ||
            (int) $attacker['message_count'] >= 3
        ) {
            return 'MEDIUM';
        }

        return 'LOW';
    }
}
