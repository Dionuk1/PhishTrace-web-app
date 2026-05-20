<?php
declare(strict_types=1);

/**
 * Detects suspicious phishing keywords in a message.
 */
class KeywordService
{
    /** @var string[] */
    private array $keywords = [
        'verify',
        'login',
        'urgent',
        'free',
        'click',
        'claim',
        'reward',
        'password',
        'confirm',
    ];

    /**
     * @return string[]
     */
    public function detect(string $message): array
    {
        $messageLower = strtolower($message);
        $detected = [];

        foreach ($this->keywords as $keyword) {
            if (str_contains($messageLower, $keyword)) {
                $detected[] = $keyword;
            }
        }

        return array_values(array_unique($detected));
    }

    /**
     * @return string[]
     */
    public function all(): array
    {
        return $this->keywords;
    }
}
