<?php
declare(strict_types=1);

class HoneypotKeywordService
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
     * Find suspicious keywords in a message.
     *
     * @return string[]
     */
    public function detect(string $message): array
    {
        $message = strtolower($message);
        $detected = [];

        foreach ($this->keywords as $keyword) {
            if (str_contains($message, $keyword)) {
                $detected[] = $keyword;
            }
        }

        return array_values(array_unique($detected));
    }
}
