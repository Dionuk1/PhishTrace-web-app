<?php
declare(strict_types=1);

require_once __DIR__ . '/KeywordService.php';
require_once __DIR__ . '/UrlService.php';
require_once __DIR__ . '/RiskService.php';
require_once __DIR__ . '/FakeProfileRepository.php';

/**
 * Simple controller for creating profiles and receiving messages.
 */
class FakeProfileController
{
    private KeywordService $keywordService;
    private UrlService $urlService;
    private RiskService $riskService;

    public function __construct(private FakeProfileRepository $repository)
    {
        $this->keywordService = new KeywordService();
        $this->urlService = new UrlService();
        $this->riskService = new RiskService();
    }

    /**
     * @return array{ok:bool,message:string}
     */
    public function createProfile(string $username, string $bio, string $profileType, bool $autoUsername): array
    {
        $profileType = in_array($profileType, ['gamer', 'crypto', 'influencer', 'normal'], true) ? $profileType : 'normal';
        $username = $autoUsername || trim($username) === '' ? $this->randomUsername($profileType) : trim($username);
        $bio = trim($bio) !== '' ? trim($bio) : $this->defaultBio($profileType);

        if (strlen($username) < 3 || strlen($username) > 80) {
            return ['ok' => false, 'message' => 'Username must be between 3 and 80 characters.'];
        }

        try {
            $this->repository->createProfile($username, $bio, $profileType);
            return ['ok' => true, 'message' => 'Fake profile created successfully.'];
        } catch (PDOException $exception) {
            return ['ok' => false, 'message' => 'Could not create profile. Try a different username.'];
        }
    }

    /**
     * @return array{ok:bool,message:string}
     */
    public function receiveMessage(int $profileId, string $senderUsername, string $messageText): array
    {
        $senderUsername = trim($senderUsername);
        $messageText = trim($messageText);

        if ($profileId <= 0 || $senderUsername === '' || $messageText === '') {
            return ['ok' => false, 'message' => 'Profile, sender, and message are required.'];
        }

        $keywords = $this->keywordService->detect($messageText);
        $urls = $this->urlService->extract($messageText);
        $urlAnalysis = $this->urlService->analyze($urls);
        $risk = $this->riskService->score($keywords, $urls, $urlAnalysis);
        $conversationId = $this->repository->findOrCreateConversation($profileId, $senderUsername);

        $this->repository->addMessage(
            $conversationId,
            $profileId,
            $senderUsername,
            $messageText,
            $keywords,
            $urls,
            $urlAnalysis,
            $risk['score'],
            $risk['level']
        );

        return ['ok' => true, 'message' => 'Message received and analyzed.'];
    }

    private function randomUsername(string $profileType): string
    {
        $prefixes = [
            'gamer' => ['pixel', 'quest', 'arena', 'ranked'],
            'crypto' => ['token', 'chain', 'wallet', 'block'],
            'influencer' => ['daily', 'style', 'social', 'vibe'],
            'normal' => ['alex', 'sam', 'mira', 'user'],
        ];

        $pool = $prefixes[$profileType] ?? $prefixes['normal'];

        return $pool[array_rand($pool)] . '_' . random_int(1000, 9999);
    }

    private function defaultBio(string $profileType): string
    {
        return match ($profileType) {
            'gamer' => 'Gaming clips, tournaments, and team invites.',
            'crypto' => 'Crypto updates, wallet security, and market notes.',
            'influencer' => 'Lifestyle posts, collaborations, and community messages.',
            default => 'Personal profile for general social messages.',
        };
    }
}
