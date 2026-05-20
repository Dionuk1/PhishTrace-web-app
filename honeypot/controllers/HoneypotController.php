<?php
declare(strict_types=1);

require_once __DIR__ . '/../models/HoneypotDatabase.php';
require_once __DIR__ . '/../models/HoneypotRepository.php';
require_once __DIR__ . '/../services/KeywordService.php';
require_once __DIR__ . '/../services/UrlService.php';
require_once __DIR__ . '/../services/RiskService.php';

class HoneypotController
{
    private HoneypotRepository $repository;
    private HoneypotKeywordService $keywordService;
    private HoneypotUrlService $urlService;
    private HoneypotRiskService $riskService;

    public function __construct(PDO $pdo)
    {
        (new HoneypotDatabase($pdo))->ensureTables();
        $this->repository = new HoneypotRepository($pdo);
        $this->keywordService = new HoneypotKeywordService();
        $this->urlService = new HoneypotUrlService();
        $this->riskService = new HoneypotRiskService();
    }

    /**
     * @return array{ok:bool,message:string}
     */
    public function handlePost(array $post): array
    {
        $action = (string) ($post['action'] ?? '');

        if ($action === 'create_profile') {
            return $this->createProfile($post);
        }

        if ($action === 'send_message') {
            return $this->sendMessage($post);
        }

        return ['ok' => false, 'message' => 'Unknown honeypot action.'];
    }

    /**
     * @return array<string,mixed>
     */
    public function pageData(?int $selectedProfileId): array
    {
        $profiles = $this->repository->profiles();
        $selectedProfileId = $selectedProfileId ?: (int) ($profiles[0]['id'] ?? 0);

        return [
            'profiles' => $profiles,
            'selected_profile_id' => $selectedProfileId,
            'chat_messages' => $this->repository->conversationMessages($selectedProfileId),
            'stats' => $this->repository->dashboardStats(),
            'recent_messages' => $this->repository->recentMessages(12),
            'top_attackers' => $this->repository->topAttackers(8),
        ];
    }

    /**
     * @param array<string,mixed> $post
     * @return array{ok:bool,message:string}
     */
    private function createProfile(array $post): array
    {
        $profileType = (string) ($post['profile_type'] ?? 'normal');
        $profileType = in_array($profileType, ['gamer', 'crypto', 'influencer', 'normal'], true) ? $profileType : 'normal';
        $username = trim((string) ($post['username'] ?? ''));
        $bio = trim((string) ($post['bio'] ?? ''));

        if (isset($post['auto_username']) || $username === '') {
            $username = $this->randomUsername($profileType);
        }

        if ($bio === '') {
            $bio = $this->defaultBio($profileType);
        }

        if (strlen($username) < 3 || strlen($username) > 80) {
            return ['ok' => false, 'message' => 'Username must be between 3 and 80 characters.'];
        }

        try {
            $this->repository->createProfile($username, $bio, $profileType);
            return ['ok' => true, 'message' => 'Fake profile created.'];
        } catch (PDOException $exception) {
            return ['ok' => false, 'message' => 'Username already exists. Try another one.'];
        }
    }

    /**
     * @param array<string,mixed> $post
     * @return array{ok:bool,message:string}
     */
    private function sendMessage(array $post): array
    {
        $profileId = (int) ($post['profile_id'] ?? 0);
        $senderUsername = trim((string) ($post['sender_username'] ?? ''));
        $messageText = trim((string) ($post['message_text'] ?? ''));

        if ($profileId <= 0 || $senderUsername === '' || $messageText === '') {
            return ['ok' => false, 'message' => 'Profile, sender, and message are required.'];
        }

        $keywords = $this->keywordService->detect($messageText);
        $urls = $this->urlService->extract($messageText);
        $urlAnalysis = $this->urlService->analyze($urls);
        $risk = $this->riskService->score($keywords, $urls, $urlAnalysis);
        $conversationId = $this->repository->findOrCreateConversation($profileId, $senderUsername);
        $messageId = $this->repository->createMessage($conversationId, $profileId, $senderUsername, $messageText);
        $this->repository->createAnalysisLog($messageId, $keywords, $urls, $risk['score'], $risk['level']);
        $this->repository->refreshAttackerStats($senderUsername);

        return ['ok' => true, 'message' => 'Message saved, analyzed, and logged.'];
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
            'gamer' => 'Gaming clips, squad invites, and tournament DMs.',
            'crypto' => 'Crypto updates, wallet safety, and web3 community posts.',
            'influencer' => 'Lifestyle content, collabs, and social media messages.',
            default => 'Everyday social profile for receiving test messages.',
        };
    }
}
