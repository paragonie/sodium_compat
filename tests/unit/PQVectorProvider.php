<?php

/**
 * Loads pinned test data only; cryptographic operations belong in the tests
 */
final class PQVectorProvider
{
    /**
     * @throws JsonException
     */
    public static function wycheproof(string $name): array
    {
        $data = self::read(__DIR__ . '/wycheproof/' . $name . '_test.json');
        $cases = [];
        foreach ($data['testGroups'] as $group) {
            foreach ($group['tests'] as $test) {
                $cases['tcId=' . $test['tcId'] . ' ' . ($test['comment'] ?? '')] = [$group, $test];
            }
        }
        if (count($cases) !== $data['numberOfTests']) {
            throw new RuntimeException('Incomplete Wycheproof corpus: ' . $name);
        }
        return $cases;
    }

    /**
     * @throws JsonException
     */
    public static function native(string $algorithm): array
    {
        $data = self::read(__DIR__ . '/KAT/pq-libsodium.json');
        $cases = [];
        foreach ($data[$algorithm === 'mldsa44' ? 'mldsa' : 'kem'] as $i => $test) {
            if ($algorithm === 'mldsa44' || $test['algorithm'] === $algorithm) {
                $cases[$algorithm . ' #' . $i] = [$test];
            }
        }
        if (!$cases) {
            throw new RuntimeException('Missing native fixtures: ' . $algorithm);
        }
        return $cases;
    }

    /**
     * @throws JsonException
     */
    private static function read(string $path): array
    {
        $json = file_get_contents($path);
        if ($json === false) {
            throw new RuntimeException('Cannot read fixture: ' . $path);
        }
        return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    }
}
