<?php

/**
 * Loads pinned test data only; cryptographic operations belong in the tests
 */
final class PQVectorProvider
{
    /**
     * @throws JsonException
     */
    public static function wycheproof($name)
    {
        $data = self::read(dirname(__FILE__) . '/wycheproof/' . $name . '_test.json');
        $cases = array();
        foreach ($data['testGroups'] as $group) {
            $tests = $group['tests'];
            unset($group['tests']);
            foreach ($tests as $test) {
                $cases['tcId=' . $test['tcId'] . ' ' . ((isset($test['comment']) ? $test['comment'] : ''))] = array($group, $test);
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
    public static function native($algorithm)
    {
        $data = self::read(dirname(__FILE__) . '/KAT/pq-libsodium.json');
        $cases = array();
        foreach ($data[$algorithm === 'mldsa44' ? 'mldsa' : 'kem'] as $i => $test) {
            if ($algorithm === 'mldsa44' || $test['algorithm'] === $algorithm) {
                $cases[$algorithm . ' #' . $i] = array($test);
            }
        }
        if (!$cases) {
            throw new RuntimeException('Missing native fixtures: ' . $algorithm);
        }
        return $cases;
    }

    /**
     * @throws JsonException (newer PHP only)
     */
    private static function read($path)
    {
        $json = file_get_contents($path);
        if ($json === false) {
            throw new RuntimeException('Cannot read fixture: ' . $path);
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new RuntimeException('Cannot decode fixture: ' . $path);
        }
        return $data;
    }
}
