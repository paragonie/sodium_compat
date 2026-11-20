<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Core_MLKem_Operations::class)]
#[CoversClass(ParagonIE_Sodium_Core_MLDSA_Operations::class)]
class CorePQSamplingTest extends TestCase
{
    public static function vectors(): array
    {
        $data = json_decode(
            file_get_contents(dirname(__DIR__) . '/KAT/pq-sampling.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        $cases = [];
        foreach ($data['tests'] as $test) {
            $cases[$test['algorithm'] . ' ' . $test['label']] = [$test];
        }
        return $cases;
    }

    /**
     * @dataProvider vectors
     */
    #[DataProvider('vectors')]
    public function testSamplingAgainstIndependentCoefficients(array $test): void
    {
        $seed = hex2bin($test['seed']);
        $suffix = hex2bin($test['suffix']);
        $params = new ParagonIE_Sodium_Core_MLDSA_Params();
        switch ($test['algorithm']) {
            case 'mlkem_ntt':
                $actual = ParagonIE_Sodium_Core_MLKem_Operations::sampleNTT($seed, ord($suffix[0]), ord($suffix[1]));
                break;
            case 'mlkem_cbd':
                $actual = ParagonIE_Sodium_Core_MLKem_Operations::samplePolyCBD($seed, ord($suffix[0]), 2);
                break;
            case 'mldsa_ntt':
                $actual = ParagonIE_Sodium_Core_MLDSA_Operations::rejNttPoly($seed . $suffix);
                break;
            case 'mldsa_bounded':
                $actual = ParagonIE_Sodium_Core_MLDSA_Operations::rejBoundedPoly($params, $seed . $suffix);
                break;
            case 'mldsa_ball':
                $actual = ParagonIE_Sodium_Core_MLDSA_Operations::sampleInBall($params, $seed);
                break;
            default:
                $this->fail('Unknown sampling fixture');
        }
        $this->assertSame($test['coefficients'], $actual->toArray());
    }
}
