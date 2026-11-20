<?php

/**
 * @covers ParagonIE_Sodium_Core_MLKem_Operations
 * @covers ParagonIE_Sodium_Core_MLDSA_Operations
 */
class CorePQSamplingTest extends PHPUnit_Framework_TestCase
{
    public static function vectors()
    {
        $data = json_decode(
            file_get_contents(dirname(dirname(__FILE__)) . '/KAT/pq-sampling.json'),
            true
        );
        $cases = array();
        foreach ($data['tests'] as $test) {
            $cases[$test['algorithm'] . ' ' . $test['label']] = array($test);
        }
        return $cases;
    }

    /**
     * @dataProvider vectors
     */
    public function testSamplingAgainstIndependentCoefficients(array $test)
    {
        $seed = ParagonIE_Sodium_Compat::hex2bin($test['seed']);
        $suffix = ParagonIE_Sodium_Compat::hex2bin($test['suffix']);
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
