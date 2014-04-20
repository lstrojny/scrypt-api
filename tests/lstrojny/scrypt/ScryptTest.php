<?php
namespace lstrojny\tests\scrypt;

use lstrojny\scrypt;

class ScryptTest extends \PHPUnit_Framework_TestCase
{
    private $hash = '65536$8$1$64$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=$293567c0a58a1b393f13f2ac882142f0064ff59b94d5e2c6ee62f4717d361b3e4b7786d23826bd0dda67ced7e3bf37e1d8272bcb171aec254eedf3cec81be91b';

    public function testHash()
    {
        $this->assertSame($this->hash, scrypt\hash('foo', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', ['cpu_cost' => pow(2, 16)]));

        $this->assertTrue(scrypt\compare($this->hash, 'foo'));
        $this->assertFalse(scrypt\compare($this->hash, 'bar'));
    }

    public function getCompareErrorStrings()
    {
        return [
            [''],
            ['$$$$$'],
            ['1024$$$$$'],
            ['1024$1$$$$'],
            ['1024$1$1$$$'],
            ['1024$1$1$16$$'],
            ['1024$1$1$16$$hash'],
            ['1024$1$1$16$äöä$hash'],
        ];
    }

    /** @dataProvider getCompareErrorStrings */
    public function testCompareErrors($hash)
    {
        $this->assertFalse(scrypt\compare($hash, 'secret'));
    }

    public static function getErrors()
    {
        return [
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['cpu_cost' => 100],
                'Invalid value of key "cpu_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): not a power of two greater than 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['cpu_cost' => 0],
                'Invalid value of key "cpu_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): not a power of two greater than 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['cpu_cost' => -1],
                'Invalid value of key "cpu_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): not a power of two greater than 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['memory_cost' => -1],
                'Invalid value of key "memory_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['memory_cost' => 0],
                'Invalid value of key "memory_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['memory_cost' => PHP_INT_MAX + 1],
                'Invalid value of key "memory_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['memory_cost' => PHP_INT_MAX + 2],
                'Invalid value of key "memory_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['parallelization_cost' => -1],
                'Invalid value of key "parallelization_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['parallelization_cost' => 0],
                'Invalid value of key "parallelization_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['parallelization_cost' => PHP_INT_MAX + 1],
                'Invalid value of key "parallelization_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['parallelization_cost' => PHP_INT_MAX + 2],
                'Invalid value of key "parallelization_cost" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 1'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['key_length' => -1],
                'Invalid value of key "key_length" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 16'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['key_length' => 15],
                'Invalid value of key "key_length" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 16'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['key_length' => 15],
                'Invalid value of key "key_length" in argument 3 ("$options") for lstrojny\scrypt\hash(): is not >= 16'
            ],
            [
                'lstrojny\scrypt\exception\InvalidArgumentException',
                ['invalid_option' => 123],
                'Invalid key "invalid_option" in argument 3 ("$options") for lstrojny\scrypt\hash()'
            ]
        ];
    }

    /** @dataProvider getErrors */
    public function testErrors($exception, array $options, $message)
    {
        $this->setExpectedException($exception, $message);
        scrypt\hash('foo', 'saltsaltsaltsaltsaltsaltsaltsaltsaltsaltsaltsaltsalt', $options);
    }

    public function testEmptySalt()
    {
        $this->setExpectedException(
            'lstrojny\scrypt\exception\InvalidArgumentException',
            'Invalid argument 2 ("$salt") for lstrojny\scrypt\hash(): length is not >= 16'
        );
        scrypt\hash('foo', 'foo');
    }
}
