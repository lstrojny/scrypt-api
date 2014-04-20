<?php
namespace lstrojny\scrypt\exception {

    interface ScryptExceptionInterface
    {
    }

    use InvalidArgumentException as BaseInvalidArgumentException;

    class InvalidArgumentException extends BaseInvalidArgumentException implements ScryptExceptionInterface
    {
        /**
         * @param string $function
         * @param integer $position
         * @param string $name
         * @param string $message
         * @return InvalidArgumentException
         */
        public static function invalidOptionValue($function, $position, $name, $message)
        {
            return new static(
                sprintf(
                    'Invalid argument %d ("$%s") for %s(): %s',
                    $position,
                    $name,
                    $function,
                    $message
                )
            );
        }

        /**
         * @param string $function
         * @param integer $position
         * @param string $name
         * @param string $key
         * @param string $message
         * @return InvalidArgumentException
         */
        public static function invalidArrayKeyValue($function, $position, $name, $key, $message)
        {
            return new static(
                sprintf(
                    'Invalid value of key "%s" in argument %d ("$%s") for %s(): %s',
                    $key,
                    $position,
                    $name,
                    $function,
                    $message
                )
            );
        }

        /**
         * @param string $function
         * @param integer $position
         * @param string $name
         * @param string $key
         * @return InvalidArgumentException
         */
        public static function invalidArrayKey($function, $position, $name, $key)
        {
            return new static(
                sprintf(
                    'Invalid key "%s" in argument %d ("$%s") for %s()',
                    $key,
                    $position,
                    $name,
                    $function
                )
            );
        }
    }

    use RuntimeException as BaseRuntimeException;

    class RuntimeException extends BaseRuntimeException implements ScryptExceptionInterface
    {
        /**
         * @param array $options
         * @return RuntimeException
         */
        public static function hashError(array $options)
        {
            return new static(
                sprintf(
                    'Could not generate hash with options cpu_cost => %d, memory_cost => %d, parallelization_cost => %d, key_length => %d',
                    $options['cpu_cost'],
                    $options['memory_cost'],
                    $options['parallelization_cost'],
                    $options['key_length']
                )
            );
        }
    }
}

namespace lstrojny\scrypt {

    use lstrojny\scrypt\exception\InvalidArgumentException;
    use lstrojny\scrypt\exception\RuntimeException;

    function hash($secret, $salt, array $options = array())
    {
        $defaults = array('cpu_cost' => pow(2, 14), 'memory_cost' => 8, 'parallelization_cost' => 1, 'key_length' => 64);
        $options  = array_merge($defaults, $options);

        $optionsDiff = array_diff_key($options, $defaults);
        if ($optionsDiff) {
            throw InvalidArgumentException::invalidArrayKey(
                __FUNCTION__,
                3,
                'options',
                current(array_keys($optionsDiff))
            );
        }

        if (($options['cpu_cost'] & ($options['cpu_cost'] - 1)) || $options['cpu_cost'] === 0) {
            throw InvalidArgumentException::invalidArrayKeyValue(
                __FUNCTION__,
                3,
                'options',
                'cpu_cost',
                'not a power of two greater than 1'
            );
        }

        if ((int) $options['memory_cost'] < 1) {
            throw InvalidArgumentException::invalidArrayKeyValue(
                __FUNCTION__,
                3,
                'options',
                'memory_cost',
                'is not >= 1'
            );
        }

        if ((int) $options['parallelization_cost'] < 1) {
            throw InvalidArgumentException::invalidArrayKeyValue(
                __FUNCTION__,
                3,
                'options',
                'parallelization_cost',
                'is not >= 1'
            );
        }

        if ($options['key_length'] < 16) {
            throw InvalidArgumentException::invalidArrayKeyValue(
                __FUNCTION__,
                3,
                'options',
                'key_length',
                'is not >= 16'
            );
        }

        if (_string_length($salt) < 16) {
            throw InvalidArgumentException::invalidOptionValue(
                __FUNCTION__,
                2,
                'salt',
                'length is not >= 16'
            );
        }

        $salt = base64_encode($salt);

        $key = scrypt(
            $secret,
            $salt,
            $options['cpu_cost'],
            $options['memory_cost'],
            $options['parallelization_cost'],
            $options['key_length']
        );

        if ($key === false) {
            throw RuntimeException::hashError($options);
        }

        return implode(
            '$',
            array(
                $options['cpu_cost'],
                $options['memory_cost'],
                $options['parallelization_cost'],
                $options['key_length'],
                $salt,
                $key,
            )
        );
    }

    function compare($hash, $secret)
    {
        list($cpuCost, $memoryCost, $parallelizationCost, $keyLength, $salt) = array_replace(
            array('', '', '' ,'', ''),
            explode('$', $hash)
        );

        if (!is_numeric($cpuCost) || !is_numeric($memoryCost) || !is_numeric($parallelizationCost) ||
            !is_numeric($keyLength) || empty($salt)) {

            return false;
        }

        $options = array(
            'cpu_cost'             => $cpuCost,
            'memory_cost'          => $memoryCost,
            'parallelization_cost' => $parallelizationCost,
            'key_length'           => $keyLength,
        );

        $salt = base64_decode($salt, true);

        if ($salt === false) {
            return false;
        }

        return _equals($hash, hash($secret, $salt, $options));
    }

    function _string_length($string)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($string, '8bit');
        }

        return strlen($string);
    }

    function _equals($left, $right)
    {
        $leftLength  = _string_length($left);
        $rightLength = _string_length($right);

        $length = min($leftLength, $rightLength);

        $result = 0;

        for ($i = 0; $i < $length; $i++) {
            $result |= ord($left[$i]) ^ ord($right[$i]);
        }

        return $result == 0 && $leftLength === $rightLength;
    }
}
