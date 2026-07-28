<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Exceptions;

use Exception;
use Throwable;

class InvalidKeyLengthException extends Exception
{

	public function __construct(string $id, int $actualLength, ?Throwable $previous = null)
	{
		$expectedBytes = SODIUM_CRYPTO_STREAM_KEYBYTES;
		$expectedHexChars = $expectedBytes * 2;
		parent::__construct("Key '{$id}' must be {$expectedBytes} bytes ({$expectedHexChars} hexadecimal characters) but is {$actualLength} bytes", previous: $previous);
	}

}
