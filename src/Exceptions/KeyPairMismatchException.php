<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Exceptions;

use Exception;
use Throwable;

class KeyPairMismatchException extends Exception
{

	public function __construct(string $keyId, ?Throwable $previous = null)
	{
		parent::__construct("Public key '{$keyId}' is not the public half of secret key '{$keyId}'", previous: $previous);
	}

}
