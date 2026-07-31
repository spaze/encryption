<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Exceptions;

use Exception;
use Throwable;

class IncompleteKeyPairException extends Exception
{

	public function __construct(string $keyId, ?Throwable $previous = null)
	{
		parent::__construct("Key id '{$keyId}' needs both our secret key and the other party's public key", previous: $previous);
	}

}
