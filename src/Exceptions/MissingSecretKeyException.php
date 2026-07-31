<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Exceptions;

use OutOfRangeException;
use Throwable;

class MissingSecretKeyException extends OutOfRangeException
{

	public function __construct(string $keyId, ?Throwable $previous = null)
	{
		parent::__construct("No secret key configured for key id '{$keyId}', it can only be used to encrypt", previous: $previous);
	}

}
