<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Exceptions;

use OutOfRangeException;
use Spaze\Encryption\Format\LogSafeValue;
use Throwable;

class UnknownEncryptionKeyIdException extends OutOfRangeException
{

	public function __construct(string $keyId, ?Throwable $previous = null)
	{
		parent::__construct("Unknown encryption key id: '" . LogSafeValue::from($keyId) . "'", previous: $previous);
	}

}
