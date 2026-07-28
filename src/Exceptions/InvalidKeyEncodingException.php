<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Exceptions;

use Exception;
use Throwable;

class InvalidKeyEncodingException extends Exception
{

	public function __construct(string $id, ?Throwable $previous = null)
	{
		parent::__construct("Key '{$id}' is not a valid hex-encoded string", previous: $previous);
	}

}
