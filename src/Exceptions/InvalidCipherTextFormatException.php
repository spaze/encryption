<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Exceptions;

use OutOfBoundsException;
use Spaze\Encryption\Format\StoredFormat;
use Throwable;

class InvalidCipherTextFormatException extends OutOfBoundsException
{

	public function __construct(StoredFormat $requiredFormats, ?Throwable $previous = null)
	{
		parent::__construct('Data format must be ' . match ($requiredFormats) {
			StoredFormat::PlainOnly => "'\$keyId\$ciphertext'",
			StoredFormat::MarkedOrPlain => "'\$keyId\$marker\$ciphertext' or '\$keyId\$ciphertext'",
		}, previous: $previous);
	}

}
