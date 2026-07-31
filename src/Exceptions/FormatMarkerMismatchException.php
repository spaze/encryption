<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Exceptions;

use OutOfBoundsException;
use Spaze\Encryption\Format\FormatMarker;
use Throwable;

class FormatMarkerMismatchException extends OutOfBoundsException
{

	public function __construct(FormatMarker $actualMarker, ?Throwable $previous = null)
	{
		parent::__construct(match ($actualMarker) {
			FormatMarker::AuthenticatedPublicKeyV1 => 'Data was encrypted with AuthenticatedPublicKeyEncryption::encrypt(), decrypt it there with decrypt()',
			FormatMarker::AuthenticatedPublicKeyWithAdV1 => 'Data was encrypted with AuthenticatedPublicKeyEncryption::encryptWithAd(), decrypt it there with decryptWithAd()',
			FormatMarker::AnonymousPublicKeyV1 => 'Data was encrypted with AnonymousPublicKeyEncryption, decrypt it there',
		}, previous: $previous);
	}

}
