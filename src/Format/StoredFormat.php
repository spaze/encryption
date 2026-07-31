<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Format;

/**
 * @internal Which stored value shapes an operation accepts, not part of the public API
 */
enum StoredFormat
{

	case PlainOnly;
	case MarkedOrPlain;

}
