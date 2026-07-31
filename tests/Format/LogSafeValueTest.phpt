<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Format;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class LogSafeValueTest extends TestCase
{

	/** @dataProvider getValues */
	public function testFrom(string $value, string $expected): void
	{
		Assert::same($expected, LogSafeValue::from($value));
	}


	/**
	 * @return array<string, array{0:string, 1:string}>
	 */
	public function getValues(): array
	{
		return [
			'short printable value untouched' => ['key1', 'key1'],
			'empty value untouched' => ['', ''],
			'exactly at the limit untouched' => [str_repeat('a', 20), str_repeat('a', 20)],
			'one over the limit shortened' => [str_repeat('a', 21), str_repeat('a', 20) . '...'],
			'much longer shortened the same' => [str_repeat('a', 1000), str_repeat('a', 20) . '...'],
			'newline replaced' => ["bad\nid", 'bad?id'],
			'space replaced' => ['a b', 'a?b'],
			'control and non-ascii bytes replaced' => ["\x00\x09\xff", '???'],
			'shortened first, then sanitized' => [str_repeat('x', 19) . "\n" . str_repeat('y', 10), str_repeat('x', 19) . '?...'],
		];
	}

}

(new LogSafeValueTest())->run();
