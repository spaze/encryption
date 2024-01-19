<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\Encryption;

use OutOfBoundsException;
use OutOfRangeException;
use Spaze\Encryption\Exceptions\InvalidNumberOfComponentsException;
use Spaze\Encryption\Exceptions\UnknownEncryptionKeyIdException;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/bootstrap.php';

/** @testCase */
class SymmetricKeyEncryptionTest extends TestCase
{

	private const PLAINTEXT = 'foobar';

	private const INACTIVE_KEY = 'dev1';

	private const ACTIVE_KEY = 'dev2';

	/** @var array<string, array<string, string>> */
	private array $keys;

	private SymmetricKeyEncryption $encryption;


	protected function setUp(): void
	{
		$this->keys = [
			self::INACTIVE_KEY => bin2hex(random_bytes(32)),
			self::ACTIVE_KEY => bin2hex(random_bytes(32)),
		];
		$this->encryption = new SymmetricKeyEncryption($this->keys, self::ACTIVE_KEY);
	}


	public function testEncryptDecrypt(): void
	{
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($this->encryption->encrypt(self::PLAINTEXT)));
	}


	public function testEncryptInactiveKeyDecrypt(): void
	{
		$inactiveKeyEncryption = new SymmetricKeyEncryption($this->keys, self::INACTIVE_KEY);
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
	}


	public function testNeedsReEncrypt(): void
	{
		$inactiveKeyEncryption = new SymmetricKeyEncryption($this->keys, self::INACTIVE_KEY);
		Assert::false($inactiveKeyEncryption->needsReEncrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
		Assert::true($this->encryption->needsReEncrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
		Assert::true($inactiveKeyEncryption->needsReEncrypt($this->encryption->encrypt(self::PLAINTEXT)));
	}


	public function testEncryptUnknownKey(): void
	{
		$e = Assert::exception(
			function () {
				(new SymmetricKeyEncryption($this->keys, 'foo'))->encrypt(self::PLAINTEXT);
			},
			UnknownEncryptionKeyIdException::class,
			"Unknown encryption key id: 'foo'",
		);
		Assert::type(OutOfRangeException::class, $e);
	}


	/** @dataProvider getInvalidEncryptedData */
	public function testDecryptInvalidCipherTextComponents(string $invalidData): void
	{
		$e = Assert::exception(
			function () use ($invalidData) {
				(new SymmetricKeyEncryption($this->keys, self::ACTIVE_KEY))->decrypt($invalidData);
			},
			InvalidNumberOfComponentsException::class,
			"Data format must be '\$keyId\$ciphertext'",
		);
		Assert::type(OutOfBoundsException::class, $e);
	}


	public function getInvalidEncryptedData(): array
	{
		return [
			['nothing'],
			['$keyId'],
			['$key$ciphertext$whatsDiz'],
		];
	}


	public function testEncryptSensitiveParameter(): void
	{
		$e = Assert::exception(
			function () {
				(new SymmetricKeyEncryption($this->keys, 'foo'))->encrypt(self::PLAINTEXT);
			},
			UnknownEncryptionKeyIdException::class,
		);
		Assert::notContains(self::PLAINTEXT, $e->getTraceAsString());
		Assert::contains('SensitiveParameterValue', $e->getTraceAsString());
	}


	public function testHiddenStringKeys(): void
	{
		$object = print_r(new SymmetricKeyEncryption($this->keys, self::ACTIVE_KEY), true);
		Assert::notContains($this->keys[self::ACTIVE_KEY], $object);
		Assert::notContains($this->keys[self::INACTIVE_KEY], $object);
	}

}

(new SymmetricKeyEncryptionTest())->run();
