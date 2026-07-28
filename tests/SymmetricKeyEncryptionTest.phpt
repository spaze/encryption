<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\Encryption;

use OutOfBoundsException;
use OutOfRangeException;
use ParagonIE\Halite\Alerts\InvalidMessage;
use SodiumException;
use Spaze\Encryption\Exceptions\DecryptWithAdNeedsAdditionalDataException;
use Spaze\Encryption\Exceptions\EncryptWithAdNeedsAdditionalDataException;
use Spaze\Encryption\Exceptions\InvalidKeyEncodingException;
use Spaze\Encryption\Exceptions\InvalidKeyLengthException;
use Spaze\Encryption\Exceptions\InvalidKeyPrefixException;
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

	private const KEY_PREFIX = 'prefix';

	private const TRUNCATED_KEY = 'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff012';

	/** @var array<string, string> */
	private array $keys;

	private SymmetricKeyEncryption $encryption;


	protected function setUp(): void
	{
		$this->keys = [
			self::INACTIVE_KEY => self::KEY_PREFIX . '_' . bin2hex(random_bytes(32)),
			self::ACTIVE_KEY => self::KEY_PREFIX . '_' . bin2hex(random_bytes(32)),
		];
		$this->encryption = new SymmetricKeyEncryption($this->keys, self::ACTIVE_KEY, self::KEY_PREFIX);
	}


	public function testEncryptDecrypt(): void
	{
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($this->encryption->encrypt(self::PLAINTEXT)));
	}


	public function testEncryptDecryptWithAd(): void
	{
		$ad = 'context';
		Assert::same(self::PLAINTEXT, $this->encryption->decryptWithAd($this->encryption->encryptWithAd(self::PLAINTEXT, $ad), $ad));
	}


	public function testDecryptWithWrongAdFails(): void
	{
		$encrypted = $this->encryption->encryptWithAd(self::PLAINTEXT, 'context1');
		Assert::exception(function () use ($encrypted) {
			$this->encryption->decryptWithAd($encrypted, 'context2');
		}, InvalidMessage::class);
	}


	public function testPairingFails(): void
	{
		$encryptedWithAd = $this->encryption->encryptWithAd(self::PLAINTEXT, 'context');
		Assert::exception(function () use ($encryptedWithAd) {
			$this->encryption->decrypt($encryptedWithAd);
		}, InvalidMessage::class);

		$encrypted = $this->encryption->encrypt(self::PLAINTEXT);
		Assert::exception(function () use ($encrypted) {
			$this->encryption->decryptWithAd($encrypted, 'context');
		}, InvalidMessage::class);
	}


	public function testEmptyAdGuard(): void
	{
		Assert::exception(function () {
			$this->encryption->encryptWithAd(self::PLAINTEXT, '');
		}, EncryptWithAdNeedsAdditionalDataException::class, 'additionalData must not be empty; use encrypt() for values that are not context-bound');

		$encryptedWithAd = $this->encryption->encryptWithAd(self::PLAINTEXT, 'context');
		Assert::exception(function () use ($encryptedWithAd) {
			$this->encryption->decryptWithAd($encryptedWithAd, '');
		}, DecryptWithAdNeedsAdditionalDataException::class, 'additionalData must not be empty; use decrypt() for values that are not context-bound');
	}


	public function testEncryptInactiveKeyDecrypt(): void
	{
		$inactiveKeyEncryption = new SymmetricKeyEncryption($this->keys, self::INACTIVE_KEY, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
	}


	public function testNeedsReEncrypt(): void
	{
		$inactiveKeyEncryption = new SymmetricKeyEncryption($this->keys, self::INACTIVE_KEY, self::KEY_PREFIX);
		Assert::false($inactiveKeyEncryption->needsReEncrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
		Assert::true($this->encryption->needsReEncrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
		Assert::true($inactiveKeyEncryption->needsReEncrypt($this->encryption->encrypt(self::PLAINTEXT)));

		$encryptedWithAd = $inactiveKeyEncryption->encryptWithAd(self::PLAINTEXT, 'context');
		Assert::false($inactiveKeyEncryption->needsReEncrypt($encryptedWithAd));
		Assert::true($this->encryption->needsReEncrypt($encryptedWithAd));
	}


	public function testEncryptUnknownKey(): void
	{
		$e = Assert::exception(
			function () {
				(new SymmetricKeyEncryption($this->keys, 'foo', self::KEY_PREFIX))->encrypt(self::PLAINTEXT);
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
				(new SymmetricKeyEncryption($this->keys, self::ACTIVE_KEY, self::KEY_PREFIX))->decrypt($invalidData);
			},
			InvalidNumberOfComponentsException::class,
			"Data format must be '\$keyId\$ciphertext'",
		);
		Assert::type(OutOfBoundsException::class, $e);
	}


	/**
	 * @return list<array{0:string}>
	 */
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
				(new SymmetricKeyEncryption($this->keys, 'foo', self::KEY_PREFIX))->encrypt(self::PLAINTEXT);
			},
			UnknownEncryptionKeyIdException::class,
		);
		assert($e instanceof UnknownEncryptionKeyIdException);
		Assert::notContains(self::PLAINTEXT, $e->getTraceAsString());
		Assert::contains('SensitiveParameterValue', $e->getTraceAsString());
	}


	public function testHiddenStringKeys(): void
	{
		$object = print_r(new SymmetricKeyEncryption($this->keys, self::ACTIVE_KEY, self::KEY_PREFIX), true);
		Assert::notContains($this->keys[self::ACTIVE_KEY], $object);
		Assert::notContains($this->keys[self::INACTIVE_KEY], $object);
	}


	public function testConstructorInvalidKeyLength(): void
	{
		$shortKey = bin2hex(random_bytes(16));
		$e = Assert::exception(
			function () use ($shortKey): void {
				new SymmetricKeyEncryption(['short' => self::KEY_PREFIX . '_' . $shortKey], 'short', self::KEY_PREFIX);
			},
			InvalidKeyLengthException::class,
			"Key 'short' must be 32 bytes (64 hexadecimal characters) but is 16 bytes",
		);
		assert($e instanceof InvalidKeyLengthException);
		Assert::notContains($shortKey, $e->getMessage());
		Assert::exception(
			function (): void {
				new SymmetricKeyEncryption(['bytes31' => self::KEY_PREFIX . '_' . bin2hex(random_bytes(31))], 'bytes31', self::KEY_PREFIX);
			},
			InvalidKeyLengthException::class,
			"Key 'bytes31' must be 32 bytes (64 hexadecimal characters) but is 31 bytes",
		);
	}


	public function testConstructorInvalidKeyEncoding(): void
	{
		$truncatedKey = substr(bin2hex(random_bytes(32)), 0, 63);
		$e = Assert::exception(
			function () use ($truncatedKey): void {
				new SymmetricKeyEncryption(['truncated' => self::KEY_PREFIX . '_' . $truncatedKey], 'truncated', self::KEY_PREFIX);
			},
			InvalidKeyEncodingException::class,
			"Key 'truncated' is not a valid hex-encoded string",
		);
		assert($e instanceof InvalidKeyEncodingException);
		Assert::type(SodiumException::class, $e->getPrevious());
		Assert::exception(
			function (): void {
				new SymmetricKeyEncryption(['nonhex' => self::KEY_PREFIX . '_' . str_repeat('xy', 32)], 'nonhex', self::KEY_PREFIX);
			},
			InvalidKeyEncodingException::class,
		);
		// str_replace() used to strip all prefix occurrences silently, substr() removes only the leading one
		Assert::exception(
			function (): void {
				new SymmetricKeyEncryption(['double' => self::KEY_PREFIX . '_' . self::KEY_PREFIX . '_' . bin2hex(random_bytes(32))], 'double', self::KEY_PREFIX);
			},
			InvalidKeyEncodingException::class,
		);
	}


	public function testConstructorExceptionsDoNotLeakKeyMaterial(): void
	{
		// No `use` capture on purpose: captured variables show up in raw traces of the closure frame itself
		$e = Assert::exception(
			function (): void {
				new SymmetricKeyEncryption(['truncated' => self::KEY_PREFIX . '_' . self::TRUNCATED_KEY], 'truncated', self::KEY_PREFIX);
			},
			InvalidKeyEncodingException::class,
		);
		$needle = substr(self::TRUNCATED_KEY, 0, 15); // getTraceAsString() truncates string arguments, check a prefix
		while ($e !== null) {
			Assert::notContains($needle, $e->getMessage());
			Assert::notContains($needle, $e->getTraceAsString());
			Assert::notContains($needle, print_r($e->getTrace(), true));
			$e = $e->getPrevious();
		}
	}


	public function testInvalidKeyPrefix(): void
	{
		Assert::exception(function (): void {
			new SymmetricKeyEncryption(['foo' => 'keyMaterial'], self::ACTIVE_KEY, self::KEY_PREFIX);
		}, InvalidKeyPrefixException::class, "Key 'foo' has no prefix");
		Assert::exception(function (): void {
			new SymmetricKeyEncryption(['foo' => self::KEY_PREFIX . 'Invalid_keyMaterial'], self::ACTIVE_KEY, self::KEY_PREFIX);
		}, InvalidKeyPrefixException::class, "Key 'foo' prefix is 'prefixInvalid' but it should be 'prefix'");
	}

}

(new SymmetricKeyEncryptionTest())->run();
