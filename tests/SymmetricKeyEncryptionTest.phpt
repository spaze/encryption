<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\Encryption;

use OutOfBoundsException;
use OutOfRangeException;
use ParagonIE\Halite\Alerts\InvalidMessage;
use ReflectionMethod;
use SensitiveParameter;
use SodiumException;
use Spaze\Encryption\Exceptions\ActiveKeyIdNotFoundException;
use Spaze\Encryption\Exceptions\DecryptWithAdNeedsAdditionalDataException;
use Spaze\Encryption\Exceptions\EncryptWithAdNeedsAdditionalDataException;
use Spaze\Encryption\Exceptions\InvalidCipherTextFormatException;
use Spaze\Encryption\Exceptions\InvalidKeyEncodingException;
use Spaze\Encryption\Exceptions\InvalidKeyIdException;
use Spaze\Encryption\Exceptions\InvalidKeyLengthException;
use Spaze\Encryption\Exceptions\InvalidKeyPrefixException;
use Spaze\Encryption\Exceptions\InvalidNumberOfComponentsException;
use Spaze\Encryption\Exceptions\MissingKeyPrefixException;
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

	private const FIXTURE_KEY_ID = 'fixture';

	private const FIXTURE_KEY = self::KEY_PREFIX . '_00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

	private const FIXTURE_AD = 'context';

	private const FIXTURE_CIPHERTEXT = '$fixture$MUIFAFMn4bpPdCBV2amSVcLrvBf1a1wlFG_tchfj5GtWwmmYjSYoE7xC5eDbsBMUQ-DbSPW6SPDEJWsef_i2QSXASoOORvWozIIBAXs-Cpsu0kx4ANL81yzSKM8YR9_MqW9RcIpzu6YVYZNXz5DadkJcc8R52YrAr34i7K3QTyNPEg==';

	private const FIXTURE_CIPHERTEXT_WITH_AD = '$fixture$MUIFABiOZSY_QL4thZ54sv63zb5raG13LwzEmr2cZzHmRC0Au_YlTdbj0756cedYIm1LhiGHspLw-nlxRhBUq3iDOto2fzaQ5QZtYNRwFEGiZfa-6cp3tjOzn8dAtHZ8H-24w-f0RasPgi4Ir_2OXBvG7qWFyrfgm2h_htarJtvE_w==';

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


	public function testDecryptStoredCipherText(): void
	{
		// Encrypted with a previous release and kept verbatim, because the output of this library is stored
		// in databases: anything that changes the format or the key handling has to fail here first
		$encryption = new SymmetricKeyEncryption([self::FIXTURE_KEY_ID => self::FIXTURE_KEY], self::FIXTURE_KEY_ID, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $encryption->decrypt(self::FIXTURE_CIPHERTEXT));
		Assert::same(self::PLAINTEXT, $encryption->decryptWithAd(self::FIXTURE_CIPHERTEXT_WITH_AD, self::FIXTURE_AD));
		Assert::false($encryption->needsReEncrypt(self::FIXTURE_CIPHERTEXT));
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


	public function testConstructorActiveKeyIdNotFound(): void
	{
		$e = Assert::exception(
			function (): void {
				new SymmetricKeyEncryption($this->keys, 'foo', self::KEY_PREFIX);
			},
			ActiveKeyIdNotFoundException::class,
			"Unknown encryption key id: 'foo'",
		);
		Assert::type(UnknownEncryptionKeyIdException::class, $e);
		Assert::type(OutOfRangeException::class, $e);
		Assert::exception(
			function (): void {
				new SymmetricKeyEncryption([], 'foo', self::KEY_PREFIX);
			},
			ActiveKeyIdNotFoundException::class,
		);
	}


	public function testDecryptUnknownKeyId(): void
	{
		Assert::exception(
			function (): void {
				$this->encryption->decrypt('$unknown$x');
			},
			UnknownEncryptionKeyIdException::class,
			"Unknown encryption key id: 'unknown'",
		);
	}


	/** @dataProvider getInvalidEncryptedData */
	public function testDecryptInvalidCipherTextFormat(string $invalidData): void
	{
		$e = Assert::exception(
			function () use ($invalidData) {
				(new SymmetricKeyEncryption($this->keys, self::ACTIVE_KEY, self::KEY_PREFIX))->decrypt($invalidData);
			},
			InvalidCipherTextFormatException::class,
			"Data format must be '\$keyId\$ciphertext'",
		);
		Assert::type(OutOfBoundsException::class, $e);
		Assert::exception(
			function () use ($invalidData): void {
				$this->encryption->decryptWithAd($invalidData, 'context');
			},
			InvalidCipherTextFormatException::class,
		);
	}


	/**
	 * @return list<array{0:string}>
	 */
	public function getInvalidEncryptedData(): array
	{
		return [
			['nothing'],
			[''],
			['$keyId'],
			['$key$ciphertext$whatsDiz'],
			['garbage$keyId$ciphertext'],
			['$keyId$'],
			['$$ciphertext'],
			['$$'],
		];
	}


	public function testDecryptInvalidNumberOfComponents(): void
	{
		$e = Assert::exception(
			function (): void {
				$this->encryption->decrypt('nothing');
			},
			InvalidNumberOfComponentsException::class,
			"Data format must be '\$keyId\$ciphertext'",
		);
		Assert::type(InvalidCipherTextFormatException::class, $e);
		Assert::type(OutOfBoundsException::class, $e);
	}


	public function testNeedsReEncryptInvalidCipherTextFormat(): void
	{
		$e = Assert::exception(
			function (): void {
				$this->encryption->needsReEncrypt('foo$bar$baz');
			},
			InvalidCipherTextFormatException::class,
		);
		// The format guards throw the base class, only the component count check throws the subclass
		Assert::false($e instanceof InvalidNumberOfComponentsException);
	}


	public function testEncryptWithAdSensitiveParameter(): void
	{
		// The empty additionalData guard is the only throw site reachable with a valid construction,
		// so this is where the SensitiveParameter masking of the plaintext argument can be observed in a trace
		$e = Assert::exception(
			function (): void {
				$this->encryption->encryptWithAd(self::PLAINTEXT, '');
			},
			EncryptWithAdNeedsAdditionalDataException::class,
		);
		assert($e instanceof EncryptWithAdNeedsAdditionalDataException);
		Assert::notContains(self::PLAINTEXT, $e->getTraceAsString());
		Assert::contains('SensitiveParameterValue', $e->getTraceAsString());
	}


	public function testSensitiveParameterAttributes(): void
	{
		// encrypt() cannot be made to throw with a valid construction anymore, so pin its attribute directly
		$parameters = [
			(new ReflectionMethod(SymmetricKeyEncryption::class, '__construct'))->getParameters()[0],
			(new ReflectionMethod(SymmetricKeyEncryption::class, 'encrypt'))->getParameters()[0],
			(new ReflectionMethod(SymmetricKeyEncryption::class, 'encryptWithAd'))->getParameters()[0],
		];
		foreach ($parameters as $parameter) {
			Assert::count(1, $parameter->getAttributes(SensitiveParameter::class));
		}
	}


	public function testHiddenStringKeys(): void
	{
		$object = print_r(new SymmetricKeyEncryption($this->keys, self::ACTIVE_KEY, self::KEY_PREFIX), true);
		Assert::notContains($this->keys[self::ACTIVE_KEY], $object);
		Assert::notContains($this->keys[self::INACTIVE_KEY], $object);
	}


	public function testConstructorInvalidKeyId(): void
	{
		// An empty key id would produce '$$<ciphertext>' which the parser rejects
		Assert::exception(
			function (): void {
				new SymmetricKeyEncryption(['' => self::KEY_PREFIX . '_' . bin2hex(random_bytes(32))], '', self::KEY_PREFIX);
			},
			InvalidKeyIdException::class,
			'Key id must not be empty',
		);
		// A key id with the separator would encrypt fine but produce output that can never be decrypted
		Assert::exception(
			function (): void {
				new SymmetricKeyEncryption(['key$1' => self::KEY_PREFIX . '_' . bin2hex(random_bytes(32))], 'key$1', self::KEY_PREFIX);
			},
			InvalidKeyIdException::class,
			"Key id 'key\$1' must not contain '\$'",
		);
	}


	public function testConstructorNumericKeyId(): void
	{
		// PHP casts a numeric key id to an integer, the constructor has to cope with that and not just with strings
		$keys = ['1' => self::KEY_PREFIX . '_' . bin2hex(random_bytes(32))];
		Assert::same([0 => 1], array_keys($keys)); // the id is an int now, there's no way to keep it a string
		$encryption = new SymmetricKeyEncryption($keys, '1', self::KEY_PREFIX);
		$encrypted = $encryption->encrypt(self::PLAINTEXT);
		Assert::same('$1$', substr($encrypted, 0, 3));
		Assert::same(self::PLAINTEXT, $encryption->decrypt($encrypted));
		Assert::false($encryption->needsReEncrypt($encrypted));
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
		// The secret/public tags of the public-key classes mean nothing here, a tagged value is just invalid hex:
		// the symmetric class must never start interpreting the tags
		Assert::exception(
			function (): void {
				new SymmetricKeyEncryption(['tagged' => self::KEY_PREFIX . '_secret_' . bin2hex(random_bytes(32))], 'tagged', self::KEY_PREFIX);
			},
			InvalidKeyEncodingException::class,
		);
	}


	public function testConstructorExceptionsDoNotLeakKeyMaterial(): void
	{
		// No `use` capture on purpose: captured variables show up in raw traces of the closure frame itself
		$exceptions = [
			Assert::exception(
				function (): void {
					new SymmetricKeyEncryption(['truncated' => self::KEY_PREFIX . '_' . self::TRUNCATED_KEY], 'truncated', self::KEY_PREFIX);
				},
				InvalidKeyEncodingException::class,
			),
			// The prefix appended instead of prepended, so it's the key material that comes before the separator
			Assert::exception(
				function (): void {
					new SymmetricKeyEncryption(['inverted' => self::TRUNCATED_KEY . '_' . self::KEY_PREFIX], 'inverted', self::KEY_PREFIX);
				},
				InvalidKeyPrefixException::class,
			),
			Assert::exception(
				function (): void {
					new SymmetricKeyEncryption(['bare' => self::TRUNCATED_KEY], 'bare', self::KEY_PREFIX);
				},
				MissingKeyPrefixException::class,
			),
		];
		$needle = substr(self::TRUNCATED_KEY, 0, 15); // getTraceAsString() truncates string arguments, check a prefix
		foreach ($exceptions as $e) {
			while ($e !== null) {
				Assert::notContains($needle, $e->getMessage());
				Assert::notContains($needle, $e->getTraceAsString());
				Assert::notContains($needle, print_r($e->getTrace(), true));
				$e = $e->getPrevious();
			}
		}
	}


	public function testInvalidKeyPrefix(): void
	{
		// No separator at all, so there's no prefix to be wrong in the first place
		$e = Assert::exception(function (): void {
			new SymmetricKeyEncryption(['foo' => 'keyMaterial'], self::ACTIVE_KEY, self::KEY_PREFIX);
		}, MissingKeyPrefixException::class, "Key 'foo' must start with 'prefix_'");
		Assert::type(InvalidKeyPrefixException::class, $e);
		$e = Assert::exception(function (): void {
			new SymmetricKeyEncryption(['foo' => self::KEY_PREFIX . 'Invalid_keyMaterial'], self::ACTIVE_KEY, self::KEY_PREFIX);
		}, InvalidKeyPrefixException::class, "Key 'foo' must start with 'prefix_'");
		// There is a prefix, it's just the wrong one, only the no-separator case throws the subclass
		Assert::false($e instanceof MissingKeyPrefixException);
	}

}

(new SymmetricKeyEncryptionTest())->run();
