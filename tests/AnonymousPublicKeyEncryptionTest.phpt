<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\Encryption;

use OutOfBoundsException;
use OutOfRangeException;
use ParagonIE\Halite\Alerts\InvalidKey;
use ReflectionMethod;
use SensitiveParameter;
use SodiumException;
use Spaze\Encryption\Exceptions\ActiveKeyIdNotFoundException;
use Spaze\Encryption\Exceptions\InvalidCipherTextFormatException;
use Spaze\Encryption\Exceptions\InvalidKeyEncodingException;
use Spaze\Encryption\Exceptions\InvalidKeyIdException;
use Spaze\Encryption\Exceptions\InvalidKeyLengthException;
use Spaze\Encryption\Exceptions\InvalidKeyPrefixException;
use Spaze\Encryption\Exceptions\InvalidKeyRoleException;
use Spaze\Encryption\Exceptions\InvalidNumberOfComponentsException;
use Spaze\Encryption\Exceptions\KeyPairMismatchException;
use Spaze\Encryption\Exceptions\MissingKeyPrefixException;
use Spaze\Encryption\Exceptions\MissingSecretKeyException;
use Spaze\Encryption\Exceptions\UnknownEncryptionKeyIdException;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/bootstrap.php';

/** @testCase */
class AnonymousPublicKeyEncryptionTest extends TestCase
{

	private const PLAINTEXT = 'foobar';

	private const INACTIVE_KEY = 'dev1';

	private const ACTIVE_KEY = 'dev2';

	private const KEY_PREFIX = 'prefix';

	private const TRUNCATED_KEY = 'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff012';

	private const FIXTURE_KEY_ID = 'fixture';

	private const FIXTURE_SECRET_KEY_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

	private const FIXTURE_CIPHERTEXT = '$fixture$DFuorlqIBtLKXuQB3WOwXP8uKem5PeQsCOB3VagYhja53nngvZMAoiAYvsyUhWE7BUi2spav';

	/** @var array<string, string> */
	private array $secretKeys;

	/** @var array<string, string> */
	private array $publicKeys;

	private AnonymousPublicKeyEncryption $encryption;


	protected function setUp(): void
	{
		$this->secretKeys = [];
		$this->publicKeys = [];
		foreach ([self::INACTIVE_KEY, self::ACTIVE_KEY] as $id) {
			$keyPair = sodium_crypto_box_keypair();
			$this->secretKeys[$id] = self::KEY_PREFIX . '_secret_' . bin2hex(sodium_crypto_box_secretkey($keyPair));
			$this->publicKeys[$id] = self::KEY_PREFIX . '_public_' . bin2hex(sodium_crypto_box_publickey($keyPair));
		}
		$this->encryption = new AnonymousPublicKeyEncryption($this->secretKeys, $this->publicKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
	}


	public function testEncryptDecrypt(): void
	{
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($this->encryption->encrypt(self::PLAINTEXT)));
	}


	public function testEncryptDecryptWithDerivedPublicKeys(): void
	{
		// Public keys left out completely, they are derived from the secret keys
		$encryption = new AnonymousPublicKeyEncryption($this->secretKeys, [], self::ACTIVE_KEY, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $encryption->decrypt($encryption->encrypt(self::PLAINTEXT)));
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($encryption->encrypt(self::PLAINTEXT)));
	}


	public function testEncryptOnlyDeployment(): void
	{
		// The whole point: a deployment configured with just the public keys can store data it can never read back
		$encryptOnly = new AnonymousPublicKeyEncryption([], $this->publicKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
		$encrypted = $encryptOnly->encrypt(self::PLAINTEXT);
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($encrypted));
		Assert::exception(
			function () use ($encryptOnly, $encrypted): void {
				$encryptOnly->decrypt($encrypted);
			},
			MissingSecretKeyException::class,
			"No secret key configured for key id 'dev2', it can only be used to encrypt",
		);
	}


	public function testDecryptStoredCipherText(): void
	{
		// Generated once when the feature was added and kept verbatim, because the output of this library is stored
		// in databases: anything that changes the format or the key handling has to fail here first
		$encryption = new AnonymousPublicKeyEncryption([self::FIXTURE_KEY_ID => self::KEY_PREFIX . '_secret_' . self::FIXTURE_SECRET_KEY_HEX], [], self::FIXTURE_KEY_ID, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $encryption->decrypt(self::FIXTURE_CIPHERTEXT));
		Assert::false($encryption->needsReEncrypt(self::FIXTURE_CIPHERTEXT));
		// Unlike the other two classes, the encrypted part carries no version marker, it looks like random data
		Assert::notSame('$fixture$MUIFA', substr(self::FIXTURE_CIPHERTEXT, 0, 14));
	}


	public function testMissingSecretKeyException(): void
	{
		// Deliberately not a subclass of UnknownEncryptionKeyIdException: the id is known,
		// this deployment just can't decrypt with it, only encrypt
		$e = Assert::exception(
			function (): void {
				$encryption = new AnonymousPublicKeyEncryption([], $this->publicKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
				$encryption->decrypt($encryption->encrypt(self::PLAINTEXT));
			},
			MissingSecretKeyException::class,
		);
		Assert::type(OutOfRangeException::class, $e);
		// The hierarchy is the contract here: code catching UnknownEncryptionKeyIdException must not swallow
		// this one, and PHPStan reports any assertion of that as statically always-false, so it guards it instead
	}


	public function testKeyPairMismatch(): void
	{
		// The public keys swapped between the two ids: each secret key gets a public key from a different pair
		$swappedPublicKeys = [
			self::INACTIVE_KEY => $this->publicKeys[self::ACTIVE_KEY],
			self::ACTIVE_KEY => $this->publicKeys[self::INACTIVE_KEY],
		];
		Assert::exception(
			function () use ($swappedPublicKeys): void {
				new AnonymousPublicKeyEncryption($this->secretKeys, $swappedPublicKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
			},
			KeyPairMismatchException::class,
			"Public key 'dev1' is not the public half of secret key 'dev1'",
		);
	}


	public function testRotationWithOldSecretAndNewPublicKey(): void
	{
		// Re-encryption after a rotation runs where the secret keys live: the old secret key decrypts,
		// the new public key encrypts, and the new secret key doesn't have to be present at all
		$oldKeyEncryption = new AnonymousPublicKeyEncryption([self::INACTIVE_KEY => $this->secretKeys[self::INACTIVE_KEY]], [], self::INACTIVE_KEY, self::KEY_PREFIX);
		$oldData = $oldKeyEncryption->encrypt(self::PLAINTEXT);

		$rotation = new AnonymousPublicKeyEncryption(
			[self::INACTIVE_KEY => $this->secretKeys[self::INACTIVE_KEY]],
			[self::ACTIVE_KEY => $this->publicKeys[self::ACTIVE_KEY]],
			self::ACTIVE_KEY,
			self::KEY_PREFIX,
		);
		Assert::true($rotation->needsReEncrypt($oldData));
		$newData = $rotation->encrypt($rotation->decrypt($oldData));
		Assert::false($rotation->needsReEncrypt($newData));
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($newData));
	}


	public function testEncryptInactiveKeyDecrypt(): void
	{
		$inactiveKeyEncryption = new AnonymousPublicKeyEncryption($this->secretKeys, $this->publicKeys, self::INACTIVE_KEY, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
	}


	public function testNeedsReEncrypt(): void
	{
		$inactiveKeyEncryption = new AnonymousPublicKeyEncryption($this->secretKeys, $this->publicKeys, self::INACTIVE_KEY, self::KEY_PREFIX);
		Assert::false($inactiveKeyEncryption->needsReEncrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
		Assert::true($this->encryption->needsReEncrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
		Assert::true($inactiveKeyEncryption->needsReEncrypt($this->encryption->encrypt(self::PLAINTEXT)));
	}


	public function testNoAdditionalDataMethods(): void
	{
		// Deliberately absent: this flavor can't bind the encrypted value to a context,
		// and no method at all beats a method that can only throw
		Assert::false(method_exists($this->encryption, 'encryptWithAd'));
		Assert::false(method_exists($this->encryption, 'decryptWithAd'));
	}


	public function testConstructorActiveKeyIdNotFound(): void
	{
		$e = Assert::exception(
			function (): void {
				new AnonymousPublicKeyEncryption($this->secretKeys, $this->publicKeys, 'foo', self::KEY_PREFIX);
			},
			ActiveKeyIdNotFoundException::class,
			"Unknown encryption key id: 'foo'",
		);
		Assert::type(UnknownEncryptionKeyIdException::class, $e);
		Assert::type(OutOfRangeException::class, $e);
		Assert::exception(
			function (): void {
				new AnonymousPublicKeyEncryption([], [], 'foo', self::KEY_PREFIX);
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
				$this->encryption->decrypt($invalidData);
			},
			InvalidCipherTextFormatException::class,
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


	public function testForeignCipherTextFailsCleanly(): void
	{
		// The symmetric test's pinned ciphertext under the same key id: Halite reports any value
		// it cannot decrypt as a wrong key, corrupted data and data from the other classes look the same
		$symmetricCipherText = '$fixture$MUIFAFMn4bpPdCBV2amSVcLrvBf1a1wlFG_tchfj5GtWwmmYjSYoE7xC5eDbsBMUQ-DbSPW6SPDEJWsef_i2QSXASoOORvWozIIBAXs-Cpsu0kx4ANL81yzSKM8YR9_MqW9RcIpzu6YVYZNXz5DadkJcc8R52YrAr34i7K3QTyNPEg==';
		Assert::exception(
			function () use ($symmetricCipherText): void {
				$encryption = new AnonymousPublicKeyEncryption([self::FIXTURE_KEY_ID => self::KEY_PREFIX . '_secret_' . self::FIXTURE_SECRET_KEY_HEX], [], self::FIXTURE_KEY_ID, self::KEY_PREFIX);
				$encryption->decrypt($symmetricCipherText);
			},
			InvalidKey::class,
			'Incorrect secret key for this sealed message',
		);
	}


	public function testSensitiveParameterAttributes(): void
	{
		// Public keys aren't secret, but a secret key mispasted into the public keys array is exactly
		// the value that would otherwise show up in a trace, so both constructor arrays are masked
		$parameters = [
			(new ReflectionMethod(AnonymousPublicKeyEncryption::class, '__construct'))->getParameters()[0],
			(new ReflectionMethod(AnonymousPublicKeyEncryption::class, '__construct'))->getParameters()[1],
			(new ReflectionMethod(AnonymousPublicKeyEncryption::class, 'encrypt'))->getParameters()[0],
		];
		foreach ($parameters as $parameter) {
			Assert::count(1, $parameter->getAttributes(SensitiveParameter::class));
		}
	}


	public function testHiddenStringKeys(): void
	{
		$object = print_r(new AnonymousPublicKeyEncryption($this->secretKeys, $this->publicKeys, self::ACTIVE_KEY, self::KEY_PREFIX), true);
		// The object stores only the decoded bytes, so those are the needles that matter:
		// checking just the config strings would pass even if the keys were stored as plain strings
		foreach ($this->secretKeys as $key) {
			Assert::notContains($key, $object);
			Assert::notContains(sodium_hex2bin(substr($key, strlen(self::KEY_PREFIX . '_secret_'))), $object);
		}
		foreach ($this->publicKeys as $key) {
			Assert::notContains($key, $object);
			Assert::notContains(sodium_hex2bin(substr($key, strlen(self::KEY_PREFIX . '_public_'))), $object);
		}
	}


	public function testConstructorInvalidKeyId(): void
	{
		// An empty key id would produce '$$<ciphertext>' which the parser rejects
		Assert::exception(
			function (): void {
				new AnonymousPublicKeyEncryption(['' => $this->secretKeys[self::ACTIVE_KEY]], [], '', self::KEY_PREFIX);
			},
			InvalidKeyIdException::class,
			'Key id must not be empty',
		);
		// A key id with the separator would encrypt fine but produce output that can never be decrypted
		Assert::exception(
			function (): void {
				new AnonymousPublicKeyEncryption([], ['key$1' => $this->publicKeys[self::ACTIVE_KEY]], 'key$1', self::KEY_PREFIX);
			},
			InvalidKeyIdException::class,
			"Key id 'key\$1' must not contain '\$'",
		);
	}


	public function testConstructorNumericKeyId(): void
	{
		// PHP casts a numeric key id to an integer, the constructor has to cope with that and not just with strings
		$secretKeys = ['1' => $this->secretKeys[self::ACTIVE_KEY]];
		Assert::same([0 => 1], array_keys($secretKeys)); // the id is an int now, there's no way to keep it a string
		$encryption = new AnonymousPublicKeyEncryption($secretKeys, [], '1', self::KEY_PREFIX);
		$encrypted = $encryption->encrypt(self::PLAINTEXT);
		Assert::same('$1$', substr($encrypted, 0, 3));
		Assert::same(self::PLAINTEXT, $encryption->decrypt($encrypted));
		Assert::false($encryption->needsReEncrypt($encrypted));
		// And a mismatched pair under a numeric id must still be reported with the id as configured
		Assert::exception(
			function () use ($secretKeys): void {
				new AnonymousPublicKeyEncryption($secretKeys, ['1' => $this->publicKeys[self::INACTIVE_KEY]], '1', self::KEY_PREFIX);
			},
			KeyPairMismatchException::class,
			"Public key '1' is not the public half of secret key '1'",
		);
	}


	public function testConstructorInvalidKeyRole(): void
	{
		// A secret key pasted where a public key belongs would produce data nobody can decrypt,
		// the tag makes that fail when the object is created instead
		Assert::exception(
			function (): void {
				new AnonymousPublicKeyEncryption([], $this->secretKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
			},
			InvalidKeyRoleException::class,
			"Key 'dev1' is tagged as a secret key but is used as a public key",
		);
		Assert::exception(
			function (): void {
				new AnonymousPublicKeyEncryption($this->publicKeys, [], self::ACTIVE_KEY, self::KEY_PREFIX);
			},
			InvalidKeyRoleException::class,
			"Key 'dev1' is tagged as a public key but is used as a secret key",
		);
	}


	public function testConstructorUntaggedKeys(): void
	{
		// Values without the secret/public tag are accepted so existing configurations keep working unchanged,
		// tagged and untagged values can live in the same array (which is what a migration looks like),
		// and the pair check still runs on untagged values
		$secretKeys = $this->secretKeys;
		$secretKeys[self::INACTIVE_KEY] = str_replace('_secret_', '_', $secretKeys[self::INACTIVE_KEY]);
		$publicKeys = [];
		foreach ($this->publicKeys as $id => $key) {
			$publicKeys[$id] = str_replace('_public_', '_', $key);
		}
		$untagged = new AnonymousPublicKeyEncryption($secretKeys, $publicKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $untagged->decrypt($this->encryption->encrypt(self::PLAINTEXT)));
		// And a round trip through the untagged key id proves it decodes the same with and without the tag
		$inactiveKeyEncryption = new AnonymousPublicKeyEncryption($secretKeys, $publicKeys, self::INACTIVE_KEY, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $untagged->decrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
		Assert::exception(
			function () use ($secretKeys): void {
				new AnonymousPublicKeyEncryption($secretKeys, [self::ACTIVE_KEY => str_replace('_public_', '_', $this->publicKeys[self::INACTIVE_KEY])], self::ACTIVE_KEY, self::KEY_PREFIX);
			},
			KeyPairMismatchException::class,
		);
	}


	public function testConstructorInvalidKeyLength(): void
	{
		$shortKey = bin2hex(random_bytes(16));
		$e = Assert::exception(
			function () use ($shortKey): void {
				new AnonymousPublicKeyEncryption(['short' => self::KEY_PREFIX . '_secret_' . $shortKey], [], 'short', self::KEY_PREFIX);
			},
			InvalidKeyLengthException::class,
			"Key 'short' must be 32 bytes (64 hexadecimal characters) but is 16 bytes",
		);
		assert($e instanceof InvalidKeyLengthException);
		Assert::notContains($shortKey, $e->getMessage());
		// The public keys array is validated the same way as the secret keys array
		Assert::exception(
			function (): void {
				new AnonymousPublicKeyEncryption([], ['bytes31' => self::KEY_PREFIX . '_public_' . bin2hex(random_bytes(31))], 'bytes31', self::KEY_PREFIX);
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
				new AnonymousPublicKeyEncryption(['truncated' => self::KEY_PREFIX . '_secret_' . $truncatedKey], [], 'truncated', self::KEY_PREFIX);
			},
			InvalidKeyEncodingException::class,
			"Key 'truncated' is not a valid hex-encoded string",
		);
		assert($e instanceof InvalidKeyEncodingException);
		Assert::type(SodiumException::class, $e->getPrevious());
		// The public keys array is validated the same way as the secret keys array
		Assert::exception(
			function (): void {
				new AnonymousPublicKeyEncryption([], ['nonhex' => self::KEY_PREFIX . '_public_' . str_repeat('xy', 32)], 'nonhex', self::KEY_PREFIX);
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
					new AnonymousPublicKeyEncryption(['truncated' => self::KEY_PREFIX . '_secret_' . self::TRUNCATED_KEY], [], 'truncated', self::KEY_PREFIX);
				},
				InvalidKeyEncodingException::class,
			),
			// The prefix appended instead of prepended, so it's the key material that comes before the separator
			Assert::exception(
				function (): void {
					new AnonymousPublicKeyEncryption(['inverted' => self::TRUNCATED_KEY . '_' . self::KEY_PREFIX], [], 'inverted', self::KEY_PREFIX);
				},
				InvalidKeyPrefixException::class,
			),
			Assert::exception(
				function (): void {
					new AnonymousPublicKeyEncryption(['bare' => self::TRUNCATED_KEY], [], 'bare', self::KEY_PREFIX);
				},
				MissingKeyPrefixException::class,
			),
			// A secret-tagged value in the public keys array: the message names the id and the tags, never the key itself
			Assert::exception(
				function (): void {
					new AnonymousPublicKeyEncryption([], ['swapped' => self::KEY_PREFIX . '_secret_' . self::TRUNCATED_KEY], 'swapped', self::KEY_PREFIX);
				},
				InvalidKeyRoleException::class,
			),
			// A mismatched pair: the message names the id only ('a' appended to make the truncated key valid hex again)
			Assert::exception(
				function (): void {
					new AnonymousPublicKeyEncryption(
						['mismatched' => self::KEY_PREFIX . '_secret_' . self::TRUNCATED_KEY . 'a'],
						['mismatched' => self::KEY_PREFIX . '_public_' . self::TRUNCATED_KEY . 'a'],
						'mismatched',
						self::KEY_PREFIX,
					);
				},
				KeyPairMismatchException::class,
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
			new AnonymousPublicKeyEncryption(['foo' => 'keyMaterial'], [], self::ACTIVE_KEY, self::KEY_PREFIX);
		}, MissingKeyPrefixException::class, "Key 'foo' must start with 'prefix_'");
		Assert::type(InvalidKeyPrefixException::class, $e);
		$e = Assert::exception(function (): void {
			new AnonymousPublicKeyEncryption(['foo' => self::KEY_PREFIX . 'Invalid_keyMaterial'], [], self::ACTIVE_KEY, self::KEY_PREFIX);
		}, InvalidKeyPrefixException::class, "Key 'foo' must start with 'prefix_'");
		// There is a prefix, it's just the wrong one, only the no-separator case throws the subclass
		Assert::false($e instanceof MissingKeyPrefixException);
	}

}

(new AnonymousPublicKeyEncryptionTest())->run();
