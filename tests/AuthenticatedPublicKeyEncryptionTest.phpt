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
use Spaze\Encryption\Exceptions\IncompleteKeyPairException;
use Spaze\Encryption\Exceptions\InvalidCipherTextFormatException;
use Spaze\Encryption\Exceptions\InvalidKeyEncodingException;
use Spaze\Encryption\Exceptions\InvalidKeyIdException;
use Spaze\Encryption\Exceptions\InvalidKeyLengthException;
use Spaze\Encryption\Exceptions\InvalidKeyPrefixException;
use Spaze\Encryption\Exceptions\InvalidKeyRoleException;
use Spaze\Encryption\Exceptions\InvalidNumberOfComponentsException;
use Spaze\Encryption\Exceptions\MissingKeyPrefixException;
use Spaze\Encryption\Exceptions\UnknownEncryptionKeyIdException;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/bootstrap.php';

/** @testCase */
class AuthenticatedPublicKeyEncryptionTest extends TestCase
{

	private const PLAINTEXT = 'foobar';

	private const INACTIVE_KEY = 'dev1';

	private const ACTIVE_KEY = 'dev2';

	private const KEY_PREFIX = 'prefix';

	private const TRUNCATED_KEY = 'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff012';

	private const FIXTURE_KEY_ID = 'fixture';

	private const FIXTURE_SECRET_KEY_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

	private const FIXTURE_OTHER_PARTY_SECRET_KEY_HEX = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';

	private const FIXTURE_AD = 'context';

	private const FIXTURE_CIPHERTEXT = '$fixture$MUIFAMRbUzVvsTa1ruJ1cwBKGxyz_UCpBNQHahdaS9xnn1sYq8S6OTdO_Q-TajtFicMm_wXL9ENqMLfKkfdpsGVp6zVP370u4C3FFoWPY2vm_GoLwrUYfD4PAhfmiE-ULcRraDi_03yehZhU0JSE5MvmtVc3d5J-_aGI_I0YtP79Jg==';

	private const FIXTURE_CIPHERTEXT_WITH_AD = '$fixture$MUIFAO1QOWgGPHLrGHgvrzpXA_7lUNgTuxmfV8LLP8uDtpQKxdDGTssw3XmedFoxrVPfWk9vqdRSrYBeiIvOu4NQUzeZtUlJnIWiLtgRXWjomHKPjvbqQQgksgeNoBho74O3eJ1UajVitRLFAD_bN-aIxDXY1X6jk43u7fP2ZP86ag==';

	private const FIXTURE_CIPHERTEXT_FROM_OTHER_PARTY = '$fixture$MUIFADmMiB4Kmq5Gi8fKn8zkW_ZV2Nds_LejRydwfAyuszG8EAV6jPCHlmh5gViNaHkYNRyRW1YPmlH9sNm54k_RfrOk-TIJubVGCq8byMyJrDNDp4yOxH6kHYXuyyx2lyc61vMbkgB2CRPd7R5rR4_NLRoE6qklMuLLT3_yYl7dSA==';

	/** @var array<string, string> */
	private array $ourSecretKeys;

	/** @var array<string, string> */
	private array $ourPublicKeys;

	/** @var array<string, string> */
	private array $theirSecretKeys;

	/** @var array<string, string> */
	private array $theirPublicKeys;

	private AuthenticatedPublicKeyEncryption $encryption;


	protected function setUp(): void
	{
		$this->ourSecretKeys = [];
		$this->ourPublicKeys = [];
		$this->theirSecretKeys = [];
		$this->theirPublicKeys = [];
		foreach ([self::INACTIVE_KEY, self::ACTIVE_KEY] as $id) {
			$ourKeyPair = sodium_crypto_box_keypair();
			$theirKeyPair = sodium_crypto_box_keypair();
			$this->ourSecretKeys[$id] = self::KEY_PREFIX . '_secret_' . bin2hex(sodium_crypto_box_secretkey($ourKeyPair));
			$this->ourPublicKeys[$id] = self::KEY_PREFIX . '_public_' . bin2hex(sodium_crypto_box_publickey($ourKeyPair));
			$this->theirSecretKeys[$id] = self::KEY_PREFIX . '_secret_' . bin2hex(sodium_crypto_box_secretkey($theirKeyPair));
			$this->theirPublicKeys[$id] = self::KEY_PREFIX . '_public_' . bin2hex(sodium_crypto_box_publickey($theirKeyPair));
		}
		$this->encryption = new AuthenticatedPublicKeyEncryption($this->ourSecretKeys, $this->theirPublicKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
	}


	public function testEncryptDecrypt(): void
	{
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($this->encryption->encrypt(self::PLAINTEXT)));
	}


	public function testDecryptStoredCipherText(): void
	{
		// Generated once when the feature was added and kept verbatim, because the output of this library is stored
		// in databases: anything that changes the format or the key handling has to fail here first
		$encryption = $this->createFixtureEncryption();
		Assert::same(self::PLAINTEXT, $encryption->decrypt(self::FIXTURE_CIPHERTEXT));
		Assert::same(self::PLAINTEXT, $encryption->decryptWithAd(self::FIXTURE_CIPHERTEXT_WITH_AD, self::FIXTURE_AD));
		// The same two keys work in both directions, so a value encrypted by the other party decrypts with our config
		Assert::same(self::PLAINTEXT, $encryption->decrypt(self::FIXTURE_CIPHERTEXT_FROM_OTHER_PARTY));
		Assert::false($encryption->needsReEncrypt(self::FIXTURE_CIPHERTEXT));
		// The encrypted part has the same shape as the symmetric class's output, only the key id tells them apart
		Assert::same('$fixture$MUIFA', substr(self::FIXTURE_CIPHERTEXT, 0, 14));
	}


	public function testBothDirections(): void
	{
		// The other party configures the mirror image: their own secret key and our public key
		$otherParty = new AuthenticatedPublicKeyEncryption($this->theirSecretKeys, $this->ourPublicKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $otherParty->decrypt($this->encryption->encrypt(self::PLAINTEXT)));
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($otherParty->encrypt(self::PLAINTEXT)));

		$ad = 'context';
		Assert::same(self::PLAINTEXT, $otherParty->decryptWithAd($this->encryption->encryptWithAd(self::PLAINTEXT, $ad), $ad));
		Assert::same(self::PLAINTEXT, $this->encryption->decryptWithAd($otherParty->encryptWithAd(self::PLAINTEXT, $ad), $ad));
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
		$inactiveKeyEncryption = new AuthenticatedPublicKeyEncryption($this->ourSecretKeys, $this->theirPublicKeys, self::INACTIVE_KEY, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
	}


	public function testNeedsReEncrypt(): void
	{
		$inactiveKeyEncryption = new AuthenticatedPublicKeyEncryption($this->ourSecretKeys, $this->theirPublicKeys, self::INACTIVE_KEY, self::KEY_PREFIX);
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
				new AuthenticatedPublicKeyEncryption($this->ourSecretKeys, $this->theirPublicKeys, 'foo', self::KEY_PREFIX);
			},
			ActiveKeyIdNotFoundException::class,
			"Unknown encryption key id: 'foo'",
		);
		Assert::type(UnknownEncryptionKeyIdException::class, $e);
		Assert::type(OutOfRangeException::class, $e);
		Assert::exception(
			function (): void {
				new AuthenticatedPublicKeyEncryption([], [], 'foo', self::KEY_PREFIX);
			},
			ActiveKeyIdNotFoundException::class,
		);
	}


	public function testConstructorIncompleteKeyPair(): void
	{
		Assert::exception(
			function (): void {
				new AuthenticatedPublicKeyEncryption($this->ourSecretKeys, [], self::ACTIVE_KEY, self::KEY_PREFIX);
			},
			IncompleteKeyPairException::class,
			"Key id 'dev1' needs both our secret key and the other party's public key",
		);
		Assert::exception(
			function (): void {
				new AuthenticatedPublicKeyEncryption([], $this->theirPublicKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
			},
			IncompleteKeyPairException::class,
		);
		// A numeric key id ends up as an integer array key but must still be reported as-is
		Assert::exception(
			function (): void {
				new AuthenticatedPublicKeyEncryption(['1' => $this->ourSecretKeys[self::ACTIVE_KEY]], [], '1', self::KEY_PREFIX);
			},
			IncompleteKeyPairException::class,
			"Key id '1' needs both our secret key and the other party's public key",
		);
	}


	public function testConstructorInvalidKeyRole(): void
	{
		// A secret key pasted where a public key belongs would produce data nobody can decrypt,
		// the tag makes that fail when the object is created instead
		Assert::exception(
			function (): void {
				new AuthenticatedPublicKeyEncryption($this->ourSecretKeys, $this->theirSecretKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
			},
			InvalidKeyRoleException::class,
			"Key 'dev1' is tagged as a secret key but is used as a public key",
		);
		Assert::exception(
			function (): void {
				new AuthenticatedPublicKeyEncryption($this->theirPublicKeys, $this->theirPublicKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
			},
			InvalidKeyRoleException::class,
			"Key 'dev1' is tagged as a public key but is used as a secret key",
		);
	}


	public function testConstructorUntaggedKeys(): void
	{
		// Values without the secret/public tag are accepted so existing configurations keep working unchanged,
		// and tagged and untagged values can live in the same array, which is what a migration looks like
		$secretKeys = $this->ourSecretKeys;
		$secretKeys[self::INACTIVE_KEY] = str_replace('_secret_', '_', $secretKeys[self::INACTIVE_KEY]);
		$publicKeys = [];
		foreach ($this->theirPublicKeys as $id => $key) {
			$publicKeys[$id] = str_replace('_public_', '_', $key);
		}
		$untagged = new AuthenticatedPublicKeyEncryption($secretKeys, $publicKeys, self::ACTIVE_KEY, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $untagged->decrypt($this->encryption->encrypt(self::PLAINTEXT)));
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($untagged->encrypt(self::PLAINTEXT)));
		// And a round trip through the untagged key id proves it decodes the same with and without the tag
		$inactiveKeyEncryption = new AuthenticatedPublicKeyEncryption($secretKeys, $publicKeys, self::INACTIVE_KEY, self::KEY_PREFIX);
		Assert::same(self::PLAINTEXT, $untagged->decrypt($inactiveKeyEncryption->encrypt(self::PLAINTEXT)));
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


	public function testSymmetricCipherTextFailsCleanly(): void
	{
		// The symmetric test's pinned ciphertext: same shape, same key id, different scheme —
		// it parses fine and only fails once decryption detects the data wasn't made with these keys
		$symmetricCipherText = '$fixture$MUIFAFMn4bpPdCBV2amSVcLrvBf1a1wlFG_tchfj5GtWwmmYjSYoE7xC5eDbsBMUQ-DbSPW6SPDEJWsef_i2QSXASoOORvWozIIBAXs-Cpsu0kx4ANL81yzSKM8YR9_MqW9RcIpzu6YVYZNXz5DadkJcc8R52YrAr34i7K3QTyNPEg==';
		Assert::exception(
			function () use ($symmetricCipherText): void {
				$this->createFixtureEncryption()->decrypt($symmetricCipherText);
			},
			InvalidMessage::class,
			'Invalid message authentication code',
		);
	}


	public function testRandomDataFailsCleanly(): void
	{
		// Values that were never produced by this class miss the version marker and fail before any key is used
		Assert::exception(
			function (): void {
				$this->encryption->decrypt('$' . self::ACTIVE_KEY . '$' . str_repeat('x', 96));
			},
			InvalidMessage::class,
			'Invalid version tag',
		);
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
		// Public keys aren't secret, but a secret key mispasted into the public keys array is exactly
		// the value that would otherwise show up in a trace, so both constructor arrays are masked
		$parameters = [
			(new ReflectionMethod(AuthenticatedPublicKeyEncryption::class, '__construct'))->getParameters()[0],
			(new ReflectionMethod(AuthenticatedPublicKeyEncryption::class, '__construct'))->getParameters()[1],
			(new ReflectionMethod(AuthenticatedPublicKeyEncryption::class, 'encrypt'))->getParameters()[0],
			(new ReflectionMethod(AuthenticatedPublicKeyEncryption::class, 'encryptWithAd'))->getParameters()[0],
		];
		foreach ($parameters as $parameter) {
			Assert::count(1, $parameter->getAttributes(SensitiveParameter::class));
		}
	}


	public function testHiddenStringKeys(): void
	{
		$object = print_r(new AuthenticatedPublicKeyEncryption($this->ourSecretKeys, $this->theirPublicKeys, self::ACTIVE_KEY, self::KEY_PREFIX), true);
		// The object stores only the decoded bytes, so those are the needles that matter:
		// checking just the config strings would pass even if the keys were stored as plain strings
		foreach ($this->ourSecretKeys as $key) {
			Assert::notContains($key, $object);
			Assert::notContains(sodium_hex2bin(substr($key, strlen(self::KEY_PREFIX . '_secret_'))), $object);
		}
		foreach ($this->theirPublicKeys as $key) {
			Assert::notContains($key, $object);
			Assert::notContains(sodium_hex2bin(substr($key, strlen(self::KEY_PREFIX . '_public_'))), $object);
		}
	}


	public function testConstructorInvalidKeyId(): void
	{
		// An empty key id would produce '$$<ciphertext>' which the parser rejects
		Assert::exception(
			function (): void {
				new AuthenticatedPublicKeyEncryption(['' => $this->ourSecretKeys[self::ACTIVE_KEY]], [], '', self::KEY_PREFIX);
			},
			InvalidKeyIdException::class,
			'Key id must not be empty',
		);
		// A key id with the separator would encrypt fine but produce output that can never be decrypted
		Assert::exception(
			function (): void {
				new AuthenticatedPublicKeyEncryption(['key$1' => $this->ourSecretKeys[self::ACTIVE_KEY]], [], 'key$1', self::KEY_PREFIX);
			},
			InvalidKeyIdException::class,
			"Key id 'key\$1' must not contain '\$'",
		);
	}


	public function testConstructorNumericKeyId(): void
	{
		// PHP casts a numeric key id to an integer, the constructor has to cope with that and not just with strings
		$secretKeys = ['1' => $this->ourSecretKeys[self::ACTIVE_KEY]];
		$publicKeys = ['1' => $this->theirPublicKeys[self::ACTIVE_KEY]];
		Assert::same([0 => 1], array_keys($secretKeys)); // the id is an int now, there's no way to keep it a string
		$encryption = new AuthenticatedPublicKeyEncryption($secretKeys, $publicKeys, '1', self::KEY_PREFIX);
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
				new AuthenticatedPublicKeyEncryption(['short' => self::KEY_PREFIX . '_secret_' . $shortKey], [], 'short', self::KEY_PREFIX);
			},
			InvalidKeyLengthException::class,
			"Key 'short' must be 32 bytes (64 hexadecimal characters) but is 16 bytes",
		);
		assert($e instanceof InvalidKeyLengthException);
		Assert::notContains($shortKey, $e->getMessage());
		// The public keys array is validated the same way as the secret keys array
		Assert::exception(
			function (): void {
				new AuthenticatedPublicKeyEncryption($this->ourSecretKeys, [self::ACTIVE_KEY => self::KEY_PREFIX . '_public_' . bin2hex(random_bytes(31))], self::ACTIVE_KEY, self::KEY_PREFIX);
			},
			InvalidKeyLengthException::class,
			"Key 'dev2' must be 32 bytes (64 hexadecimal characters) but is 31 bytes",
		);
	}


	public function testConstructorInvalidKeyEncoding(): void
	{
		$truncatedKey = substr(bin2hex(random_bytes(32)), 0, 63);
		$e = Assert::exception(
			function () use ($truncatedKey): void {
				new AuthenticatedPublicKeyEncryption(['truncated' => self::KEY_PREFIX . '_secret_' . $truncatedKey], [], 'truncated', self::KEY_PREFIX);
			},
			InvalidKeyEncodingException::class,
			"Key 'truncated' is not a valid hex-encoded string",
		);
		assert($e instanceof InvalidKeyEncodingException);
		Assert::type(SodiumException::class, $e->getPrevious());
		// The public keys array is validated the same way as the secret keys array
		Assert::exception(
			function (): void {
				new AuthenticatedPublicKeyEncryption($this->ourSecretKeys, [self::ACTIVE_KEY => self::KEY_PREFIX . '_public_' . str_repeat('xy', 32)], self::ACTIVE_KEY, self::KEY_PREFIX);
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
					new AuthenticatedPublicKeyEncryption(['truncated' => self::KEY_PREFIX . '_secret_' . self::TRUNCATED_KEY], [], 'truncated', self::KEY_PREFIX);
				},
				InvalidKeyEncodingException::class,
			),
			// The prefix appended instead of prepended, so it's the key material that comes before the separator
			Assert::exception(
				function (): void {
					new AuthenticatedPublicKeyEncryption(['inverted' => self::TRUNCATED_KEY . '_' . self::KEY_PREFIX], [], 'inverted', self::KEY_PREFIX);
				},
				InvalidKeyPrefixException::class,
			),
			Assert::exception(
				function (): void {
					new AuthenticatedPublicKeyEncryption(['bare' => self::TRUNCATED_KEY], [], 'bare', self::KEY_PREFIX);
				},
				MissingKeyPrefixException::class,
			),
			// A secret-tagged value in the public keys array: the message names the id and the tags, never the key itself
			Assert::exception(
				function (): void {
					new AuthenticatedPublicKeyEncryption([], ['swapped' => self::KEY_PREFIX . '_secret_' . self::TRUNCATED_KEY], 'swapped', self::KEY_PREFIX);
				},
				InvalidKeyRoleException::class,
			),
			// A valid secret key with no matching public key: thrown after the key was decoded and stored
			// ('a' appended to make the truncated key valid hex again)
			Assert::exception(
				function (): void {
					new AuthenticatedPublicKeyEncryption(['incomplete' => self::KEY_PREFIX . '_secret_' . self::TRUNCATED_KEY . 'a'], [], 'incomplete', self::KEY_PREFIX);
				},
				IncompleteKeyPairException::class,
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
			new AuthenticatedPublicKeyEncryption(['foo' => 'keyMaterial'], [], self::ACTIVE_KEY, self::KEY_PREFIX);
		}, MissingKeyPrefixException::class, "Key 'foo' must start with 'prefix_'");
		Assert::type(InvalidKeyPrefixException::class, $e);
		$e = Assert::exception(function (): void {
			new AuthenticatedPublicKeyEncryption(['foo' => self::KEY_PREFIX . 'Invalid_keyMaterial'], [], self::ACTIVE_KEY, self::KEY_PREFIX);
		}, InvalidKeyPrefixException::class, "Key 'foo' must start with 'prefix_'");
		// There is a prefix, it's just the wrong one, only the no-separator case throws the subclass
		Assert::false($e instanceof MissingKeyPrefixException);
	}


	private function createFixtureEncryption(): AuthenticatedPublicKeyEncryption
	{
		return new AuthenticatedPublicKeyEncryption(
			[self::FIXTURE_KEY_ID => self::KEY_PREFIX . '_secret_' . self::FIXTURE_SECRET_KEY_HEX],
			[self::FIXTURE_KEY_ID => self::KEY_PREFIX . '_public_' . $this->derivePublicKeyHex(self::FIXTURE_OTHER_PARTY_SECRET_KEY_HEX)],
			self::FIXTURE_KEY_ID,
			self::KEY_PREFIX,
		);
	}


	private function derivePublicKeyHex(string $secretKeyHex): string
	{
		return bin2hex(sodium_crypto_box_publickey_from_secretkey(sodium_hex2bin($secretKeyHex)));
	}

}

(new AuthenticatedPublicKeyEncryptionTest())->run();
