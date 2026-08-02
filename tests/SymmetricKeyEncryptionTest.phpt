<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\Encryption;

use OutOfBoundsException;
use OutOfRangeException;
use ParagonIE\Halite\Alerts\InvalidMessage;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;
use ReflectionMethod;
use SensitiveParameter;
use SodiumException;
use Spaze\Encryption\Exceptions\ActiveKeyIdNotFoundException;
use Spaze\Encryption\Exceptions\DecryptWithAdNeedsAdditionalDataException;
use Spaze\Encryption\Exceptions\EncryptWithAdNeedsAdditionalDataException;
use Spaze\Encryption\Exceptions\FormatMarkerMismatchException;
use Spaze\Encryption\Exceptions\InvalidCipherTextFormatException;
use Spaze\Encryption\Exceptions\InvalidKeyEncodingException;
use Spaze\Encryption\Exceptions\InvalidKeyIdException;
use Spaze\Encryption\Exceptions\InvalidKeyLengthException;
use Spaze\Encryption\Exceptions\InvalidKeyPrefixException;
use Spaze\Encryption\Exceptions\InvalidNumberOfComponentsException;
use Spaze\Encryption\Exceptions\MissingKeyPrefixException;
use Spaze\Encryption\Exceptions\UnknownEncryptionKeyIdException;
use Spaze\Encryption\Exceptions\UnknownFormatMarkerException;
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

	private const FIXTURE_CIPHERTEXT = '$fixture$SymV1$MUIFAHuQ7obWmIZ-e64OVH8PXwOKhp7o3tQkPWGsQB3qtu50Fhnn94ccFVV2BzJvGbxUyHXPBfdC4hNVLguO8ew0VJZTnu8K9Z2S9puYll9gDmFqA2UHmURJlpXN-SLEKt8Rz3MsIZDDbS5IF8TQTuYUy13PHjWeMcxWaB7Omkl0sQ==';

	private const FIXTURE_CIPHERTEXT_WITH_AD = '$fixture$SymAdV1$MUIFAO93FxYXZ9mmN2jmmz8F9GnuiHazJYE49Es_QUb5wRDVPqedn7HElHzf9nR69XhRD6kPnOQp0wDIc996rIzcT0URzJWfU-K73ZUAuI8AqZsDzq87WeGYHkr2WZb6MpbBvz9cKvztnNXvBXQXele98XNCpzCmCT5uQfrAK6HWcw==';

	private const LEGACY_FIXTURE_CIPHERTEXT = '$fixture$MUIFAFMn4bpPdCBV2amSVcLrvBf1a1wlFG_tchfj5GtWwmmYjSYoE7xC5eDbsBMUQ-DbSPW6SPDEJWsef_i2QSXASoOORvWozIIBAXs-Cpsu0kx4ANL81yzSKM8YR9_MqW9RcIpzu6YVYZNXz5DadkJcc8R52YrAr34i7K3QTyNPEg==';

	private const LEGACY_FIXTURE_CIPHERTEXT_WITH_AD = '$fixture$MUIFABiOZSY_QL4thZ54sv63zb5raG13LwzEmr2cZzHmRC0Au_YlTdbj0756cedYIm1LhiGHspLw-nlxRhBUq3iDOto2fzaQ5QZtYNRwFEGiZfa-6cp3tjOzn8dAtHZ8H-24w-f0RasPgi4Ir_2OXBvG7qWFyrfgm2h_htarJtvE_w==';

	/** @var array<string, string> */
	private array $keys;

	private SymmetricKeyEncryption $encryption;


	protected function setUp(): void
	{
		$this->keys = [
			self::INACTIVE_KEY => self::KEY_PREFIX . '_' . sodium_bin2hex(random_bytes(32)),
			self::ACTIVE_KEY => self::KEY_PREFIX . '_' . sodium_bin2hex(random_bytes(32)),
		];
		$this->encryption = new SymmetricKeyEncryption($this->keys, self::ACTIVE_KEY, self::KEY_PREFIX);
	}


	public function testEncryptDecrypt(): void
	{
		Assert::same(self::PLAINTEXT, $this->encryption->decrypt($this->encryption->encrypt(self::PLAINTEXT)));
	}


	public function testDecryptStoredCipherText(): void
	{
		// Generated once when the marked format was added and kept verbatim, because the output of this library
		// is stored in databases: anything that changes the format or the key handling has to fail here first
		$encryption = $this->createFixtureEncryption();
		Assert::same(self::PLAINTEXT, $encryption->decrypt(self::FIXTURE_CIPHERTEXT));
		Assert::same(self::PLAINTEXT, $encryption->decryptWithAd(self::FIXTURE_CIPHERTEXT_WITH_AD, self::FIXTURE_AD));
		Assert::false($encryption->needsReEncrypt(self::FIXTURE_CIPHERTEXT));
		Assert::false($encryption->needsReEncrypt(self::FIXTURE_CIPHERTEXT_WITH_AD));
		Assert::same('$fixture$SymV1$MUIFA', substr(self::FIXTURE_CIPHERTEXT, 0, 20));
		Assert::same('$fixture$SymAdV1$MUIFA', substr(self::FIXTURE_CIPHERTEXT_WITH_AD, 0, 22));
	}


	public function testDecryptStoredLegacyCipherText(): void
	{
		// Values in the format without the marker, written by all the previous releases, have to keep decrypting,
		// and needsReEncrypt() reports them so a re-encryption sweep migrates them to the marked format
		$encryption = $this->createFixtureEncryption();
		Assert::same(self::PLAINTEXT, $encryption->decrypt(self::LEGACY_FIXTURE_CIPHERTEXT));
		Assert::same(self::PLAINTEXT, $encryption->decryptWithAd(self::LEGACY_FIXTURE_CIPHERTEXT_WITH_AD, self::FIXTURE_AD));
		Assert::true($encryption->needsReEncrypt(self::LEGACY_FIXTURE_CIPHERTEXT));
		Assert::true($encryption->needsReEncrypt(self::LEGACY_FIXTURE_CIPHERTEXT_WITH_AD));
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
		// New values carry the marker, so mixing up the methods is caught by this library with a message
		// that says what to call, before the decryption itself would fail
		$encryptedWithAd = $this->encryption->encryptWithAd(self::PLAINTEXT, 'context');
		Assert::exception(function () use ($encryptedWithAd) {
			$this->encryption->decrypt($encryptedWithAd);
		}, FormatMarkerMismatchException::class, 'Data was encrypted with SymmetricKeyEncryption::encryptWithAd(), decrypt it with SymmetricKeyEncryption::decryptWithAd()');

		$encrypted = $this->encryption->encrypt(self::PLAINTEXT);
		Assert::exception(function () use ($encrypted) {
			$this->encryption->decryptWithAd($encrypted, 'context');
		}, FormatMarkerMismatchException::class, 'Data was encrypted with SymmetricKeyEncryption::encrypt(), decrypt it with SymmetricKeyEncryption::decrypt()');

		// Values without the marker have no such protection and fail only when the decryption itself does
		$fixtureEncryption = $this->createFixtureEncryption();
		Assert::exception(function () use ($fixtureEncryption) {
			$fixtureEncryption->decrypt(self::LEGACY_FIXTURE_CIPHERTEXT_WITH_AD);
		}, InvalidMessage::class);
		Assert::exception(function () use ($fixtureEncryption) {
			$fixtureEncryption->decryptWithAd(self::LEGACY_FIXTURE_CIPHERTEXT, self::FIXTURE_AD);
		}, InvalidMessage::class);
	}


	public function testKeyIdTamperingDetected(): void
	{
		// The key id and the marker go into what the decryption verifies. With every id mapping
		// to a different key a flipped id fails anyway, so the test uses the same key under two ids
		// (which the docs forbid) to prove the id itself is verified, not just the key it selects
		$encryption = new SymmetricKeyEncryption(
			['key1' => $this->keys[self::ACTIVE_KEY], 'key2' => $this->keys[self::ACTIVE_KEY]],
			'key1',
			self::KEY_PREFIX,
		);
		$tampered = str_replace('$key1$', '$key2$', $encryption->encrypt(self::PLAINTEXT));
		Assert::exception(
			function () use ($encryption, $tampered): void {
				$encryption->decrypt($tampered);
			},
			InvalidMessage::class,
		);
		$tamperedWithAd = str_replace('$key1$', '$key2$', $encryption->encryptWithAd(self::PLAINTEXT, 'context'));
		Assert::exception(
			function () use ($encryption, $tamperedWithAd): void {
				$encryption->decryptWithAd($tamperedWithAd, 'context');
			},
			InvalidMessage::class,
		);
	}


	public function testMarkerStrippingDetected(): void
	{
		// Rewriting a marked value into the older format must not decrypt it as if it were genuine old data:
		// the marker went into what the decryption verifies, so the downgrade fails there, not in the parser
		$stripped = str_replace('$SymV1$', '$', $this->encryption->encrypt(self::PLAINTEXT));
		Assert::exception(function () use ($stripped): void {
			$this->encryption->decrypt($stripped);
		}, InvalidMessage::class);

		$strippedWithAd = str_replace('$SymAdV1$', '$', $this->encryption->encryptWithAd(self::PLAINTEXT, 'context'));
		Assert::exception(function () use ($strippedWithAd): void {
			$this->encryption->decryptWithAd($strippedWithAd, 'context');
		}, InvalidMessage::class);
	}


	public function testMarkerForgingDetected(): void
	{
		// The opposite direction: a genuine old-format value rewritten into the marked format must not decrypt
		// either, old values were encrypted without the key id and the marker in what the decryption verifies
		$encryption = $this->createFixtureEncryption();
		$forged = str_replace('$fixture$', '$fixture$SymV1$', self::LEGACY_FIXTURE_CIPHERTEXT);
		Assert::exception(function () use ($encryption, $forged): void {
			$encryption->decrypt($forged);
		}, InvalidMessage::class);

		$forgedWithAd = str_replace('$fixture$', '$fixture$SymAdV1$', self::LEGACY_FIXTURE_CIPHERTEXT_WITH_AD);
		Assert::exception(function () use ($encryption, $forgedWithAd): void {
			$encryption->decryptWithAd($forgedWithAd, self::FIXTURE_AD);
		}, InvalidMessage::class);
	}


	public function testMarkerSwapDetected(): void
	{
		// Swapping the two symmetric markers makes the value acceptable to the other method's marker check,
		// so the rejection has to happen during the decryption itself; that the marker alone is enough
		// to make it fail is pinned separately by testBoundAdditionalDataRecipe()
		$swapped = str_replace('$SymV1$', '$SymAdV1$', $this->encryption->encrypt(self::PLAINTEXT));
		Assert::exception(function () use ($swapped): void {
			$this->encryption->decryptWithAd($swapped, 'context');
		}, InvalidMessage::class);

		$swappedWithAd = str_replace('$SymAdV1$', '$SymV1$', $this->encryption->encryptWithAd(self::PLAINTEXT, 'context'));
		Assert::exception(function () use ($swappedWithAd): void {
			$this->encryption->decrypt($swappedWithAd);
		}, InvalidMessage::class);
	}


	public function testBoundAdditionalDataRecipe(): void
	{
		// The README documents the verified value so the data can be decrypted with Halite directly,
		// and this rebuilds it exactly as described there: the recipe can never change unnoticed.
		// The wrong-marker attempt proves the marker itself is part of what the decryption verifies
		$key = new EncryptionKey(new HiddenString(sodium_hex2bin(substr(self::FIXTURE_KEY, strlen(self::KEY_PREFIX . '_')))));
		$cipherText = substr(self::FIXTURE_CIPHERTEXT_WITH_AD, strlen('$' . self::FIXTURE_KEY_ID . '$SymAdV1$'));
		$boundData = sprintf(
			'{"keyId":"%s","marker":"SymAdV1","additionalData":"%s"}',
			sodium_bin2base64(self::FIXTURE_KEY_ID, SODIUM_BASE64_VARIANT_URLSAFE),
			sodium_bin2base64(self::FIXTURE_AD, SODIUM_BASE64_VARIANT_URLSAFE),
		);
		Assert::same(self::PLAINTEXT, Crypto::decryptWithAD($cipherText, $key, $boundData)->getString());
		Assert::exception(function () use ($cipherText, $key, $boundData): void {
			Crypto::decryptWithAD($cipherText, $key, str_replace('SymAdV1', 'SymV1', $boundData));
		}, InvalidMessage::class);
	}


	public function testFormatMarkerMismatch(): void
	{
		// A value created by another class names its creator instead of failing with a misleading decryption error
		Assert::exception(
			function (): void {
				$this->encryption->decrypt('$' . self::ACTIVE_KEY . '$AnonV1$vJpOCa5fgshA9i4tKlRhW0OX6xd5iZeI');
			},
			FormatMarkerMismatchException::class,
			'Data was encrypted with AnonymousPublicKeyEncryption, decrypt it with AnonymousPublicKeyEncryption::decrypt()',
		);
		Assert::exception(
			function (): void {
				$this->encryption->decrypt('$' . self::ACTIVE_KEY . '$AuthV1$MUIFAwhatever');
			},
			FormatMarkerMismatchException::class,
			'Data was encrypted with AuthenticatedPublicKeyEncryption::encrypt(), decrypt it with AuthenticatedPublicKeyEncryption::decrypt()',
		);
	}


	public function testUnknownFormatMarker(): void
	{
		Assert::exception(
			function (): void {
				$this->encryption->needsReEncrypt('$' . self::ACTIVE_KEY . '$SymV9$whatever');
			},
			UnknownFormatMarkerException::class,
			"Unknown format marker 'SymV9', is the data corrupted, or encrypted by a newer version of this library?",
		);
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
			"Data format must be '\$keyId\$marker\$ciphertext' or '\$keyId\$ciphertext'",
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
			['$keyId$marker$ciphertext$whatsDiz'],
			['garbage$keyId$ciphertext'],
			['$keyId$'],
			['$keyId$marker$'],
			['$$marker$ciphertext'],
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
			"Data format must be '\$keyId\$marker\$ciphertext' or '\$keyId\$ciphertext'",
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
		// The object stores only the decoded bytes, so those are the needles that matter:
		// checking just the config strings would pass even if the keys were stored as plain strings
		foreach ($this->keys as $key) {
			Assert::notContains($key, $object);
			Assert::notContains(sodium_hex2bin(substr($key, strlen(self::KEY_PREFIX . '_'))), $object);
		}
	}


	public function testConstructorInvalidKeyId(): void
	{
		// An empty key id would produce '$$<ciphertext>' which the parser rejects
		Assert::exception(
			function (): void {
				new SymmetricKeyEncryption(['' => self::KEY_PREFIX . '_' . sodium_bin2hex(random_bytes(32))], '', self::KEY_PREFIX);
			},
			InvalidKeyIdException::class,
			'Key id must not be empty',
		);
		// A key id with the separator would encrypt fine but produce output that can never be decrypted
		Assert::exception(
			function (): void {
				new SymmetricKeyEncryption(['key$1' => self::KEY_PREFIX . '_' . sodium_bin2hex(random_bytes(32))], 'key$1', self::KEY_PREFIX);
			},
			InvalidKeyIdException::class,
			"Key id 'key\$1' must not contain '\$'",
		);
	}


	public function testConstructorKeyPastedAsKeyIdShortened(): void
	{
		// A whole key pasted into the id slot ends up repeated in the exception message,
		// so the message shows only the beginning of the id, like everywhere a stored value is repeated
		$keyAsId = self::TRUNCATED_KEY . 'a';
		$e = Assert::exception(
			function () use ($keyAsId): void {
				new SymmetricKeyEncryption([$keyAsId => 'garbage'], $keyAsId, self::KEY_PREFIX);
			},
			MissingKeyPrefixException::class,
			"Key '" . substr($keyAsId, 0, 20) . "...' must start with 'prefix_'",
		);
		assert($e instanceof MissingKeyPrefixException);
		Assert::notContains(substr($keyAsId, 20), $e->getMessage());
	}


	public function testConstructorNumericKeyId(): void
	{
		// PHP casts a numeric key id to an integer, the constructor has to cope with that and not just with strings
		$keys = ['1' => self::KEY_PREFIX . '_' . sodium_bin2hex(random_bytes(32))];
		Assert::same([0 => 1], array_keys($keys)); // the id is an int now, there's no way to keep it a string
		$encryption = new SymmetricKeyEncryption($keys, '1', self::KEY_PREFIX);
		$encrypted = $encryption->encrypt(self::PLAINTEXT);
		Assert::same('$1$SymV1$', substr($encrypted, 0, 9));
		Assert::same(self::PLAINTEXT, $encryption->decrypt($encrypted));
		Assert::false($encryption->needsReEncrypt($encrypted));
	}


	public function testConstructorInvalidKeyLength(): void
	{
		$shortKey = sodium_bin2hex(random_bytes(16));
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
				new SymmetricKeyEncryption(['bytes31' => self::KEY_PREFIX . '_' . sodium_bin2hex(random_bytes(31))], 'bytes31', self::KEY_PREFIX);
			},
			InvalidKeyLengthException::class,
			"Key 'bytes31' must be 32 bytes (64 hexadecimal characters) but is 31 bytes",
		);
	}


	public function testConstructorInvalidKeyEncoding(): void
	{
		$truncatedKey = substr(sodium_bin2hex(random_bytes(32)), 0, 63);
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
				new SymmetricKeyEncryption(['double' => self::KEY_PREFIX . '_' . self::KEY_PREFIX . '_' . sodium_bin2hex(random_bytes(32))], 'double', self::KEY_PREFIX);
			},
			InvalidKeyEncodingException::class,
		);
		// The secret/public tags of the public-key classes mean nothing here, a tagged value is just invalid hex:
		// the symmetric class must never start interpreting the tags
		Assert::exception(
			function (): void {
				new SymmetricKeyEncryption(['tagged' => self::KEY_PREFIX . '_secret_' . sodium_bin2hex(random_bytes(32))], 'tagged', self::KEY_PREFIX);
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


	private function createFixtureEncryption(): SymmetricKeyEncryption
	{
		return new SymmetricKeyEncryption([self::FIXTURE_KEY_ID => self::FIXTURE_KEY], self::FIXTURE_KEY_ID, self::KEY_PREFIX);
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
