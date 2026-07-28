<?php
declare(strict_types = 1);

namespace Spaze\Encryption;

use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\InvalidDigestLength;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Alerts\InvalidMessage;
use ParagonIE\Halite\Alerts\InvalidSignature;
use ParagonIE\Halite\Alerts\InvalidType;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;
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
use Spaze\Encryption\Exceptions\UnknownEncryptionKeyIdException;
use TypeError;
use function count;
use function explode;

class SymmetricKeyEncryption
{

	private const KEY_CIPHERTEXT_SEPARATOR = '$';

	private const KEY_PREFIX_SEPARATOR = '_';

	/** @var array<string, HiddenString> */
	private array $keys = [];


	/**
	 * @param array<string, string> $keys key id => key
	 * @throws ActiveKeyIdNotFoundException
	 * @throws InvalidKeyEncodingException
	 * @throws InvalidKeyIdException
	 * @throws InvalidKeyLengthException
	 * @throws InvalidKeyPrefixException
	 */
	public function __construct(
		#[SensitiveParameter] array $keys,
		private string $activeKeyId,
		private string $keyPrefix,
	) {
		$keyPrefix = $this->keyPrefix . self::KEY_PREFIX_SEPARATOR;
		foreach ($keys as $id => $key) {
			if ($id === '' || str_contains($id, self::KEY_CIPHERTEXT_SEPARATOR)) {
				throw new InvalidKeyIdException($id, self::KEY_CIPHERTEXT_SEPARATOR);
			}
			if (!str_starts_with($key, $keyPrefix)) {
				$pos = strpos($key, self::KEY_PREFIX_SEPARATOR);
				throw new InvalidKeyPrefixException($id, $this->keyPrefix, $pos !== false ? substr($key, 0, $pos) : null);
			}
			try {
				$decodedKey = sodium_hex2bin(substr($key, strlen($keyPrefix)));
			} catch (SodiumException $e) {
				throw new InvalidKeyEncodingException($id, $e);
			}
			if (strlen($decodedKey) !== SODIUM_CRYPTO_STREAM_KEYBYTES) {
				throw new InvalidKeyLengthException($id, strlen($decodedKey));
			}
			$this->keys[$id] = new HiddenString($decodedKey);
		}
		if (!isset($this->keys[$this->activeKeyId])) {
			throw new ActiveKeyIdNotFoundException($this->activeKeyId);
		}
	}


	/**
	 * @throws CannotPerformOperation
	 * @throws InvalidDigestLength
	 * @throws InvalidKey
	 * @throws InvalidMessage
	 * @throws InvalidType
	 * @throws SodiumException
	 * @throws TypeError
	 */
	public function encrypt(#[SensitiveParameter] string $data): string
	{
		$key = $this->getKey($this->activeKeyId);
		$cipherText = Crypto::encrypt(new HiddenString($data), $key);
		return $this->formatKeyCipherText($this->activeKeyId, $cipherText);
	}


	/**
	 * @throws CannotPerformOperation
	 * @throws EncryptWithAdNeedsAdditionalDataException
	 * @throws InvalidDigestLength
	 * @throws InvalidKey
	 * @throws InvalidMessage
	 * @throws InvalidType
	 * @throws SodiumException
	 * @throws TypeError
	 */
	public function encryptWithAd(#[SensitiveParameter] string $data, string $additionalData): string
	{
		if ($additionalData === '') {
			throw new EncryptWithAdNeedsAdditionalDataException();
		}
		$key = $this->getKey($this->activeKeyId);
		$cipherText = Crypto::encryptWithAD(new HiddenString($data), $key, $additionalData);
		return $this->formatKeyCipherText($this->activeKeyId, $cipherText);
	}


	/**
	 * @throws CannotPerformOperation
	 * @throws InvalidDigestLength
	 * @throws InvalidKey
	 * @throws InvalidMessage
	 * @throws InvalidSignature
	 * @throws InvalidType
	 * @throws SodiumException
	 * @throws TypeError
	 * @throws UnknownEncryptionKeyIdException
	 * @throws InvalidCipherTextFormatException
	 * @throws InvalidNumberOfComponentsException
	 */
	public function decrypt(string $data): string
	{
		[$keyId, $cipherText] = $this->parseKeyCipherText($data);
		$key = $this->getKey($keyId);
		return Crypto::decrypt($cipherText, $key)->getString();
	}


	/**
	 * @throws CannotPerformOperation
	 * @throws DecryptWithAdNeedsAdditionalDataException
	 * @throws InvalidDigestLength
	 * @throws InvalidKey
	 * @throws InvalidMessage
	 * @throws InvalidSignature
	 * @throws InvalidType
	 * @throws SodiumException
	 * @throws TypeError
	 * @throws UnknownEncryptionKeyIdException
	 * @throws InvalidCipherTextFormatException
	 * @throws InvalidNumberOfComponentsException
	 */
	public function decryptWithAd(string $data, string $additionalData): string
	{
		if ($additionalData === '') {
			throw new DecryptWithAdNeedsAdditionalDataException();
		}
		[$keyId, $cipherText] = $this->parseKeyCipherText($data);
		$key = $this->getKey($keyId);
		return Crypto::decryptWithAD($cipherText, $key, $additionalData)->getString();
	}


	/**
	 * Checks if the given data are encrypted using the active key.
	 *
	 * @throws InvalidCipherTextFormatException
	 * @throws InvalidNumberOfComponentsException
	 */
	public function needsReEncrypt(string $data): bool
	{
		[$keyId] = $this->parseKeyCipherText($data);
		return $keyId !== $this->activeKeyId;
	}


	/**
	 * @throws InvalidKey
	 * @throws TypeError
	 * @throws UnknownEncryptionKeyIdException
	 */
	private function getKey(string $keyId): EncryptionKey
	{
		if (isset($this->keys[$keyId])) {
			return new EncryptionKey($this->keys[$keyId]);
		} else {
			throw new UnknownEncryptionKeyIdException($keyId);
		}
	}


	/**
	 * @return array{0:non-empty-string, 1:non-empty-string}
	 * @throws InvalidCipherTextFormatException
	 * @throws InvalidNumberOfComponentsException
	 */
	private function parseKeyCipherText(string $data): array
	{
		$data = explode(self::KEY_CIPHERTEXT_SEPARATOR, $data);
		if (count($data) !== 3) {
			throw new InvalidNumberOfComponentsException();
		}
		if ($data[0] !== '' || $data[1] === '' || $data[2] === '') {
			throw new InvalidCipherTextFormatException();
		}
		return [$data[1], $data[2]];
	}


	private function formatKeyCipherText(string $keyId, string $cipherText): string
	{
		return self::KEY_CIPHERTEXT_SEPARATOR . $keyId . self::KEY_CIPHERTEXT_SEPARATOR . $cipherText;
	}

}
