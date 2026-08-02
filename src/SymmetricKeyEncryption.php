<?php
declare(strict_types = 1);

namespace Spaze\Encryption;

use JsonException;
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
use Spaze\Encryption\Format\FormatMarker;
use Spaze\Encryption\Format\KeyEnvelope;
use TypeError;

class SymmetricKeyEncryption
{

	use KeyEnvelope;


	/** @var array<string, HiddenString> */
	private array $keys = [];


	/**
	 * @param array<array-key, string> $keys key id => key
	 * @throws ActiveKeyIdNotFoundException
	 * @throws InvalidKeyEncodingException
	 * @throws InvalidKeyIdException
	 * @throws InvalidKeyLengthException
	 * @throws InvalidKeyPrefixException
	 * @throws MissingKeyPrefixException
	 */
	public function __construct(
		#[SensitiveParameter] array $keys,
		private string $activeKeyId,
		private string $keyPrefix,
	) {
		$this->keys = $this->decodeKeys($keys, $this->keyPrefix, SODIUM_CRYPTO_STREAM_KEYBYTES);
		if (!isset($this->keys[$this->activeKeyId])) {
			throw new ActiveKeyIdNotFoundException($this->activeKeyId);
		}
	}


	/**
	 * The key id and the marker go into what the decryption verifies, so changing them
	 * in the stored value makes decryption fail.
	 *
	 * @throws CannotPerformOperation
	 * @throws InvalidDigestLength
	 * @throws InvalidKey
	 * @throws InvalidMessage
	 * @throws InvalidType
	 * @throws JsonException
	 * @throws SodiumException
	 * @throws TypeError
	 */
	public function encrypt(#[SensitiveParameter] string $data): string
	{
		$key = $this->getKey($this->activeKeyId);
		$boundData = $this->buildBoundAdditionalData($this->activeKeyId, FormatMarker::SymmetricKeyV1);
		$cipherText = Crypto::encryptWithAD(new HiddenString($data), $key, $boundData);
		return $this->formatKeyCipherText($this->activeKeyId, FormatMarker::SymmetricKeyV1, $cipherText);
	}


	/**
	 * The key id and the marker are combined with the given additional data into what the decryption verifies,
	 * so changing them in the stored value makes decryption fail.
	 *
	 * @throws CannotPerformOperation
	 * @throws EncryptWithAdNeedsAdditionalDataException
	 * @throws InvalidDigestLength
	 * @throws InvalidKey
	 * @throws InvalidMessage
	 * @throws InvalidType
	 * @throws JsonException
	 * @throws SodiumException
	 * @throws TypeError
	 */
	public function encryptWithAd(#[SensitiveParameter] string $data, string $additionalData): string
	{
		if ($additionalData === '') {
			throw new EncryptWithAdNeedsAdditionalDataException();
		}
		$key = $this->getKey($this->activeKeyId);
		$boundData = $this->buildBoundAdditionalData($this->activeKeyId, FormatMarker::SymmetricKeyWithAdV1, $additionalData);
		$cipherText = Crypto::encryptWithAD(new HiddenString($data), $key, $boundData);
		return $this->formatKeyCipherText($this->activeKeyId, FormatMarker::SymmetricKeyWithAdV1, $cipherText);
	}


	/**
	 * @throws CannotPerformOperation
	 * @throws FormatMarkerMismatchException
	 * @throws InvalidDigestLength
	 * @throws InvalidKey
	 * @throws InvalidMessage
	 * @throws InvalidSignature
	 * @throws InvalidType
	 * @throws JsonException
	 * @throws SodiumException
	 * @throws TypeError
	 * @throws UnknownEncryptionKeyIdException
	 * @throws UnknownFormatMarkerException
	 * @throws InvalidCipherTextFormatException
	 * @throws InvalidNumberOfComponentsException
	 */
	public function decrypt(string $data): string
	{
		[$keyId, $marker, $cipherText] = $this->parseKeyCipherText($data);
		$validMarker = $this->checkFormatMarker($marker, FormatMarker::SymmetricKeyV1);
		$key = $this->getKey($keyId);
		if ($validMarker === null) {
			// Data from before the marker existed, nothing was added to what the decryption verifies back then
			return Crypto::decrypt($cipherText, $key)->getString();
		}
		$boundData = $this->buildBoundAdditionalData($keyId, $validMarker);
		return Crypto::decryptWithAD($cipherText, $key, $boundData)->getString();
	}


	/**
	 * @throws CannotPerformOperation
	 * @throws DecryptWithAdNeedsAdditionalDataException
	 * @throws FormatMarkerMismatchException
	 * @throws InvalidDigestLength
	 * @throws InvalidKey
	 * @throws InvalidMessage
	 * @throws InvalidSignature
	 * @throws InvalidType
	 * @throws JsonException
	 * @throws SodiumException
	 * @throws TypeError
	 * @throws UnknownEncryptionKeyIdException
	 * @throws UnknownFormatMarkerException
	 * @throws InvalidCipherTextFormatException
	 * @throws InvalidNumberOfComponentsException
	 */
	public function decryptWithAd(string $data, string $additionalData): string
	{
		if ($additionalData === '') {
			throw new DecryptWithAdNeedsAdditionalDataException();
		}
		[$keyId, $marker, $cipherText] = $this->parseKeyCipherText($data);
		$validMarker = $this->checkFormatMarker($marker, FormatMarker::SymmetricKeyWithAdV1);
		$key = $this->getKey($keyId);
		if ($validMarker === null) {
			// Data from before the marker existed, the additional data was used alone back then
			return Crypto::decryptWithAD($cipherText, $key, $additionalData)->getString();
		}
		$boundData = $this->buildBoundAdditionalData($keyId, $validMarker, $additionalData);
		return Crypto::decryptWithAD($cipherText, $key, $boundData)->getString();
	}


	/**
	 * Checks if the given data should be re-encrypted with the currently active key:
	 * either they are encrypted with an inactive key, or they are stored in the older format
	 * without the marker, and re-encrypting them adds it.
	 *
	 * @throws FormatMarkerMismatchException
	 * @throws InvalidCipherTextFormatException
	 * @throws InvalidNumberOfComponentsException
	 * @throws UnknownFormatMarkerException
	 */
	public function needsReEncrypt(string $data): bool
	{
		return $this->needsReEncryptMarked($data, $this->activeKeyId, FormatMarker::SymmetricKeyV1, FormatMarker::SymmetricKeyWithAdV1);
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

}
