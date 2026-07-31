<?php
declare(strict_types = 1);

namespace Spaze\Encryption;

use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\InvalidDigestLength;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Alerts\InvalidMessage;
use ParagonIE\Halite\Alerts\InvalidSignature;
use ParagonIE\Halite\Alerts\InvalidType;
use ParagonIE\Halite\Asymmetric\Crypto;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\HiddenString\HiddenString;
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
use Spaze\Encryption\Format\AsymmetricKeyRole;
use Spaze\Encryption\Format\KeyEnvelope;
use TypeError;
use function array_keys;

class AuthenticatedPublicKeyEncryption
{

	use KeyEnvelope;


	/** @var array<string, HiddenString> */
	private array $secretKeys = [];

	/** @var array<string, HiddenString> */
	private array $publicKeys = [];


	/**
	 * Encryption between two parties: each side configures its own secret key and the other side's public key under the same key id.
	 * Both sides can encrypt and decrypt, and decryption only succeeds for data created with one of the two configured keys,
	 * so it also proves the data came from the other party, or from us.
	 *
	 * @param array<array-key, string> $secretKeys key id => our secret key
	 * @param array<array-key, string> $publicKeys key id => the other party's public key
	 * @throws ActiveKeyIdNotFoundException
	 * @throws IncompleteKeyPairException
	 * @throws InvalidKeyEncodingException
	 * @throws InvalidKeyIdException
	 * @throws InvalidKeyLengthException
	 * @throws InvalidKeyPrefixException
	 * @throws InvalidKeyRoleException
	 * @throws MissingKeyPrefixException
	 */
	public function __construct(
		#[SensitiveParameter] array $secretKeys,
		#[SensitiveParameter] array $publicKeys,
		private string $activeKeyId,
		private string $keyPrefix,
	) {
		$this->secretKeys = $this->decodeKeys($secretKeys, $this->keyPrefix, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, AsymmetricKeyRole::Secret);
		$this->publicKeys = $this->decodeKeys($publicKeys, $this->keyPrefix, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, AsymmetricKeyRole::Public);
		foreach (array_keys($secretKeys) as $id) {
			if (!isset($this->publicKeys[$id])) {
				throw new IncompleteKeyPairException((string)$id);
			}
		}
		foreach (array_keys($publicKeys) as $id) {
			if (!isset($this->secretKeys[$id])) {
				throw new IncompleteKeyPairException((string)$id);
			}
		}
		if (!isset($this->secretKeys[$this->activeKeyId])) {
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
		[$secretKey, $publicKey] = $this->getKeyPair($this->activeKeyId);
		$cipherText = Crypto::encrypt(new HiddenString($data), $secretKey, $publicKey);
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
		[$secretKey, $publicKey] = $this->getKeyPair($this->activeKeyId);
		$cipherText = Crypto::encryptWithAD(new HiddenString($data), $secretKey, $publicKey, $additionalData);
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
		[$secretKey, $publicKey] = $this->getKeyPair($keyId);
		return Crypto::decrypt($cipherText, $secretKey, $publicKey)->getString();
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
		[$secretKey, $publicKey] = $this->getKeyPair($keyId);
		return Crypto::decryptWithAD($cipherText, $secretKey, $publicKey, $additionalData)->getString();
	}


	/**
	 * Checks if the given data are encrypted with an inactive key
	 * and thus should be re-encrypted with the currently active one.
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
	 * The constructor guarantees a key id always has both keys, so one lookup can serve both.
	 *
	 * @return array{0:EncryptionSecretKey, 1:EncryptionPublicKey}
	 * @throws InvalidKey
	 * @throws TypeError
	 * @throws UnknownEncryptionKeyIdException
	 */
	private function getKeyPair(string $keyId): array
	{
		if (isset($this->secretKeys[$keyId], $this->publicKeys[$keyId])) {
			return [new EncryptionSecretKey($this->secretKeys[$keyId]), new EncryptionPublicKey($this->publicKeys[$keyId])];
		} else {
			throw new UnknownEncryptionKeyIdException($keyId);
		}
	}

}
