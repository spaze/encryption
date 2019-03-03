<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Symmetric;

use ParagonIE\Halite\Symmetric;
use ParagonIE\HiddenString\HiddenString;

/**
 * StaticKey encryption service.
 *
 * @author Michal Špaček
 */
class StaticKey
{

	use \Nette\SmartObject;

	private const KEY_CIPHERTEXT_SEPARATOR = '$';

	/** @var string[][] */
	private $keys;

	/** @var string[] */
	private $activeKeyIds;

	/** @var string */
	private $keyGroup;


	/**
	 * StaticKey constructor.
	 *
	 * @param string $keyGroup The group from which to read the key
	 * @param string[][] $keys
	 * @param string[] $activeKeyIds
	 */
	public function __construct(string $keyGroup, array $keys, array $activeKeyIds)
	{
		$this->keyGroup = $keyGroup;
		$this->keys = $keys;
		$this->activeKeyIds = $activeKeyIds;
	}


	/**
	 * Encrypt data using symmetric encryption.
	 *
	 * It's safe to throw exceptions here as the stack trace will not contain the key,
	 * because the key is not passed as a parameter to the function.
	 *
	 * @param string $data The plaintext
	 * @return string
	 * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
	 * @throws \ParagonIE\Halite\Alerts\InvalidDigestLength
	 * @throws \ParagonIE\Halite\Alerts\InvalidKey
	 * @throws \ParagonIE\Halite\Alerts\InvalidMessage
	 * @throws \ParagonIE\Halite\Alerts\InvalidType
	 * @throws \TypeError
	 */
	public function encrypt(string $data): string
	{
		$keyId = $this->getActiveKeyId();
		$key = $this->getKey($keyId);
		$cipherText = Symmetric\Crypto::encrypt(new HiddenString($data), $key);
		return $this->formatKeyCipherText($keyId, $cipherText);
	}


	/**
	 * Decrypt data using symmetric encryption.
	 *
	 * @param string $data
	 * @return string
	 * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
	 * @throws \ParagonIE\Halite\Alerts\InvalidDigestLength
	 * @throws \ParagonIE\Halite\Alerts\InvalidKey
	 * @throws \ParagonIE\Halite\Alerts\InvalidMessage
	 * @throws \ParagonIE\Halite\Alerts\InvalidSignature
	 * @throws \ParagonIE\Halite\Alerts\InvalidType
	 * @throws \TypeError
	 */
	public function decrypt(string $data): string
	{
		list($keyId, $cipherText) = $this->parseKeyCipherText($data);
		$key = $this->getKey($keyId);
		return Symmetric\Crypto::decrypt($cipherText, $key)->getString();
	}


	/**
	 * Get encryption key.
	 *
	 * @param string $keyId
	 * @return Symmetric\EncryptionKey
	 * @throws \ParagonIE\Halite\Alerts\InvalidKey
	 * @throws \TypeError
	 */
	private function getKey(string $keyId): Symmetric\EncryptionKey
	{
		if (isset($this->keys[$this->keyGroup][$keyId])) {
			return new Symmetric\EncryptionKey(new HiddenString($this->keys[$this->keyGroup][$keyId]));
		} else {
			throw new \OutOfRangeException('Unknown encryption key id: ' . $keyId);
		}
	}


	/**
	 * Get active key id.
	 *
	 * Active key is used when encrypting.
	 *
	 * @return string
	 */
	private function getActiveKeyId(): string
	{
		return $this->activeKeyIds[$this->keyGroup];
	}


	/**
	 * Parse text into key id and ciphertext.
	 *
	 * @param string $data
	 * @return string[]
	 */
	private function parseKeyCipherText(string $data): array
	{
		$data = explode(self::KEY_CIPHERTEXT_SEPARATOR, $data);
		if (count($data) !== 3) {
			throw new \OutOfBoundsException('Data must have cipher, key, iv, and ciphertext. Now look at the Oxford comma!');
		}
		return array($data[1], $data[2]);
	}


	/**
	 * Format string to store into database.
	 *
	 * @param string $keyId
	 * @param string $cipherText
	 * @return string
	 */
	private function formatKeyCipherText(string $keyId, string $cipherText): string
	{
		return self::KEY_CIPHERTEXT_SEPARATOR . $keyId . self::KEY_CIPHERTEXT_SEPARATOR . $cipherText;
	}

}
