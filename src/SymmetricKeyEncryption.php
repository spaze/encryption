<?php
declare(strict_types = 1);

namespace Spaze\Encryption;

use OutOfBoundsException;
use OutOfRangeException;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\InvalidDigestLength;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Alerts\InvalidMessage;
use ParagonIE\Halite\Alerts\InvalidSignature;
use ParagonIE\Halite\Alerts\InvalidType;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;
use SodiumException;
use TypeError;
use function count;
use function explode;

class SymmetricKeyEncryption
{

	private const KEY_CIPHERTEXT_SEPARATOR = '$';


	/**
	 * @param array<string, array<string, string>> $keys key group => key id => key
	 * @param array<string, string> $activeKeyIds key group => key id
	 */
	public function __construct(
		private string $keyGroup,
		private array $keys,
		private array $activeKeyIds,
	) {
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
	public function encrypt(string $data): string
	{
		$keyId = $this->getActiveKeyId();
		$key = $this->getKey($keyId);
		$cipherText = Crypto::encrypt(new HiddenString($data), $key);
		return $this->formatKeyCipherText($keyId, $cipherText);
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
	 */
	public function decrypt(string $data): string
	{
		[$keyId, $cipherText] = $this->parseKeyCipherText($data);
		$key = $this->getKey($keyId);
		return Crypto::decrypt($cipherText, $key)->getString();
	}


	/**
	 * Checks if the given data are encrypted using the active key.
	 */
	public function needsReEncrypt(string $data): bool
	{
		[$keyId] = $this->parseKeyCipherText($data);
		return $keyId !== $this->getActiveKeyId();
	}


	/**
	 * @throws InvalidKey
	 * @throws TypeError
	 */
	private function getKey(string $keyId): EncryptionKey
	{
		if (isset($this->keys[$this->keyGroup][$keyId])) {
			return new EncryptionKey(new HiddenString(Hex::decode($this->keys[$this->keyGroup][$keyId])));
		} else {
			throw new OutOfRangeException('Unknown encryption key id: ' . $keyId);
		}
	}


	private function getActiveKeyId(): string
	{
		return $this->activeKeyIds[$this->keyGroup];
	}


	/**
	 * @return array{0:string, 1:string}
	 */
	private function parseKeyCipherText(string $data): array
	{
		$data = explode(self::KEY_CIPHERTEXT_SEPARATOR, $data);
		if (count($data) !== 3) {
			throw new OutOfBoundsException('Data must have cipher, key, iv, and ciphertext. Now look at the Oxford comma!');
		}
		return [$data[1], $data[2]];
	}


	private function formatKeyCipherText(string $keyId, string $cipherText): string
	{
		return self::KEY_CIPHERTEXT_SEPARATOR . $keyId . self::KEY_CIPHERTEXT_SEPARATOR . $cipherText;
	}

}
