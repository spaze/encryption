<?php
declare(strict_types = 1);

namespace Spaze\Encryption\Format;

use ParagonIE\HiddenString\HiddenString;
use SensitiveParameter;
use SodiumException;
use Spaze\Encryption\Exceptions\InvalidCipherTextFormatException;
use Spaze\Encryption\Exceptions\InvalidKeyEncodingException;
use Spaze\Encryption\Exceptions\InvalidKeyIdException;
use Spaze\Encryption\Exceptions\InvalidKeyLengthException;
use Spaze\Encryption\Exceptions\InvalidKeyPrefixException;
use Spaze\Encryption\Exceptions\InvalidKeyRoleException;
use Spaze\Encryption\Exceptions\InvalidNumberOfComponentsException;
use Spaze\Encryption\Exceptions\MissingKeyPrefixException;
use function count;
use function explode;

/**
 * @internal Shared key decoding and encrypted output formatting, not part of the public API
 */
trait KeyEnvelope
{

	private const KEY_CIPHERTEXT_SEPARATOR = '$';
	private const KEY_PREFIX_SEPARATOR = '_';


	/**
	 * @param array<array-key, string> $keys key id => key
	 * @return array<string, HiddenString>
	 * @throws InvalidKeyEncodingException
	 * @throws InvalidKeyIdException
	 * @throws InvalidKeyLengthException
	 * @throws InvalidKeyPrefixException
	 * @throws InvalidKeyRoleException
	 * @throws MissingKeyPrefixException
	 */
	private function decodeKeys(#[SensitiveParameter] array $keys, string $keyPrefix, int $expectedLength, ?AsymmetricKeyRole $role = null): array
	{
		$keyPrefix .= self::KEY_PREFIX_SEPARATOR;
		$decodedKeys = [];
		foreach ($keys as $id => $key) {
			$id = (string)$id;
			if ($id === '' || str_contains($id, self::KEY_CIPHERTEXT_SEPARATOR)) {
				throw new InvalidKeyIdException($id, self::KEY_CIPHERTEXT_SEPARATOR);
			}
			if (!str_starts_with($key, $keyPrefix)) {
				if (str_contains($key, self::KEY_PREFIX_SEPARATOR)) {
					throw new InvalidKeyPrefixException($id, $keyPrefix);
				}
				throw new MissingKeyPrefixException($id, $keyPrefix);
			}
			$hexKey = substr($key, strlen($keyPrefix));
			if ($role !== null) {
				$hexKey = $this->stripKeyRole($id, $hexKey, $role);
			}
			try {
				$decodedKey = sodium_hex2bin($hexKey);
			} catch (SodiumException $e) {
				throw new InvalidKeyEncodingException($id, $e);
			}
			if (strlen($decodedKey) !== $expectedLength) {
				throw new InvalidKeyLengthException($id, strlen($decodedKey), $expectedLength);
			}
			$decodedKeys[$id] = new HiddenString($decodedKey);
		}
		return $decodedKeys;
	}


	/**
	 * The role tag between the prefix and the key itself is optional, but when present, it has to match how the key is used.
	 *
	 * @throws InvalidKeyRoleException
	 */
	private function stripKeyRole(string $id, #[SensitiveParameter] string $key, AsymmetricKeyRole $expectedRole): string
	{
		foreach (AsymmetricKeyRole::cases() as $role) {
			if (str_starts_with($key, $role->value . self::KEY_PREFIX_SEPARATOR)) {
				if ($role !== $expectedRole) {
					throw new InvalidKeyRoleException($id, $expectedRole, $role);
				}
				return substr($key, strlen($role->value . self::KEY_PREFIX_SEPARATOR));
			}
		}
		return $key;
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
