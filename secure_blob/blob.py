import hmac
from base64 import b64decode, b64encode
from hashlib import sha3_256
from io import BytesIO
from typing import Union

import msgpack
import zstandard as zstd
from Crypto.Cipher import AES


class SecureBlob:
	"""
	This is a secure message algorithm to be used with a pre-shared key
	"""

	def __init__(self, key: Union[str, bytes], compression_level: int, data: bytes = None) -> None:
		if data is not None:
			self.data = data

		if type(key) == str:
			key = key.encode('utf-8')

		self.key = sha3_256(key).digest()

		if compression_level <= 0:
			self.cl = 1
		elif compression_level >= 22:
			self.cl = 22
		else:
			self.cl = compression_level

	def encrypt_message(self, data: bytes = None, b64out: bool = False, returns: bool = False) -> Union[bytes, str]:
		if data is not None:
			self.data = data

		if not self.data:
			raise ValueError('No data to encrypt')

		hmac_verif = hmac.new(self.key, digestmod='sha3_256')

		cipher = AES.new(self.key, AES.MODE_GCM)
		e_nonce = cipher.nonce
		e_data, e_tag = cipher.encrypt_and_digest(self.data)

		tmp = bytearray()
		tmp = tmp + len(e_nonce).to_bytes(length=1,
										  byteorder='little') + e_nonce
		tmp = tmp + len(e_tag).to_bytes(length=1, byteorder='little') + e_tag
		tmp = tmp + len(e_data).to_bytes(length=32,
										 byteorder='little') + e_data

		cctx = zstd.ZstdCompressor(write_content_size=True)

		tmp = cctx.compress(tmp)

		hmac_verif.update(tmp)

		final = hmac_verif.digest() + tmp

		if returns:
			return b64encode(final) if b64out else final
		else:
			self.data = final
	
	def decrypt_message(self, data: bytes = None, b64out: bool = False, returns: bool = False):
		if data is not None:
			self.data = data

		if not self.data:
			raise ValueError('No data to encrypt')

		hmac_verif = hmac.new(self.key, digestmod='sha3_256')
		dctx = zstd.ZstdDecompressor()

		i_hash = self.data[0:32]
		i_data = self.data[32:]

		hmac_verif.update(i_data)
		if hmac_verif.digest() != i_hash:
			raise ValueError('Message hmac is different')

		data = BytesIO(dctx.decompress(i_data))

		i_nonce_len = int.from_bytes(data.read(1), byteorder='little')
		nonce = data.read(i_nonce_len)

		i_tag_len = int.from_bytes(data.read(1), byteorder='little')
		tag = data.read(i_tag_len)

		data_len = int.from_bytes(data.read(32), byteorder='little')
		e_data = data.read(data_len)

		cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)

		plain = cipher.decrypt(e_data)

		try:
			cipher.verify(tag)
		except ValueError:
			raise ValueError('Message likelly corrupted')

		if returns:
			return b64encode(plain) if b64out else plain
		else:
			self.data = plain

