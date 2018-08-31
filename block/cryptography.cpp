#include <sstream>
#include <cstring>

#include <boost/uuid/sha1.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "cryptography.hpp"

namespace ShaCoin
{
	Cryptography::Cryptography()
	{

	}
	Cryptography::~Cryptography()
	{

	}

	std::string Cryptography::GetHash(void const* buffer, std::size_t len)
	{
		std::stringstream ss;
		boost::uuids::detail::sha1 sha;
		sha.process_bytes(buffer, len);
		unsigned int digest[5];      //摘要的返回值
		sha.get_digest(digest);
		for (int i = 0; i < 5; ++i)
			ss << std::hex << digest[i];

		return ss.str();
	}

	std::string Cryptography::Base64Encode(const void*buff, size_t len)
	{
		typedef boost::archive::iterators::base64_from_binary<boost::archive::iterators::transform_width<const char *, 6, 8> > Base64EncodeIterator;
		std::stringstream result;
		std::copy(Base64EncodeIterator(buff), Base64EncodeIterator((char*)buff + len), std::ostream_iterator<char>(result));
		size_t equal_count = (3 - len % 3) % 3;
		for (size_t i = 0; i < equal_count; i++)
		{
			result.put('=');
		}

		return result.str();
	}

	void Cryptography::Base64Decode(const std::string &str64, void *outbuff, size_t outsize, size_t *outlen)
	{
		unsigned int inlen = str64.length();
		const char *inbuff = str64.c_str();
		if (outsize * 4 / 3 < inlen)
		{
			*outlen = -1;
			return;
		}

		std::stringstream result;

		typedef boost::archive::iterators::transform_width<boost::archive::iterators::binary_from_base64<const char *>, 8, 6> Base64DecodeIterator;

		try
		{
			std::copy(Base64DecodeIterator(inbuff), Base64DecodeIterator(inbuff + inlen), std::ostream_iterator<char>(result));
		}
		catch (...)
		{
			return;
		}

		std::string str = result.str();
		*outlen = str.length();
		memcpy((char *)outbuff, str.c_str(), *outlen);
		return;
	}

	void Cryptography::Createkey(KeyPair &keyPair)
	{
		unsigned char *p = NULL;
		keyPair.prikey.len = -1;
		keyPair.pubKey.len = -1;

		EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
		if (!group)
			return;

		EC_KEY *key = EC_KEY_new();
		if (!key)
		{
			EC_GROUP_free(group);
			return;
		}

		if (!EC_KEY_set_group(key, group))
		{
			EC_GROUP_free(group);
			EC_KEY_free(key);
			return;
		}

		if (!EC_KEY_generate_key(key))
		{
			EC_GROUP_free(group);
			EC_KEY_free(key);
			return;
		}

		if (!EC_KEY_check_key(key))
		{
			EC_GROUP_free(group);
			EC_KEY_free(key);
			return;
		}

		keyPair.prikey.len = i2d_ECPrivateKey(key, NULL);
		if (keyPair.prikey.len > (int)sizeof(keyPair.prikey.key))
		{
			keyPair.prikey.len = -1;
			EC_GROUP_free(group);
			EC_KEY_free(key);
			return;
		}
		p = keyPair.prikey.key;
		keyPair.prikey.len = i2d_ECPrivateKey(key, &p);

		keyPair.pubKey.len = i2o_ECPublicKey(key, NULL);
		if (keyPair.pubKey.len > (int)sizeof(keyPair.pubKey.key))
		{
			keyPair.pubKey.len = -1;
			EC_GROUP_free(group);
			EC_KEY_free(key);
			return;
		}
		p = keyPair.pubKey.key;
		keyPair.pubKey.len = i2o_ECPublicKey(key, &p);

		EC_GROUP_free(group);
		EC_KEY_free(key);
	}

	bool Cryptography::Signature(const KeyData &prikey, const void *data, int datalen, unsigned char *sign, size_t signszie, unsigned int *signlen)
	{
		EC_KEY *ec_key = NULL;
		const unsigned char *pp = (const unsigned char *)prikey.key;
		ec_key = d2i_ECPrivateKey(&ec_key, &pp, prikey.len);
		if (!ec_key)
			return false;

		if (ECDSA_size(ec_key) > (int)signszie)
		{
			EC_KEY_free(ec_key);
			return false;
		}

		if (!ECDSA_sign(0, (unsigned char *)data, datalen, sign, signlen, ec_key))
		{
			EC_KEY_free(ec_key);
			return false;
		}

		EC_KEY_free(ec_key);
		return true;
	}

	int Cryptography::Verify(const KeyData &pubkey, const char *data, int datalen, const unsigned char *sign, size_t signszie, unsigned int signlen)
	{
		int ret = -1;
		EC_KEY *ec_key = NULL;
		EC_GROUP *ec_group = NULL;
		const unsigned char *pp = (const unsigned char *)pubkey.key;

		ec_key = EC_KEY_new();
		if (!ec_key)
			return ret;

		if (ECDSA_size(ec_key) > (int)signszie)
		{
			EC_KEY_free(ec_key);
			return ret;
		}

		ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
		if (!ec_group)
		{
			EC_KEY_free(ec_key);
			return ret;
		}

		if (!EC_KEY_set_group(ec_key, ec_group))
		{
			EC_GROUP_free(ec_group);
			EC_KEY_free(ec_key);
			return ret;
		}

		ec_key = o2i_ECPublicKey(&ec_key, &pp, pubkey.len);
		if (!ec_key)
		{
			EC_GROUP_free(ec_group);
			EC_KEY_free(ec_key);
			return ret;
		}

		ret = ECDSA_verify(0, (const unsigned char*)data, datalen, sign,
			signlen, ec_key);

		EC_GROUP_free(ec_group);
		EC_KEY_free(ec_key);
		return ret;
	}
}