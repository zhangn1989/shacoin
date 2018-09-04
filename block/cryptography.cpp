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

	std::string Cryptography::Base64Encode(const void*buff, int len)
	{
		int i;
		std::string str;
		int outl = -1;
		char out[(1024 * 5) / 3];
		EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();

		if (!ctx)
			return str;

		EVP_EncodeInit(ctx);

		for (i = 0; i < len / 1024; ++i)
		{
			memset(out, 0, sizeof(out));
			EVP_EncodeUpdate(ctx, (unsigned char *)out, &outl, (unsigned char *)buff + i * 1024, 1024);
			str += std::string(out, outl);
		}

		memset(out, 0, sizeof(out));
		EVP_EncodeUpdate(ctx, (unsigned char *)out, &outl, (unsigned char *)buff + i * 1024, len % 1024);
		str += std::string(out, outl);

		memset(out, 0, sizeof(out));
		EVP_EncodeFinal(ctx, (unsigned char *)out, &outl);
		str += std::string(out, outl);

		EVP_ENCODE_CTX_free(ctx);

		str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());

		return str;
#if 0
		typedef boost::archive::iterators::base64_from_binary<boost::archive::iterators::transform_width<const char *, 6, 8> > Base64EncodeIterator;
		std::stringstream result;
		std::copy(Base64EncodeIterator(buff), Base64EncodeIterator((char*)buff + len), std::ostream_iterator<char>(result));
		size_t equal_count = (3 - len % 3) % 3;
		for (size_t i = 0; i < equal_count; i++)
		{
			result.put('=');
		}

		return result.str();
#endif
	}

	void Cryptography::Base64Decode(const std::string &str64, void *outbuff, size_t outsize, size_t *outlen)
	{
		unsigned int i;
		unsigned int inlen = str64.length();
		if (outsize * 5 / 3 < inlen)
		{
			*outlen = -1;
			return;
		}

		int outl = -1;
		char out[(1024 * 5) / 3];
		char *p = (char *)outbuff;

		EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();

		if (!ctx)
		{
			*outlen = -1;
			return;
		}

		EVP_DecodeInit(ctx);

		for (i = 0; i < str64.length() / 1024; ++i)
		{
			memset(out, 0, sizeof(out));
			EVP_DecodeUpdate(ctx, (unsigned char *)out, &outl, (unsigned char *)str64.c_str() + i * 1024, 1024);
			memcpy(p, out, outl);
			p += outl;
			*outlen += outl;
		}

		memset(out, 0, sizeof(out));
		EVP_DecodeUpdate(ctx, (unsigned char *)out, &outl, (unsigned char *)str64.c_str() + i * 1024, str64.length() % 1024);
		memcpy(p, out, outl);
		p += outl;
		*outlen += outl;

		memset(out, 0, sizeof(out));
		EVP_DecodeFinal(ctx, (unsigned char *)out, &outl);
		memcpy(p, out, outl);
		p += outl;
		*outlen += outl;
#if 0
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
#endif
	}

	void Cryptography::Createkey(KeyPair &keyPair)
	{
		unsigned char *p = NULL;
		keyPair.priKey.len = -1;
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

		keyPair.priKey.len = i2d_ECPrivateKey(key, NULL);
		if (keyPair.priKey.len > (int)sizeof(keyPair.priKey.key))
		{
			keyPair.priKey.len = -1;
			EC_GROUP_free(group);
			EC_KEY_free(key);
			return;
		}
		p = keyPair.priKey.key;
		keyPair.priKey.len = i2d_ECPrivateKey(key, &p);

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

	bool Cryptography::Signature(const KeyData &priKey, const void *data, int datalen, unsigned char *sign, size_t signszie, unsigned int *signlen)
	{
		EC_KEY *ec_key = NULL;
		const unsigned char *pp = (const unsigned char *)priKey.key;
		ec_key = d2i_ECPrivateKey(&ec_key, &pp, priKey.len);
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

	std::string Cryptography::StringToLower(const std::string &str)
	{
		std::string strTmp = str;
		std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), tolower);
		return strTmp;
	}

	bool Cryptography::CompareNoCase(const std::string &strA, const std::string &strB)
	{
		std::string str1 = StringToLower(strA);
		std::string str2 = StringToLower(strB);
		return (str1 == str2);
	}

	std::vector<std::string> Cryptography::StringSplit(const std::string &str, const char sep)
	{
		std::vector<std::string> strvec;

		std::string::size_type pos1, pos2;
		pos2 = str.find(sep);
		pos1 = 0;
		while (std::string::npos != pos2)
		{
			strvec.push_back(str.substr(pos1, pos2 - pos1));

			pos1 = pos2 + 1;
			pos2 = str.find(sep, pos1);
		}
		strvec.push_back(str.substr(pos1));
		return strvec;

	}
}