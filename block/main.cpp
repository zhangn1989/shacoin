#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>

#include <iostream>
#include <list>
#include <string>
#include <functional>
#include <cstdlib>
#include <ctime>

#include <boost/uuid/sha1.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "p2pServer.hpp"
#include "p2pNode.hpp"
/*

block = {
'index': 1,
'timestamp': 1506057125.900785,
'transactions': [
{
'sender': "8527147fe1f5426f9dd545de4b27ee00",
'recipient': "a77f5cdfa2934df3954a5c7c7da5df1f",
'amount': 5,
}
],
'proof': 324984774000,
'previous_hash': "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
}

*/

typedef struct __transactions
{
	std::string sender;
	std::string recipient;
	float amount;
}Transactions;

typedef struct __block
{
	int index;
	time_t timestamp;
	std::list<Transactions> lst_ts;
	long int proof;
	std::string previous_hash;
} Block;

typedef struct __keydata
{
	int len;
	unsigned char key[256];
} KeyData;

typedef struct __KeyPair
{
	KeyData prikey;
	KeyData pubKey;
} KeyPair;

static std::list<Transactions> g_lst_ts;
static std::list<Block> g_lst_block;


std::string GetJsonFromBlock(Block &block)
{
	boost::property_tree::ptree item;

	boost::property_tree::ptree lstts;
	{
		std::list<Transactions>::iterator it;
		for (it = block.lst_ts.begin(); it != block.lst_ts.end(); ++it)
		{
			boost::property_tree::ptree ts;
			ts.put("sender", it->sender);
			ts.put("recipient", it->recipient);
			ts.put("amount", it->amount);
			lstts.push_back(make_pair("", ts));
		}
	}

	item.put("index", block.index);
	item.put("timestamp", block.timestamp);
	item.put_child("transactions", lstts);
	item.put("proof", block.proof);
	item.put("previous_hash", block.previous_hash);

	std::stringstream is;
	boost::property_tree::write_json(is, item);
	return is.str();
}

Block GetBlockFromJson(const std::string &json)
{
	Block block;
	std::stringstream ss(json);
	boost::property_tree::ptree pt;
	boost::property_tree::ptree array;
	boost::property_tree::read_json(ss, pt);
	block.index = pt.get<int>("index");
	block.previous_hash = pt.get<std::string>("previous_hash");
	block.proof = pt.get<long int>("proof");
	block.timestamp = pt.get<time_t>("timestamp");
	array = pt.get_child("transactions");

	for (auto v : array)
	{
		Transactions ts;
		ts.sender = v.second.get<std::string>("sender");
		ts.recipient = v.second.get<std::string>("recipient");
		ts.amount = v.second.get<float>("amount");
		block.lst_ts.push_back(ts);
	}

	return block;
}

std::string GetJsonFromBlockList(std::list<Block> &lst_block)
{
	int i = 0;

	boost::property_tree::ptree item;

	boost::property_tree::ptree pblock;
	{
		std::list<Block>::iterator bit;
		for (bit = lst_block.begin(); bit != lst_block.end(); ++bit)
		{
			boost::property_tree::ptree b;
			boost::property_tree::ptree pts;
			{
				std::list<Transactions>::iterator tit;
				for (tit = bit->lst_ts.begin(); tit != bit->lst_ts.end(); ++tit)
				{
					boost::property_tree::ptree t;
					t.put("sender", tit->sender);
					t.put("recipient", tit->recipient);
					t.put("amount", tit->amount);
					pts.push_back(make_pair("", t));
				}
			}

			b.put("index", bit->index);
			b.put("timestamp", bit->timestamp);
			b.put_child("transactions", pts);
			b.put("proof", bit->proof);
			b.put("previous_hash", bit->previous_hash);
			pblock.push_back(make_pair("", b));

			++i;
		}
	}

	item.put_child("chain", pblock);
	item.put("length", i);

	std::stringstream is;
	boost::property_tree::write_json(is, item);
	return is.str();
}

std::list<Block> GetBlockListFromJson(const std::string &json)
{
	std::list<Block> lstBlock;
	std::stringstream ss(json);
	boost::property_tree::ptree pt;
	boost::property_tree::ptree barray;
	boost::property_tree::read_json(ss, pt);
	barray = pt.get_child("chain");

	for (auto bv : barray)
	{
		Block block;
		boost::property_tree::ptree tarray;

		block.index = bv.second.get<int>("index");
		block.previous_hash = bv.second.get<std::string>("previous_hash");
		block.proof = bv.second.get<long int>("proof");
		block.timestamp = bv.second.get<time_t>("timestamp");
		tarray = bv.second.get_child("transactions");

		for (auto tv : tarray)
		{
			Transactions ts;
			ts.sender = tv.second.get<std::string>("sender");
			ts.recipient = tv.second.get<std::string>("recipient");
			ts.amount = tv.second.get<float>("amount");
			block.lst_ts.push_back(ts);
		}
		lstBlock.push_back(block);
	}

	return lstBlock;
}

std::string GetHash(void const* buffer, std::size_t count)
{
	std::stringstream ss;
	boost::uuids::detail::sha1 sha;
	sha.process_bytes(buffer, count);
	unsigned int digest[5];      //摘要的返回值
	sha.get_digest(digest);
	for (int i = 0; i < 5; ++i)
		ss << std::hex << digest[i];

	return ss.str();
}

std::string Base64Encode(const char*buff, int len)
{
	typedef boost::archive::iterators::base64_from_binary<boost::archive::iterators::transform_width<const char *, 6, 8> > Base64EncodeIterator;
	std::stringstream result;
	std::copy(Base64EncodeIterator(buff), Base64EncodeIterator(buff + len), std::ostream_iterator<char>(result));
	size_t equal_count = (3 - len % 3) % 3;
	for (size_t i = 0; i < equal_count; i++)
	{
		result.put('=');
	}

	return result.str();
}

void Base64Decode(const char *inbuff, int inlen, char *outbuff, int outsize, int *outlen)
{
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
		return ;
	}
	
	std::string str = result.str();
	*outlen = str.length();
	memcpy((char *)outbuff, str.c_str(), *outlen);
	return ;
}

void Createkey(KeyPair &keyPair)
{
	unsigned char *p = NULL;
	keyPair.prikey.len = -1;
	keyPair.pubKey.len = -1;
	
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if (!group)
		return ;

	EC_KEY *key = EC_KEY_new();
	if (!key)
	{
		EC_GROUP_free(group);
		return;
	}

	if(!EC_KEY_set_group(key, group))
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

int Signature(const KeyData &prikey, const char *data, int datalen, unsigned char *sign, size_t signszie, unsigned int *signlen)
{
	EC_KEY *ec_key = NULL;
	const unsigned char *pp = (const unsigned char *)prikey.key;
	ec_key = d2i_ECPrivateKey(&ec_key, &pp, prikey.len);
	if (!ec_key)
		return 0;

	if (ECDSA_size(ec_key) > (int)signszie)
	{
		EC_KEY_free(ec_key);
		return 0;
	}

	if (!ECDSA_sign(0, (unsigned char *)data, datalen, sign, signlen, ec_key))
	{
		EC_KEY_free(ec_key);
		return 0;
	}

	EC_KEY_free(ec_key);
	return 1;
}

int Verify(const KeyData &pubkey, const char *data, int datalen, const unsigned char *sign, size_t signszie, unsigned int signlen)
{
	int ret = -1;
	EC_KEY *ec_key = NULL;
	EC_GROUP *ec_group = NULL;
	const unsigned char *pp = (const unsigned char *)pubkey.key;

	ec_key = EC_KEY_new();
	if (!ec_key)
		return 0;

	if (ECDSA_size(ec_key) > (int)signszie)
	{
		EC_KEY_free(ec_key);
		return 0;
	}

	ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if (!ec_group)
	{
		EC_KEY_free(ec_key);
		return 0;
	}

	if (!EC_KEY_set_group(ec_key, ec_group))
	{
		EC_GROUP_free(ec_group);
		EC_KEY_free(ec_key);
		return 0;
	}

	ec_key = o2i_ECPublicKey(&ec_key, &pp, pubkey.len);
	if (!ec_key)
	{
		EC_GROUP_free(ec_group);
		EC_KEY_free(ec_key);
		return 0;
	}

	ret = ECDSA_verify(0, (const unsigned char*)data, datalen, sign,
		signlen, ec_key);

	EC_GROUP_free(ec_group);
	EC_KEY_free(ec_key);
	return ret;
}

std::string CreateNewAddress(const KeyPair &keyPair)
{
	std::string hash = GetHash(keyPair.pubKey.key, keyPair.pubKey.len);
	return Base64Encode(hash.c_str(), hash.length());
}

Transactions CreateTransactions(const std::string &sender, const std::string &recipient, float amount)
{
	Transactions ts;
	ts.sender = sender;
	ts.recipient = recipient;
	ts.amount = amount;
	return ts;
}

Block CreateBlock(int index, time_t timestamp, std::list<Transactions> &lst_ts, long int proof, const std::string &previous)
{
	Block block;
	block.index = index;
	block.timestamp = timestamp;
	block.lst_ts = lst_ts;
	block.proof = proof;
	block.previous_hash = previous;
	return block;
}

int WorkloadProof(int last_proof)
{
	std::string strHash;
	std::string strTemp;
	int proof = last_proof + 1;

	std::string str = "Hello Shacoin!";

	while (true)
	{
		strTemp = str + std::to_string(proof);
		strHash = GetHash(strTemp.c_str(), strTemp.length());
		if (strHash.back() == '0')
			return proof;
		else
			++proof;
	}
}

bool WorkloadVerification(int proof)
{
	std::string str = "Hello Shacoin!" + std::to_string(proof);
	std::string strHash = GetHash(str.c_str(), str.length());
	return (strHash.back() == '0');
}

void Mining(const std::string &addr)
{
	//挖矿的交易，交易支出方地址为0
	//每次挖矿成功奖励10个币
	Block last = g_lst_block.back();
	std::string strLastBlock = GetJsonFromBlock(last);
	int proof = WorkloadProof(last.proof);
	Transactions ts = CreateTransactions("0", addr, 10);
	g_lst_ts.push_back(ts);
	Block block = CreateBlock(last.index + 1, time(NULL), g_lst_ts, proof,
		GetHash(strLastBlock.c_str(), strLastBlock.length()));
	g_lst_block.push_back(block);
	g_lst_ts.clear();

	//p2p广播，暂未实现
}

int main(int argc, char **argv)
{
	ShaCoin::P2PNode *p2pNode = ShaCoin::P2PNode::Instance(argv[1]);
	p2pNode->Listen();
	return 0;




#if 0
 	if (g_lst_block.size() == 0)
 	{
 		Block GenesisBlock;
 		GenesisBlock.index = 0;
 		GenesisBlock.timestamp = time(NULL);
 		GenesisBlock.lst_ts.clear();
 		GenesisBlock.proof = 0;
 		GenesisBlock.previous_hash = "0";
 		g_lst_block.push_back(GenesisBlock);
 	}

 	KeyPair skeyPair;
  	Createkey(skeyPair);
  	std::string sAddr = CreateNewAddress(skeyPair);

	KeyPair rkeyPair;
	Createkey(rkeyPair);
	std::string rAddr = CreateNewAddress(rkeyPair);

	Mining(sAddr);
	Mining(rAddr);

	std::string strListJson = GetJsonFromBlockList(g_lst_block);
	std::cout << strListJson << std::endl;

	Transactions tr = CreateTransactions(sAddr, rAddr, 5);
	g_lst_ts.push_back(ts);
	Block last = g_lst_block.back();
	std::string strLastBlock = GetJsonFromBlock(last);

	Block block = CreateBlock(last.index + 1, time(NULL), g_lst_ts, last.proof,
		GetHash(strLastBlock.c_str(), strLastBlock.length()));
	g_lst_block.push_back(block);

	strListJson = GetJsonFromBlockList(g_lst_block);
	std::cout << strListJson << std::endl;


//  	std::string addrhash = GetHash(addr.c_str(), addr.length());
//  	unsigned int signlen = 0;
//  	unsigned char sign[1024] = { 0 };
//  	int a = Signature(keyPair.prikey, addrhash.c_str(), addrhash.length(), sign, sizeof(sign), &signlen);
//  	int b = Verify(keyPair.pubKey, addrhash.c_str(), addrhash.length(), sign, sizeof(sign), signlen);
#endif

	return 0;
}
