#include <iostream>

#include <unistd.h>

#include "p2pServer.hpp"
#include "p2pNode.hpp"
#include "blockChain.hpp"
#include "cryptography.hpp"


int main(int argc, char **argv)
{
	if (argc < 2)
	{
		std::cout << "argc error!" << std::endl;
		return 0;
	}

	std::string strInputCmd;
	ShaCoin::P2PNode *p2pNode = ShaCoin::P2PNode::Instance(argv[1]);
	p2pNode->Listen();

	ShaCoin::BlockChain *blockChain = ShaCoin::BlockChain::Instance();

	while (1)
	{
		std::cout << "Please input command:" << std::endl;
		getline(std::cin, strInputCmd);
		std::vector<std::string> vec_str = ShaCoin::Cryptography::StringSplit(strInputCmd, ' ');
		
		if (vec_str.size() < 1)
			continue;

		if (ShaCoin::Cryptography::CompareNoCase(vec_str[0], "addr"))
		{
			ShaCoin::KeyPair keyPair;
			ShaCoin::Cryptography::Createkey(keyPair);
			std::string addr = blockChain->CreateNewAddress(keyPair);

			std::cout << "Public key is " << ShaCoin::Cryptography::Base64Encode(keyPair.pubKey.key, keyPair.pubKey.len) << std::endl;
			std::cout << "Private key is " << ShaCoin::Cryptography::Base64Encode(keyPair.priKey.key, keyPair.priKey.len) << std::endl;
			std::cout << "Address is " << addr << std::endl;
			continue;
		}
		else if (ShaCoin::Cryptography::CompareNoCase(vec_str[0], "ts"))
		{
			if (vec_str.size() < 6)
				continue;

			ShaCoin::KeyPair kp;
			memset(&kp, 0, sizeof(kp));
			ShaCoin::Cryptography::Base64Decode(vec_str[4], kp.pubKey.key, sizeof(kp.pubKey.key), &kp.pubKey.len);
			ShaCoin::Cryptography::Base64Decode(vec_str[5], kp.priKey.key, sizeof(kp.priKey.key), &kp.priKey.len);

			ShaCoin::Transactions ts = blockChain->CreateTransactions(vec_str[1], vec_str[2], stof(vec_str[3]));
			std::string strTsJson = blockChain->GetJsonFromTransactions(ts);
			std::string strHash = ShaCoin::Cryptography::GetHash(strTsJson.c_str(), strTsJson.length());
			
			ShaCoin::BroadcastMessage tm;
			memset(&tm, 0, sizeof(tm));
			tm.pubkey = kp.pubKey;
			strncpy(tm.json, strTsJson.c_str(), strTsJson.length());
			if (ShaCoin::Cryptography::Signature(kp.priKey, strHash.c_str(), strHash.length(), tm.sign, sizeof(tm.sign), &tm.signlen))
				p2pNode->Broadcast(ShaCoin::p2p_transaction, tm);

			continue;
		}
		else if (ShaCoin::Cryptography::CompareNoCase(vec_str[0], "Mining"))
		{
			if (vec_str.size() < 2)
				continue;

			int count;
			if (vec_str.size() >= 3)
				count = stoi(vec_str[2]);
			else
				count = 1;

			if (count < 1)
				count = 1;

			while (count)
			{
				std::string strMiningJson = blockChain->Mining(vec_str[1]);
		
				ShaCoin::BroadcastMessage bmMining;
				memset(&bmMining, 0, sizeof(bmMining));
				strncpy(bmMining.json, strMiningJson.c_str(), strMiningJson.length());
				p2pNode->Broadcast(ShaCoin::p2p_bookkeeping, bmMining);

				--count;
			}

			continue;
		}
		else if (ShaCoin::Cryptography::CompareNoCase(vec_str[0], "Merge"))
		{
			p2pNode->MergeChain();
			continue;
		}
		else if (ShaCoin::Cryptography::CompareNoCase(vec_str[0], "Balances"))
		{
			if(vec_str.size() < 2)
				continue;

			std::cout << blockChain->CheckBalances(vec_str[1]) << std::endl;

			continue;
		}
		else if (ShaCoin::Cryptography::CompareNoCase(vec_str[0], "show"))
		{
			std::cout << blockChain->GetJsonFromBlockList() << std::endl;

			continue;
		}
		else if (ShaCoin::Cryptography::CompareNoCase(vec_str[0], "help"))
		{
			std::cout << "<quit> quit." << std::endl;
			std::cout << "<addr> create a new address and key pair." << std::endl;
			std::cout << "<ts> initiate a new benefit,the parameters are in order:send address, recipient address, amount." << std::endl;
			std::cout << "<mining> mining.the parameters are in order:mining address,number of mining times" << std::endl;
			std::cout << "<merge> blockchain merge." << std::endl;
			std::cout << "<balances> get the balance.the parameters are in order:address" << std::endl;
			std::cout << "<show> display blockchain in json format." << std::endl;
			std::cout << "<quit> quit." << std::endl;
			std::cout << "<help> show this message." << std::endl;
			continue;
		}
		else if (ShaCoin::Cryptography::CompareNoCase(vec_str[0], "quit"))
		{
			break;
		}
	}

	return 0;
	
#if 0
	ShaCoin::KeyPair rkeyPair;
	ShaCoin::Cryptography::Createkey(rkeyPair);
	std::string rAddr = blockChain->CreateNewAddress(rkeyPair);

	std::string strMiningJson = blockChain->Mining(sAddr);
	std::string strMiningHash = ShaCoin::Cryptography::GetHash(strMiningJson.c_str(), strMiningJson.length());

	ShaCoin::BroadcastMessage bmMining;
	memset(&bmMining, 0, sizeof(bmMining));
	bmMining.pubkey = skeyPair.pubKey;
	strncpy(bmMining.json, strMiningJson.c_str(), strMiningJson.length());
	if (ShaCoin::Cryptography::Signature(skeyPair.prikey, strMiningHash.c_str(), strMiningHash.length(), bmMining.sign, sizeof(bmMining.sign), &bmMining.signlen))
		p2pNode->Broadcast(ShaCoin::p2p_bookkeeping, bmMining);

	p2pNode->MergeChain();

// 	std::string strListJson = blockChain->GetJsonFromBlockList();
// 	std::cout << strListJson << std::endl;
// 
// 	ShaCoin::Transactions ts = blockChain->CreateTransactions(sAddr, rAddr, 5);
// 	std::string strTsJson = blockChain->GetJsonFromTransactions(ts);
// 	std::string strHash = ShaCoin::Cryptography::GetHash(strTsJson.c_str(), strTsJson.length());
// 
// 	ShaCoin::BroadcastMessage tm;
// 	memset(&tm, 0, sizeof(tm));
// 	tm.pubkey = skeyPair.pubKey;
// 	strncpy(tm.json, strTsJson.c_str(), strTsJson.length());
// 	if (ShaCoin::Cryptography::Signature(skeyPair.prikey, strHash.c_str(), strHash.length(), tm.sign, sizeof(tm.sign), &tm.signlen))
// 		p2pNode->Broadcast(ShaCoin::p2p_transaction, tm);

	while (1)
		sleep(1);

	return 0;

#endif


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
