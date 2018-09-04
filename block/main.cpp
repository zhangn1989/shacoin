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
}
