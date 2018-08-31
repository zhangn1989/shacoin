#include <iostream>

#include <unistd.h>

#include "p2pServer.hpp"
#include "p2pNode.hpp"
#include "blockChain.hpp"


int main(int argc, char **argv)
{
	ShaCoin::P2PNode *p2pNode = ShaCoin::P2PNode::Instance(argv[1]);
	p2pNode->Listen();

	ShaCoin::BlockChain *blockChain = ShaCoin::BlockChain::Instance();

	ShaCoin::KeyPair skeyPair;
	ShaCoin::Cryptography::Createkey(skeyPair);
	std::string sAddr = blockChain->CreateNewAddress(skeyPair);

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
