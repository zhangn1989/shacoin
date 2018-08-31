#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "blockChain.hpp"

namespace ShaCoin
{
	BlockChain::BlockChain()
	{
		pthread_mutex_init(&m_mutexTs, NULL);
		pthread_mutex_init(&m_mutexBlock, NULL);
		if (m_lst_block.size() == 0)
		{
			Block GenesisBlock;
			GenesisBlock.index = 0;
			GenesisBlock.timestamp = time(NULL);
			GenesisBlock.lst_ts.clear();
			GenesisBlock.proof = 0;
			GenesisBlock.previous_hash = "0";

			pthread_mutex_lock(&m_mutexBlock);
			m_lst_block.push_back(GenesisBlock);
			pthread_mutex_unlock(&m_mutexBlock);
		}
	}

	BlockChain::~BlockChain()
	{
		pthread_mutex_destroy(&m_mutexTs);
		pthread_mutex_destroy(&m_mutexBlock);
	}

	BlockChain *BlockChain::Instance()
	{
		static BlockChain bc;
		return &bc;
	}

	std::string BlockChain::GetJsonFromBlock(Block &block)
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

	std::string BlockChain::GetJsonFromTransactions(Transactions &ts)
	{
		boost::property_tree::ptree item;

		item.put("sender", ts.sender);
		item.put("recipient", ts.recipient);
		item.put("amount", ts.amount);

		std::stringstream is;
		boost::property_tree::write_json(is, item);
		return is.str();
	}

	Block BlockChain::GetBlockFromJson(const std::string &json)
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
	
	Transactions BlockChain::GetTransactionsFromJson(const std::string &json)
	{
		Transactions ts;
		std::stringstream ss(json);
		boost::property_tree::ptree pt;
		boost::property_tree::read_json(ss, pt);

		ts.sender = pt.get<std::string>("sender");
		ts.recipient = pt.get<std::string>("recipient");
		ts.amount = pt.get<float>("amount");
		
		return ts;
	}

	std::string BlockChain::GetJsonFromBlockList()
	{
		int i = 0;

		boost::property_tree::ptree item;

		boost::property_tree::ptree pblock;
		{
			std::list<Block>::iterator bit;

			pthread_mutex_lock(&m_mutexBlock);
			for (bit = m_lst_block.begin(); bit != m_lst_block.end(); ++bit)
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
			pthread_mutex_unlock(&m_mutexBlock);
		}

		item.put_child("chain", pblock);
		item.put("length", i);

		std::stringstream is;
		boost::property_tree::write_json(is, item);
		return is.str();
	}

	std::string BlockChain::GetJsonFromTransactionsList()
	{
		int i = 0;

		boost::property_tree::ptree item;

		boost::property_tree::ptree pts;
		{
			std::list<Transactions>::iterator bit;

			pthread_mutex_lock(&m_mutexTs);
			for (bit = m_lst_ts.begin(); bit != m_lst_ts.end(); ++bit)
			{
				boost::property_tree::ptree b;
				
				b.put("sender", bit->sender);
				b.put("recipient", bit->recipient);
				b.put("amount", bit->amount);

				pts.push_back(make_pair("", b));

				++i;
			}
			pthread_mutex_unlock(&m_mutexTs);
		}

		item.put_child("transactions", pts);
		item.put("length", i);

		std::stringstream is;
		boost::property_tree::write_json(is, item);
		return is.str();
	}

	void BlockChain::GetBlockListFromJson(const std::string &json)
	{
		pthread_mutex_lock(&m_mutexBlock);
		m_lst_block.clear();
		pthread_mutex_unlock(&m_mutexBlock);
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

			pthread_mutex_lock(&m_mutexBlock);
			m_lst_block.push_back(block);
			pthread_mutex_unlock(&m_mutexBlock);
		}
	}

	void BlockChain::GetTransactionsListFromJson(const std::string &json)
	{
		pthread_mutex_lock(&m_mutexTs);
		m_lst_ts.clear();
		pthread_mutex_unlock(&m_mutexTs);

		std::stringstream ss(json);
		boost::property_tree::ptree pt;
		boost::property_tree::ptree array;
		boost::property_tree::read_json(ss, pt);
		array = pt.get_child("transactions");

		for (auto v : array)
		{
			Transactions ts;
			ts.sender = v.second.get<std::string>("sender");
			ts.recipient = v.second.get<std::string>("recipient");
			ts.amount = v.second.get<float>("amount");

			pthread_mutex_lock(&m_mutexTs);
			m_lst_ts.push_back(ts);
			pthread_mutex_unlock(&m_mutexTs);
		}
	}

	std::string BlockChain::CreateNewAddress(const KeyPair &keyPair)
	{
		std::string hash = Cryptography::GetHash(keyPair.pubKey.key, keyPair.pubKey.len);
		return Cryptography::Base64Encode(hash.c_str(), hash.length());
	}

	Transactions BlockChain::CreateTransactions(const std::string &sender, const std::string &recipient, float amount)
	{
		Transactions ts;
		ts.sender = sender;
		ts.recipient = recipient;
		ts.amount = amount;
		return ts;
	}

	Block BlockChain::CreateBlock(int index, time_t timestamp, long int proof)
	{
		Block block;

		ShaCoin::Block last = GetLastBlock();
		std::string strLastBlock = GetJsonFromBlock(last);

		block.index = index;
		block.timestamp = timestamp;
		block.proof = proof;
		block.previous_hash = Cryptography::GetHash(strLastBlock.c_str(), strLastBlock.length());

		pthread_mutex_lock(&m_mutexTs);
		block.lst_ts = m_lst_ts;
		m_lst_ts.clear();
		pthread_mutex_unlock(&m_mutexTs);

		pthread_mutex_lock(&m_mutexBlock);
		m_lst_block.push_back(block);
		pthread_mutex_unlock(&m_mutexBlock);

		return block;
	}

	int BlockChain::WorkloadProof(int last_proof)
	{
		std::string strHash;
		std::string strTemp;
		int proof = last_proof + 1;

		std::string str = "Hello Shacoin!";

		while (true)
		{
			strTemp = str + std::to_string(proof);
			strHash = Cryptography::GetHash(strTemp.c_str(), strTemp.length());
			if (strHash.back() == '0')
				return proof;
			else
				++proof;
		}
	}

	bool BlockChain::WorkloadVerification(int proof)
	{
		std::string str = "Hello Shacoin!" + std::to_string(proof);
		std::string strHash = Cryptography::GetHash(str.c_str(), str.length());
		return (strHash.back() == '0');
	}

	std::string BlockChain::Mining(const std::string &addr)
	{
		//挖矿的交易，交易支出方地址为0
		//每次挖矿成功奖励10个币
		Block last = GetLastBlock();
		int proof = WorkloadProof(last.proof);
		Transactions ts = CreateTransactions("0", addr, 10);
		InsertTransactions(ts);
		Block block = CreateBlock(last.index + 1, time(NULL), proof);
		return GetJsonFromBlock(block);
	}

	int BlockChain::CheckBalances(const std::string &addr)
	{
		int balan = 0;

		std::list<Block>::iterator bit;
		std::list<Transactions>::iterator tit;

		pthread_mutex_lock(&m_mutexBlock);
		for (bit = m_lst_block.begin(); bit != m_lst_block.end(); ++bit)
		{
			for (tit = bit->lst_ts.begin(); tit != bit->lst_ts.end(); ++tit)
			{
				if (tit->recipient == addr)
					balan += tit->amount;
				else if (tit->sender == addr)
					balan -= tit->amount;
			}
		}
		pthread_mutex_unlock(&m_mutexBlock);

		return balan;
	}

	void BlockChain::DeleteDuplicateTransactions(const Block &block)
	{
		std::list<Transactions>::iterator selfIt;
		std::list<Transactions>::const_iterator otherIt;

		pthread_mutex_lock(&m_mutexTs);
		for (selfIt = m_lst_ts.begin(); selfIt != m_lst_ts.end();)
		{
			if (block.lst_ts.end() != std::find(block.lst_ts.begin(), block.lst_ts.end(), *selfIt))
			{
				selfIt = m_lst_ts.erase(selfIt);
			}
			else
			{
				++selfIt;
			}
		}
		pthread_mutex_unlock(&m_mutexTs);
	}
}