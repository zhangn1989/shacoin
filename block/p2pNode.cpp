#include <string>
#include <algorithm>
#include <cstdlib>
#include <ctime>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include "p2pNode.hpp"

namespace ShaCoin
{
	P2PNode::P2PNode(const char *if_name)
	{
		m_sock = socket(AF_INET, SOCK_DGRAM, 0);//IPV4  SOCK_DGRAM 数据报套接字（UDP协议）  
		if (m_sock < 0)
		{
			perror("socket\n");
			return ;
		}

// 		int val = 1;
// 		if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
// 		{
// 			perror("setsockopt");
// 		}

		struct timeval tv_out;
		tv_out.tv_sec = 10;//等待10秒
		tv_out.tv_usec = 0;
		if (setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) < 0)
		{
			perror("setsockopt");
		}

		memset(&m_serverAddr, 0, sizeof(m_serverAddr));
		m_serverAddr.sin_family = AF_INET;
		m_serverAddr.sin_port = htons(SERVERPORT);
		m_serverAddr.sin_addr.s_addr = inet_addr(SERVERIP);
		socklen_t serverLen = sizeof(m_serverAddr);

		memset(&m_localAddr, 0, sizeof(m_localAddr));
		m_localAddr.sin_family = AF_INET;
		m_localAddr.sin_port = htons(LOCALPORT);
		m_localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		if (bind(m_sock, (struct sockaddr*)&m_localAddr, sizeof(m_localAddr)) < 0)
		{
			perror("bind");
			close(m_sock);
			exit(2);
		}

		
		memset(&m_recvAddr, 0, sizeof(m_recvAddr));
		socklen_t recvLen = sizeof(m_recvAddr);

		NodeInfo sendNode, recvNode;
		memset(&sendNode, 0, sizeof(NodeInfo));
		memset(&recvNode, 0, sizeof(NodeInfo));
		sendNode.cmd = cmd_register;
		sendNode.node.recvPort = LOCALPORT;
		get_local_ip(if_name, sendNode.node.recvIp);

		while (1)
		{
			if (sendto(m_sock, &sendNode, sizeof(NodeInfo), 0, (struct sockaddr*)&m_serverAddr, serverLen) < 0)
			{
				perror("sendto");
				close(m_sock);
				exit(4);
			}

			memset(&m_recvAddr, 0, sizeof(m_recvAddr));
			memset(&recvNode, 0, sizeof(NodeInfo));
			if (recvfrom(m_sock, &recvNode, sizeof(NodeInfo), 0, (struct sockaddr*)&m_recvAddr, &recvLen) < 0)
			{
				if (errno == EINTR || errno == EAGAIN)
					continue;

				perror("recvfrom");
				close(m_sock);
				exit(2);
			}

			if (recvNode.cmd != cmd_register)
				continue;

			m_selfNode = recvNode.node;
			break;
		}

		while (1)
		{
			memset(&sendNode, 0, sizeof(NodeInfo));
			memset(&recvNode, 0, sizeof(NodeInfo));
			memset(&m_recvAddr, 0, sizeof(m_recvAddr));

			sendNode.cmd = cmd_getnode;
			sendNode.node = m_selfNode;
			if (sendto(m_sock, &sendNode, sizeof(NodeInfo), 0, (struct sockaddr*)&m_serverAddr, serverLen) < 0)
			{
				perror("sendto");
				close(m_sock);
				exit(4);
			}

			if (recvfrom(m_sock, &recvNode, sizeof(NodeInfo), 0, (struct sockaddr*)&m_recvAddr, &recvLen) < 0)
			{
				if (errno == EINTR || errno == EAGAIN)
					continue;

				perror("recvfrom");
				close(m_sock);
				exit(2);
			}

			if (recvNode.cmd != cmd_getnode)
				continue;

			m_otherNode = recvNode.node;
			break;
		}

		//查询到的IP和接收到的IP如果不相同，则是内网环境
		//自己查询到的IP和另一个节点查询到的IP如果相同，则处于同一内网
		//同一内网的节点用内网传输数据，不在同一内网的节点只能用公网传输数据
		if (strcmp(m_selfNode.queryIp, m_selfNode.recvIp) &&
			!strcmp(m_selfNode.queryIp, m_otherNode.queryIp))
		{
			m_otherIP = m_otherNode.recvIp;
			m_otherPort = m_otherNode.recvPort;
		}
		else
		{
			m_otherIP = m_otherNode.queryIp;
			m_otherPort = m_otherNode.queryPort;
		}

		pthread_mutex_init(&m_mutexPack, NULL);
		pthread_mutex_init(&m_mutexResult, NULL);
	}

	P2PNode::~P2PNode()
	{
		NodeInfo sendNode;
		memset(&sendNode, 0, sizeof(NodeInfo));

		socklen_t serverLen = sizeof(m_serverAddr);

		sendNode.cmd = cmd_unregister;
		sendNode.node = m_selfNode;
		if (sendto(m_sock, &sendNode, sizeof(NodeInfo), 0, (struct sockaddr*)&m_serverAddr, serverLen) < 0)
		{
			perror("sendto");
			close(m_sock);
			exit(4);
		}

		close(m_sock);

		pthread_mutex_destroy(&m_mutexPack);
		pthread_mutex_destroy(&m_mutexResult);
	}

	P2PNode* P2PNode::Instance(const char *if_name)
	{
		static P2PNode node(if_name);
		return &node;
	}

	void P2PNode::Listen()
	{
		if (pthread_create(&m_tid, NULL, threadFunc, this) != 0)
		{
			close(m_sock);
			exit(2);
		}
	}

	void P2PNode::Broadcast(P2PCommand cmd, const BroadcastMessage &bm)
	{
		P2PMessage mess;
		std::string hash;

		memset(&mess, 0, sizeof(mess));
		mess.cmd = cmd;
		mess.index = 0;
		mess.total = 1;
		hash = Cryptography::GetHash(&bm, sizeof(BroadcastMessage));
		memcpy(mess.messHash, hash.c_str(), hash.length());
		mess.length = sizeof(BroadcastMessage);
		memcpy(mess.mess, &bm, mess.length);

		sendMessage(mess);
	}

	void P2PNode::MergeChain()
	{
		P2PMessage mess;

		unsigned int seed = (unsigned)time(NULL);
		int r = rand_r(&seed);
		std::string strHash = Cryptography::GetHash(&r, sizeof(r));

		memset(&mess, 0, sizeof(mess));
		mess.cmd = p2p_merge;
		mess.total = 1;
		strcpy(mess.messHash, strHash.c_str());
		sendMessage(mess);
	}

	void P2PNode::sendBlockChain()
	{
		P2PMessage mess;
		int i = 0;
		BlockChain *bc = BlockChain::Instance();
		std::string strBcJson = bc->GetJsonFromBlockList();
		std::string strBcHash = Cryptography::GetHash(strBcJson.c_str(), strBcJson.length());
		int total = strBcJson.length() / MAX_P2P_SIZE + 1;

		for (i = 0; i < total - 1; ++i)
		{
			memset(&mess, 0, sizeof(mess));
			mess.cmd = p2p_blockchain;
			mess.index = i;
			mess.total = total;
			mess.length = MAX_P2P_SIZE;
			strcpy(mess.messHash, strBcHash.c_str());
			strncpy(mess.mess, strBcJson.c_str() + i * MAX_P2P_SIZE, MAX_P2P_SIZE);

			sendMessage(mess);
		}

		memset(&mess, 0, sizeof(mess));
		mess.cmd = p2p_blockchain;
		mess.index = i;
		mess.total = total;
		mess.length = strBcJson.length() % MAX_P2P_SIZE;
		strcpy(mess.messHash, strBcHash.c_str());
		strncpy(mess.mess, strBcJson.c_str() + i * MAX_P2P_SIZE, mess.length);

		sendMessage(mess);
	}

	void P2PNode::sendMessage(P2PMessage &mess)
	{
		sockaddr_in otherAddr;
		memset(&otherAddr, 0, sizeof(otherAddr));
		otherAddr.sin_family = AF_INET;
		otherAddr.sin_port = htons(m_otherPort);
		otherAddr.sin_addr.s_addr = inet_addr(m_otherIP);

		P2PResult result;
		result.index = mess.index;
		memcpy(result.messHash, mess.messHash, sizeof(result.messHash));

		while (1)
		{
			if (sendto(m_sock, &mess, sizeof(P2PMessage), 0, (struct sockaddr*)&otherAddr, sizeof(otherAddr)) < 0)
			{
				perror("sendto");
				close(m_sock);
				exit(4);
			}

			sleep(1);

			pthread_mutex_lock(&m_mutexResult);
			if (m_lstResult.end() == std::find(m_lstResult.begin(), m_lstResult.end(), result))
			{
				pthread_mutex_unlock(&m_mutexResult);
				continue;
			}

			m_lstResult.remove(result);
			pthread_mutex_unlock(&m_mutexResult);
			break;
		}
	}

	void *P2PNode::threadFunc(void *arg)
	{
		P2PNode *p = (P2PNode*)arg;
		p->threadHandler();
		return NULL;
	}

	void P2PNode::threadHandler()
	{
		sockaddr_in otherAddr;
		memset(&otherAddr, 0, sizeof(otherAddr));
		otherAddr.sin_family = AF_INET;
		otherAddr.sin_port = htons(m_otherPort);
		otherAddr.sin_addr.s_addr = inet_addr(m_otherIP);

		P2PMessage recvMess;
		P2PMessage sendMess;
		P2PResult result;

		socklen_t recvLen = sizeof(m_recvAddr);

		ThreadPool<P2PMessage, P2PNode> tp(1);
		tp.setTaskFunc(this, &P2PNode::combinationPackage);
		tp.start();

		while (1)
		{
			memset(&recvMess, 0, sizeof(P2PMessage));
			memset(&sendMess, 0, sizeof(P2PMessage));
			memset(&result, 0, sizeof(P2PResult));
			memset(&m_recvAddr, 0, sizeof(m_recvAddr));

			if (recvfrom(m_sock, &recvMess, sizeof(P2PMessage), 0, (struct sockaddr*)&m_recvAddr, &recvLen) < 0)
			{
				if (errno == EINTR || errno == EAGAIN)
					continue;

				perror("recvfrom");
				tp.stop();
				close(m_sock);
				exit(2);
			}

			if (recvMess.cmd == p2p_result)
			{
				memcpy(&result, recvMess.mess, recvMess.length);
				pthread_mutex_lock(&m_mutexResult);
				m_lstResult.push_back(result);
				pthread_mutex_unlock(&m_mutexResult);
				continue;
			}

			tp.addTask(recvMess);

			result.index = recvMess.index;
			memcpy(result.messHash, recvMess.messHash, sizeof(recvMess.messHash));
			sendMess.cmd = p2p_result;
			sendMess.length = sizeof(result);
			memcpy(sendMess.mess, &result, sendMess.length);
			if (sendto(m_sock, &sendMess, sizeof(sendMess), 0, (struct sockaddr*)&m_recvAddr, sizeof(m_recvAddr)) < 0)
			{
				perror("sendto");
				tp.stop();
				close(m_sock);
				exit(4);
			}
		}
		tp.stop();
	}

	void P2PNode::combinationPackage(P2PMessage &mess)
	{
		Package package;
		int index = mess.index;
		std::list<Package>::iterator it;

		pthread_mutex_lock(&m_mutexPack);
		for (it = m_lstPackage.begin(); it != m_lstPackage.end(); ++it)
		{
			if (!strcmp(it->messHash, mess.messHash))
				break;
		}

		if (it == m_lstPackage.end())
		{
			package.total = mess.total;
			package.cmd = mess.cmd;
			memcpy(package.messHash, mess.messHash, sizeof(package.messHash));
			package.mapMess.insert(std::pair<int, std::string>(index, std::string(mess.mess, mess.length)));
			m_lstPackage.push_back(package);
		}
		else
		{
			it->mapMess.insert(std::pair<int, std::string>(index, std::string(mess.mess, mess.length)));
			package = *it;
		}
		pthread_mutex_unlock(&m_mutexPack);

		if (package.total == (int)package.mapMess.size())
		{
			std::string str;
			std::map<int, std::string>::iterator mapIt;
			for (mapIt = package.mapMess.begin(); mapIt != package.mapMess.end(); ++mapIt)
			{
				str += mapIt->second;
			}

			BlockChain *blockChain = BlockChain::Instance();

			switch (package.cmd)
			{
			case p2p_transaction:
			{
				BroadcastMessage bm;
				memset(&bm, 0, sizeof(bm));
				memcpy(&bm, str.c_str(), str.length());

				std::string strHash = ShaCoin::Cryptography::GetHash(bm.json, strlen(bm.json));
				
				Transactions ts = blockChain->GetTransactionsFromJson(bm.json);
				int balan = blockChain->CheckBalances(ts.sender);
				if (balan < ts.amount)
					break;

				if (Cryptography::Verify(bm.pubkey, strHash.c_str(), strHash.length(), bm.sign, sizeof(bm.sign), bm.signlen) < 1)
					break;

				blockChain->InsertTransactions(ts);
			}
				break;
			case p2p_bookkeeping:
			{
				BroadcastMessage bm;
				memset(&bm, 0, sizeof(bm));
				memcpy(&bm, str.c_str(), str.length());

				Block block = blockChain->GetBlockFromJson(std::string(bm.json, strlen(bm.json)));
				if (block.proof > blockChain->GetLastBlock().proof && blockChain->WorkloadVerification(block.proof))
				{
					blockChain->DeleteDuplicateTransactions(block);
					blockChain->InsertBlock(block);
				}
			}
				break;
			case p2p_result:
				break;
			case p2p_merge:
				sendBlockChain();
				break;
			case p2p_blockchain:
				blockChain->MergeBlockChain(str);
				break;
			default:
				break;
			}

			m_lstPackage.remove(package);
		}
	}

	int P2PNode::get_local_ip(const char *ifname, char *ip)
	{
		char *temp = NULL;
		int inet_sock;
		struct ifreq ifr;

		inet_sock = socket(AF_INET, SOCK_DGRAM, 0);

		memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
		memcpy(ifr.ifr_name, ifname, strlen(ifname));

		if (0 != ioctl(inet_sock, SIOCGIFADDR, &ifr))
		{
			perror("ioctl error");
			return -1;
		}

		temp = inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr);
		memcpy(ip, temp, strlen(temp));

		close(inet_sock);

		return 0;
	}
}
