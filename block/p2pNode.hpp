#ifndef __P2PNODE_H
#define __P2PNODE_H

#include <map>
#include <list>

#include <netinet/in.h>

#include "p2pServer.hpp"
#include "threadPool.hpp"
#include "cryptography.hpp"
#include "blockChain.hpp"

namespace ShaCoin
{

#define MAX_UDP_SIZE	65507
#define MAX_P2P_SIZE	(MAX_UDP_SIZE - sizeof(int) *2 - sizeof(P2PCommand) - sizeof(size_t) - 64)

	typedef enum
	{
		p2p_transaction = 0x2000,
		p2p_bookkeeping,
		p2p_result,
		p2p_max
	} P2PCommand;

	typedef struct st_broadcast
	{
		KeyData pubkey;
		char json[1024];
		unsigned int signlen;
		unsigned char sign[1024];
	} __attribute__((packed))
		BroadcastMessage;

	typedef struct st_p2pMessage
	{
		int index;
		int total;
		char messHash[64];
		P2PCommand cmd;
		size_t length;
		char mess[MAX_P2P_SIZE];
	} __attribute__((packed))
		P2PMessage;

	typedef struct st_p2pResult
	{
		int index;
		char messHash[64];

		bool operator == (const struct st_p2pResult & value) const
		{
			return
				this->index == value.index &&
				!strcmp(this->messHash, value.messHash);
		}
	} __attribute__((packed))
		P2PResult;

	class P2PNode
	{
	public:
		static P2PNode *Instance(const char *if_name);
		void Listen();
		void Broadcast(P2PCommand cmd, const BroadcastMessage &bm);

	protected:
		P2PNode(const char *if_name);
		virtual ~P2PNode();

	private:
		int m_sock;
		Node m_selfNode;
		Node m_otherNode;
		char *m_otherIP;
		int m_otherPort;
		pthread_t m_tid;
		pthread_mutex_t m_mutexPack;
		pthread_mutex_t m_mutexResult;

		struct sockaddr_in m_serverAddr;
		struct sockaddr_in m_localAddr;
		struct sockaddr_in m_recvAddr;

		typedef struct st_package
		{
			int total;
			char messHash[64];
			P2PCommand cmd;
			std::map<int, std::string> mapMess;
		} Package;

		std::list<Package> m_lstPackage;
		std::list<P2PResult> m_lstResult;

		static void *threadFunc(void *arg);
		void threadHandler();
		void combinationPackage(P2PMessage &mess);
		int get_local_ip(const char *ifname, char *ip);
	};
}
#endif	//__P2PNODE_H
