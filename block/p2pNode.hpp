#ifndef __P2PNODE_H
#define __P2PNODE_H

#include <map>
#include <list>

#include "p2pServer.hpp"
#include "threadPool.hpp"

namespace ShaCoin
{
	class P2PNode
	{
	public:
		static P2PNode *Instance(const char *if_name);
		void Listen();

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

		struct sockaddr_in m_serverAddr;
		struct sockaddr_in m_localAddr;
		struct sockaddr_in m_recvAddr;

		typedef struct st_package
		{
			int group;
			int total;
			p2pCommand cmd;
			std::map<int, std::string> mapMess;
		} Package;

		std::list<Package> m_lstPackage;

		static void *threadFunc(void *arg);
		void threadHandler();
		void combinationPackage(p2pMessage &mess);
		int get_local_ip(const char *ifname, char *ip);
	};
}
#endif	//__P2PNODE_H
