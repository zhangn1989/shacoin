#ifndef __THREADPOOL_H
#define __THREADPOOL_H

#include <pthread.h>

#include <queue>

namespace ShaCoin
{
	template <class T1, class T2>
	class ThreadPool
	{
	public:
		ThreadPool(int count);
		virtual ~ThreadPool();

		void addTask(T1 t);
		int start();
		void stop();

		inline void setTaskFunc(T2 *t2, void(T2::*taskFunc) (T1 &t))
		{
			m_t2 = t2;
			m_taskFunc = taskFunc;
		}

	private:
		int m_count;
		bool m_bStop;
		std::queue<T1> m_queue;
		std::vector<pthread_t> m_vecTid;
		T2 *m_t2;
		void (T2::*m_taskFunc) (T1 &t);

		static pthread_mutex_t m_mutexPack;
		static pthread_cond_t m_cond;

		static void *threadFunc(void *arg);
		void threadHandler();
	};

	template<class T1, class T2>
	pthread_mutex_t ThreadPool<T1, T2>::m_mutexPack = PTHREAD_MUTEX_INITIALIZER;
	template<class T1, class T2>
	pthread_cond_t ThreadPool<T1, T2>::m_cond = PTHREAD_COND_INITIALIZER;

	template<class T1, class T2>
	ThreadPool<T1, T2>::ThreadPool(int count)
	{
		m_count = count;
	}

	template<class T1, class T2>
	ThreadPool<T1, T2>::~ThreadPool()
	{
		if (!m_bStop)
			stop();
	}

	template<class T1, class T2>
	void ThreadPool<T1, T2>::addTask(T1 t)
	{
		pthread_mutex_lock(&m_mutexPack);
		m_queue.push(t);
		pthread_mutex_unlock(&m_mutexPack);
		pthread_cond_signal(&m_cond);
	}

	template<class T1, class T2>
	int ThreadPool<T1, T2>::start()
	{
		int i;
		pthread_t tid;

		if (!m_t2)
			return 0;

		if (!m_taskFunc)
			return 0;

		if (m_count < 1)
			return 0;

		m_bStop = false;

		for (i = 0; i < m_count; ++i)
		{
			if (pthread_create(&tid, NULL, threadFunc, this) == 0)
				m_vecTid.push_back(tid);
		}

		return i;
	}

	template<class T1, class T2>
	void ThreadPool<T1, T2>::stop()
	{
		m_bStop = true;
		pthread_cond_broadcast(&m_cond);

		std::vector<pthread_t>::iterator it;
		for (it = m_vecTid.begin(); it != m_vecTid.end(); ++it)
			pthread_join(*it, NULL);
	}

	template<class T1, class T2>
	void *ThreadPool<T1, T2>::threadFunc(void *arg)
	{
		ThreadPool<T1, T2> *p = (ThreadPool<T1, T2>*)arg;
		p->threadHandler();
		return NULL;
	}

	template<class T1, class T2>
	void ThreadPool<T1, T2>::threadHandler()
	{
		while (!m_bStop)
		{
			pthread_mutex_lock(&m_mutexPack);
			while (m_queue.size() <= 0)
			{
				pthread_cond_wait(&m_cond, &m_mutexPack);
				if (m_bStop)
				{
					pthread_mutex_unlock(&m_mutexPack);
					return ;
				}
			}
			T1 t = m_queue.front();
			m_queue.pop();
			pthread_mutex_unlock(&m_mutexPack);
			(m_t2->*m_taskFunc)(t);
		}
	}
}

#endif
