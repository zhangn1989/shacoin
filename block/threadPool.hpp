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
		pthread_mutex_t m_mutex;
		pthread_cond_t m_cond;
		T2 *m_t2;
		void (T2::*m_taskFunc) (T1 &t);

		static void *threadFunc(void *arg);
		void threadHandler();
	};

	template<class T1, class T2>
	ThreadPool<T1, T2>::ThreadPool(int count)
	{
		m_count = count;
		pthread_mutex_init(&m_mutex, NULL);
		pthread_cond_init(&m_cond, NULL);
	}

	template<class T1, class T2>
	ThreadPool<T1, T2>::~ThreadPool()
	{
		if (!m_bStop)
			stop();

		pthread_mutex_destroy(&m_mutex);
		pthread_cond_destroy(&m_cond);
	}

	template<class T1, class T2>
	void ThreadPool<T1, T2>::addTask(T1 t)
	{
		pthread_mutex_lock(&m_mutex);
		m_queue.push(t);
		pthread_mutex_unlock(&m_mutex);
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
			pthread_mutex_lock(&m_mutex);
			while (m_queue.size() <= 0)
			{
				pthread_cond_wait(&m_cond, &m_mutex);
				if (!m_bStop)
				{
					pthread_mutex_unlock(&m_mutex);
					return ;
				}
			}
			T1 t = m_queue.front();
			m_queue.pop();
			pthread_mutex_unlock(&m_mutex);
			(m_t2->*m_taskFunc)(t);
		}
	}
}

#endif
