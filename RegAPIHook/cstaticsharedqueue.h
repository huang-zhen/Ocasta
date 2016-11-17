#ifndef CSTATICSHAREDQUEUE_H
#define CSTATICSHAREDQUEUE_H

#include <windows.h>
#include <assert.h>

template<class T> class CStaticSharedQueue {
public:
	struct header {
		int head;
		int tail;
	};
	
	CStaticSharedQueue(const char *name, int count) {
		char buf[80];

		sprintf_s(buf, sizeof(buf), "%s_mutex", name);
		m_mutex = CreateMutexA(NULL, FALSE, buf);
		sprintf_s(buf, sizeof(buf), "%s_sem_full", name);
		m_sem_full = CreateSemaphoreA(NULL, count, count, buf);
		sprintf_s(buf, sizeof(buf), "%s_sem_empty", name);
		m_sem_empty = CreateSemaphoreA(NULL, 0, count, buf);

		m_memsize =  count * sizeof(T) + sizeof(header);
		m_count = count + 1;

		BOOL fInit;

		m_maphandle = CreateFileMappingA( 
			INVALID_HANDLE_VALUE, // use paging file
			NULL,                 // default security attributes
			PAGE_READWRITE,       // read/write access
			0,                    // size: high 32-bits
			m_memsize,		     // size: low 32-bits
			name);				 // name of map object
		if (m_maphandle == NULL) 
			return; 
	 
		// The first process to attach initializes memory.
		fInit = (GetLastError() != ERROR_ALREADY_EXISTS); 

		// Get a pointer to the file-mapped shared memory.
		m_memptr = (PBYTE)MapViewOfFile( 
			m_maphandle,     // object to map view of
			FILE_MAP_WRITE, // read/write access
			0,              // high offset:  map from
			0,              // low offset:   beginning
			0);             // default: map entire file
		if (m_memptr == NULL) 
			return; 
 
		// Initialize memory if this is the first process.
		if (fInit) 
			memset(m_memptr, '\0', m_memsize); 

	}
	
	~CStaticSharedQueue() {
			UnmapViewOfFile(m_memptr);
			CloseHandle(m_maphandle);
			CloseHandle(m_mutex);
	}
	
	int size() {
		int ret;
		if (lock_mutex() == 1) {
			int head = get_head();
			int tail = get_tail();
			unlock_mutex();
			ret = abs(tail - head);
		} else
			ret = -1;
		return ret;
	}

	int add_tail(T *t) {
		wait_sem(m_sem_full);
		if (lock_mutex() == 1) {
			int head = get_head();
			int tail = get_tail();
			//assert((tail + 1) % m_count != head);
			PBYTE pOff = m_memptr + tail * sizeof(T) + sizeof(header);
			*(T *)pOff = *t;
			set_tail((tail + 1) % m_count);
			release_sem(m_sem_empty);
			unlock_mutex();
		}
		return 1;
	}

	int remove_head(T* t) {
		wait_sem(m_sem_empty);
		if (lock_mutex() == 1) {
			int head = get_head();
			int tail = get_tail();
			//assert(head % m_count != tail);
			PBYTE pOff = m_memptr + head * sizeof(T) + sizeof(header);
			*t = *(T *)pOff;
			set_head((head + 1) % m_count);
			release_sem(m_sem_full);
			unlock_mutex();
		}
		return 1;
	}

	void reset()
	{
		memset(m_memptr, 0, m_memsize);
	}

protected:
	int get_head() const {
		return ((header *)m_memptr)->head;
	}
	
	int get_tail() const {
		return ((header *)m_memptr)->tail;
	}

	void set_head(int value) {
		((header *)m_memptr)->head = value;
	}
	
	void set_tail(int value) {
		((header *)m_memptr)->tail = value;
	}

	int lock_mutex()
	// return 1 on success
	{
		DWORD dwWaitResult; 
		int ret;

		// Request ownership of mutex.
		dwWaitResult = WaitForSingleObject( 
			m_mutex,   // handle to mutex
			INFINITE);
	 
		switch (dwWaitResult) 
		{
			// The thread got mutex ownership.
			case WAIT_OBJECT_0:
				ret = 1;
				break;
			case WAIT_TIMEOUT:
				ret = 0;
				break;
			case WAIT_ABANDONED:
			default:
				ret = -1;
				break;
		}
		return ret;
	}

	int unlock_mutex()
	// return 1 on success
	{
		if (ReleaseMutex(m_mutex))
			return 1;
		else
			return 0;
	}

	int wait_sem(HANDLE sem)
	// return 1 on success
	{
		DWORD dwWaitResult; 
		int ret;

		dwWaitResult = WaitForSingleObject( 
			sem,
			INFINITE);
	 
		switch (dwWaitResult) 
		{
			case WAIT_OBJECT_0:
				ret = 1;
				break;
			case WAIT_TIMEOUT:
				ret = 0;
				break;
			case WAIT_ABANDONED:
			default:
				ret = -1;
				break;
		}
		return ret;
	}

	int release_sem(HANDLE sem)
	// return 1 on success
	{
		// Increment the count of the semaphore.
		if (!ReleaseSemaphore( 
				sem,		  // handle to semaphore
				1,           // increase count by one
				NULL) )      // not interested in previous count
		{
			return 0;
		}
		return 1;
	}

	int m_count;
	// lock to protect access to sharedmem
	HANDLE m_mutex;

	HANDLE m_sem_full;
	HANDLE m_sem_empty;

	// sharedmem
	HANDLE m_maphandle;
	PBYTE m_memptr;
	int m_memsize;
};

#endif
