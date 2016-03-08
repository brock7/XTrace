#pragma once

class Snap
{
protected:
	Snap(void);
	~Snap(void);
public:

	static Snap& instance()
	{
		static Snap inst;
		return inst;
	}

	bool Open(DWORD pid);
	bool Start();
	bool Stop();

	DWORD GetPID() const
	{
		return m_pid;
	}

	void SetSpeed(DWORD speed)
	{
		m_speed = speed;		
	}

	DWORD GetSpeed() const
	{
		return m_speed;		
	}

	void AddMemRange(ULONG_PTR base, ULONG width)
	{
		m_addrRanges.push_back(AddrRange(base, base + width));
	}

	size_t ReadCommand(void* addr, BYTE* buf, SIZE_T len);	

	struct ThreadSnap {
		ULONG_PTR		progPtr;
		HANDLE			threadHandle;
	};

	void IncNum()
	{
		m_traceNum ++;
	}


protected:

	static void CALLBACK OnTimer(UINT uTimerID, UINT uMsg, DWORD_PTR dwUser, 
		DWORD_PTR dw1, DWORD_PTR dw2); 

	void PostSnap(DWORD tid, ThreadSnap& snap);
	bool CreateThreadSnap(HANDLE thread, ThreadSnap& snap);
	bool CreatSnap();

	bool TestAddrRange(ULONG_PTR addr)
	{
		if (m_recOnce) {
			if (m_addrSet.find(addr) != m_addrSet.end())
				return false;
		}

		if (m_allModules)
			return true;

		for (size_t i = 0; i < m_addrRanges.size(); i ++) {
			if (addr >= m_addrRanges[i].begin && addr <= m_addrRanges[i].end)
				return true;
		}

		return false;
	}

	void UpdateInfo(ULONG_PTR addr)
	{
		if (m_leftAddr > addr)
			m_leftAddr = addr;

		if (m_rightAddr < addr)
			m_rightAddr = addr;
	}


public:

	bool		m_allModules;
	bool		m_recOnce;
	ULONG_PTR				m_leftAddr;
	ULONG_PTR				m_rightAddr;


protected:

	DWORD		m_speed;
	bool		m_ignoreWaiting;
	DWORD		m_pid;
	HANDLE		m_hProcess;
	DWORD		m_traceNum;

	DWORD		m_timerId;

	std::map<DWORD, ThreadSnap>	m_savedSnaps;


	struct AddrRange {
		AddrRange(ULONG_PTR b, ULONG_PTR e)
		{
			begin = b;
			end = e;
		}

		ULONG_PTR					begin;
		ULONG_PTR					end;
	};

	typedef std::vector<AddrRange> AddrRanges;

	AddrRanges	m_addrRanges;

	std::set<ULONG_PTR>		m_addrSet;

};
