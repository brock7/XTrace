#pragma once

// #define Tracer		Tracer4
#if 0
class Tracer1: public DbgEvent {
	Tracer1(void);

public:
	
	~Tracer1(void);

	static Tracer1& instance()
	{
		static Tracer1 inst;
		return inst;
	}

	static bool InitTracer();

	EventHResult OnException(DWORD tid, EXCEPTION_DEBUG_INFO& info);
	EventHResult OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info);
	EventHResult OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info);
	EventHResult OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info);
	EventHResult OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info);
	EventHResult OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info);
	EventHResult OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO & info);
	EventHResult OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info);	
	EventHResult OnRipEvent(DWORD tid, RIP_INFO& info);

	bool IsEnabled()
	{
		return false;
	}

	bool Enable(bool enable)
	{
		return false;
	}

protected:
	
	bool TestAddrRange(ULONG_PTR addr);
	bool IsTracedThread(DWORD tid);

	void OnStep(ThreadInfo* thread, EXCEPTION_DEBUG_INFO& info);

public:
	typedef std::set<DWORD>	ThreadIdSet;

	ThreadIdSet			m_tracedThreads;

	struct AddrRange {
		AddrRange(ULONG_PTR b, ULONG_PTR e)
		{
			begin = b;
			end = e;
		}

		ULONG_PTR		begin;
		ULONG_PTR		end;
	};

	typedef std::vector<AddrRange> AddrRanges;

	AddrRanges		m_addrRanges;

	VOID*			m_mainModMap;

	bool			m_isCreateProc;

	PVOID			m_lastStepAddr;
};

//////////////////////////////////////////////////////////////////////////

class Tracer2: public DbgEvent {
	Tracer2(void);

public:

	~Tracer2(void);

	static Tracer2& instance()
	{
		static Tracer2 inst;
		return inst;
	}

	bool IsEnabled()
	{
		return false;
	}

	bool Enable(bool enable)
	{
		return false;
	}

	static bool InitTracer();

	EventHResult OnException(DWORD tid, EXCEPTION_DEBUG_INFO& info);
	EventHResult OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info);
	EventHResult OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info);
	EventHResult OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info);
	EventHResult OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info);
	EventHResult OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info);
	EventHResult OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO & info);
	EventHResult OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info);	
	EventHResult OnRipEvent(DWORD tid, RIP_INFO& info);

protected:

	bool TestAddrRange(ULONG_PTR addr);
	PVOID GetBackup(ULONG_PTR addr);

	bool IsTracedThread(DWORD tid);

	void OnStep(DWORD tid, EXCEPTION_DEBUG_INFO& info);

	bool WriteINT3(MEMORY_BASIC_INFORMATION& memInfo);
	bool AddTraceMemBlk(MEMORY_BASIC_INFORMATION& memInfo);
	void ResetINT3();
	bool RestoreInst(ULONG_PTR addr);

	bool RestoreData(ULONG_PTR addr, size_t len);

public:
	typedef std::set<DWORD>	ThreadIdSet;

	ThreadIdSet			m_tracedThreads;

	struct AddrRange {
		AddrRange(ULONG_PTR b, ULONG_PTR e)
		{
			begin = b;
			end = e;
		}

		ULONG_PTR					begin;
		ULONG_PTR					end;
		MEMORY_BASIC_INFORMATION	info;
		PVOID						backup;
	};

	typedef std::vector<AddrRange> AddrRanges;

	AddrRanges		m_addrRanges;
	bool			m_isCreateProc;
	PVOID			m_lastStepAddr;
};

#endif

//////////////////////////////////////////////////////////////////////////
class TracerBase: public DbgEvent {

public:
	virtual bool InitTracer() = 0;
	virtual bool IsEnabled() = 0;
	virtual bool Enable(bool enable) = 0;
	virtual void IncTraceNum() = 0;
	virtual bool AddTraceMemBlk(ULONG_PTR addr, DWORD width) = 0;
};

class Tracer3: public TracerBase {
	Tracer3(void);

public:

	~Tracer3(void);

	static Tracer3& instance()
	{
		static Tracer3 inst;
		return inst;
	}

	virtual bool InitTracer();

	virtual bool IsEnabled()
	{
		return m_enbale;
	}

	virtual bool Enable(bool enable);

	void IncTraceNum()
	{
		m_traceNum ++;
	}

	EventHResult OnBreakPoint(DWORD tid, BreakPoint& bp, EXCEPTION_DEBUG_INFO& info);
	EventHResult OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info);
	EventHResult OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info);
	EventHResult OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info);
	EventHResult OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info);
	EventHResult OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info);
	EventHResult OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO & info);
	EventHResult OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info);	
	EventHResult OnRipEvent(DWORD tid, RIP_INFO& info);

protected:

	bool TestAddrRange(ULONG_PTR addr);
	PVOID GetBackup(ULONG_PTR addr);

	bool IsTracedThread(DWORD tid);

	void OnStep(DWORD tid, EXCEPTION_DEBUG_INFO& info);

	bool AddTraceMemBlk(ULONG_PTR addr, DWORD width);

public:
	typedef std::set<DWORD>	ThreadIdSet;

	ThreadIdSet			m_tracedThreads;

	struct AddrRange {
		AddrRange(ULONG_PTR b, ULONG_PTR e)
		{
			begin = b;
			end = e;
		}

		ULONG_PTR					begin;
		ULONG_PTR					end;
		// MEMORY_BASIC_INFORMATION	info;
	};

	typedef std::vector<AddrRange> AddrRanges;

	AddrRanges		m_addrRanges;
	bool			m_isCreateProc;
	PVOID			m_lastStepAddr;
	typedef std::set<ULONG_PTR> AddrSet;
	AddrSet			m_hits;
	bool			m_hitflag;
	bool			m_enbale;
	ULONG			m_traceNum;	
};

//////////////////////////////////////////////////////////////////////////

class Tracer4: public TracerBase {
	Tracer4(void);

public:

	~Tracer4(void);

	static Tracer4& instance()
	{
		static Tracer4 inst;
		return inst;
	}

	virtual  bool InitTracer();

	virtual bool IsEnabled()
	{
		return m_enbale;
	}

	virtual bool Enable(bool enable);

	virtual void IncTraceNum()
	{
		m_traceNum ++;
	}

	EventHResult OnBreakPoint(DWORD tid, BreakPoint& bp, EXCEPTION_DEBUG_INFO& info);
	EventHResult OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info);
	EventHResult OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info);
	EventHResult OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info);
	EventHResult OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info);
	EventHResult OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info);
	EventHResult OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO & info);
	EventHResult OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info);	
	EventHResult OnRipEvent(DWORD tid, RIP_INFO& info);

protected:

	bool TestAddrRange(ULONG_PTR addr);
	PVOID GetBackup(ULONG_PTR addr);

	bool IsTracedThread(DWORD tid);

	void OnStep(DWORD tid, EXCEPTION_DEBUG_INFO& info);

	bool AddTraceMemBlk(ULONG_PTR addr, DWORD width);

	void SetBreakPoints(ULONG_PTR addr, ULONG size);

public:
	typedef std::set<DWORD>	ThreadIdSet;

	ThreadIdSet			m_tracedThreads;

	struct AddrRange {
		AddrRange(ULONG_PTR b, ULONG_PTR e)
		{
			begin = b;
			end = e;
		}

		ULONG_PTR					begin;
		ULONG_PTR					end;
		// MEMORY_BASIC_INFORMATION	info;
	};

	typedef std::vector<AddrRange> AddrRanges;

	AddrRanges		m_addrRanges;
	bool			m_isCreateProc;
	PVOID			m_lastStepAddr;
	typedef std::set<ULONG_PTR> AddrSet;
	AddrSet			m_hits;
	bool			m_hitflag;
	bool			m_enbale;
	ULONG			m_traceNum;
};

//////////////////////////////////////////////////////////////////////////

// for trace

#define		ITEM_TYPE_TRACE		0
#define		ITEM_TYPE_SNAP		1

struct TraceItem {
	BYTE	type;
	DWORD	tid;
	PVOID	addr;
	long	traceNum;
	bool	hitflag;
};

void ASyncDisasm(TraceItem& item);
