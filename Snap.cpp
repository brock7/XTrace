#include "stdafx.h"
#include "XTrace.h"
#include "Snap.h"
#include "tracer.h"

//typedef NTSTATUS (NTAPI *NtSuspendProcessPtr )(IN HANDLE ProcessHandle) = NULL;
//typedef NTSTATUS (NTAPI *NtResumeProcessPtr )(IN HANDLE ProcessHandle) = NULL;

Snap::Snap(void)
{
	m_traceNum = 1;
	m_ignoreWaiting = true;
	m_speed = 1;
	m_allModules = true;
	m_recOnce = false;

	HMODULE hmod = GetModuleHandle(_T("ntdll.dll"));

	//NtSuspendProcessPtr NtSuspendProcess = (NtSuspendProcessPtr ) GetProcAddress(hmod, "NtSuspendProcess");
	//NtResumeProcessPtr NtResumeProcess = (NtResumeProcessPtr ) GetProcAddress(hmod, "NtResumeProcess");
}

Snap::~Snap(void)
{
	if (m_hProcess != NULL) {
		CloseHandle(m_hProcess);
		m_hProcess = NULL;
	}
}

bool Snap::Open(DWORD pid)
{
	m_pid = pid;

	if (m_hProcess != NULL) {
		CloseHandle(m_hProcess);
	}

	m_hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD, FALSE, pid);
	if (m_hProcess == NULL)
		return false;

	m_addrRanges.clear();
	m_leftAddr = 0x80000000;
	m_rightAddr = 0;

	m_addrSet.clear();

	return true;
}

HMODULE GetRemoteModuleHandle(HANDLE process)
{
	FARPROC fn = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "GetModuleHandleA");
	DWORD tid;
	HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE )fn, NULL, 0, &tid);
	WaitForSingleObject(thread, INFINITE);

	HMODULE hmod;
	GetExitCodeThread(thread, (LPDWORD )&hmod);
	CloseHandle(thread);

	return hmod;
}

bool Snap::Start()
{
	if (m_hProcess == NULL)
		return false;

	/*
	if (!m_allModules) {

		MODULEINFO modInfo;
		GetModuleInformation(m_hProcess, NULL, &modInfo, sizeof(modInfo));
		modInfo.lpBaseOfDll = GetRemoteModuleHandle(m_hProcess);
		m_addrRanges.push_back(AddrRange((ULONG_PTR )modInfo.lpBaseOfDll, 
			(ULONG_PTR )modInfo.lpBaseOfDll + modInfo.SizeOfImage));
	}
	*/

	m_savedSnaps.clear();
	// m_addrSet.clear();

	m_timerId = ::timeSetEvent(m_speed, 0, &Snap::OnTimer, (DWORD_PTR )this, TIME_PERIODIC);
	if (m_timerId == 0)
		return false;

	return true;
}

bool Snap::Stop()
{
	if (m_hProcess == NULL)
		return false;

	timeKillEvent(m_timerId);
	return true;
}

size_t Snap::ReadCommand(void* addr, BYTE* buf, SIZE_T len)
{
	if (!::ReadProcessMemory(m_hProcess, addr, buf, len, &len))
		return 0;

	return len;
}

void CALLBACK Snap::OnTimer(UINT uTimerID, UINT uMsg, DWORD_PTR dwUser, 
							 DWORD_PTR dw1, DWORD_PTR dw2)
{
	Snap* snap = (Snap* )dwUser;
	snap->CreatSnap();
}

void ASyncDisasm(TraceItem& item);
void Snap::PostSnap(DWORD tid, ThreadSnap& snap)
{
	TraceItem item;
	item.type = ITEM_TYPE_SNAP;
	item.addr = (PVOID )snap.progPtr;
	item.tid = tid;
	item.hitflag = 0;
	item.traceNum = m_traceNum;
	ASyncDisasm(item);
}

bool Snap::CreateThreadSnap(HANDLE thread, ThreadSnap& snap)
{
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	SuspendThread(thread);
	BOOL r = GetThreadContext(thread, &ctx);
	ResumeThread(thread);
	snap.threadHandle = thread;
	snap.progPtr = r ? ctx.Eip : NULL;
	return true;
}

bool Snap::CreatSnap()
{
	HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, m_pid);
	if (hSnap == NULL)
		return false;
	
	ThreadSnap snap;
	std::map<DWORD, ThreadSnap> snaps;
	std::map<DWORD, ThreadSnap>::iterator it;
	HANDLE thread;

	THREADENTRY32 te;
	te.dwSize = sizeof(te);

	BOOL bContiune = ::Thread32First(hSnap, &te);
	while (bContiune) {

		if (te.th32OwnerProcessID == m_pid) {

			it = m_savedSnaps.find(te.th32ThreadID);
			if (it == m_savedSnaps.end()) {
				// new thread
				thread = OpenThread(THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
				CreateThreadSnap(thread, snap);
				snaps[te.th32ThreadID] = snap;

				if (TestAddrRange(snap.progPtr)) {
					PostSnap(te.th32ThreadID, snap);
					if (m_recOnce)
						m_addrSet.insert(snap.progPtr);

					UpdateInfo(snap.progPtr);
				}

			} else {

				ThreadSnap& savedSnap = it->second;

				thread = savedSnap.threadHandle;
				CreateThreadSnap(thread, snap);
				snaps[te.th32ThreadID] = snap;

				if (!(m_ignoreWaiting && savedSnap.progPtr == snap.progPtr) && TestAddrRange(snap.progPtr)) {

					PostSnap(te.th32ThreadID, snap);
					if (m_recOnce)
						m_addrSet.insert(snap.progPtr);

					UpdateInfo(snap.progPtr);
				}

				m_savedSnaps.erase(it);
			}
		}			

		bContiune = ::Thread32Next(hSnap, &te);
	}

	CloseHandle( hSnap );

	// exited threads
	for (it = m_savedSnaps.begin(); it != m_savedSnaps.end(); it ++ ) {
		::CloseHandle(it->second.threadHandle);
	}

	m_savedSnaps = snaps;

	return true;
}
