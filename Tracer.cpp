#include "stdafx.h"
#include "XTrace.h"
#include ".\tracer.h"
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")
#include "ProcessDlg.h"
#include "MsgQueue.h"
extern "C" {
#include "disasm/disasm.h"
}

//////////////////////////////////////////////////////////////////////////

#define PROCESS_DEP_ENABLE				0x1
#define PROCESS_DEP_DISABLE				0x0
#define PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION	0x00000002

DWORD SetProcDep(HANDLE hProc, DWORD dwVal);

//////////////////////////////////////////////////////////////////////////

extern bool manualSelMemSec;
extern bool autoSelectModule;

//////////////////////////////////////////////////////////////////////////

bool IsSpaceString(char* str)
{
	char* c = str;
	while (*c != ' ' && *c != '\t' && *c != 0)
		c ++;

	return *c == 0;
}

bool IsFiltered(char* str)
{
	if (IsSpaceString(str))	
		return true;

	if (strstr(str, "Direct") != NULL)
		return true;

	return false;
}

extern "C" int TracerDecodeAddr(void* addr, char* symbol, int nsymb, char* comment)
{
	return 0;
	
	/*
	CHAR symBuf[1024];
	memset(symBuf, 0, sizeof(symBuf));
	PIMAGEHLP_SYMBOL sym = (PIMAGEHLP_SYMBOL )symBuf;
	DWORD disp = 0;
	sym->SizeOfStruct = sizeof(symBuf);
	sym->MaxNameLength = sizeof(symBuf) - sizeof(sym);
	strcpy(sym->Name, "?");

	if (SymGetSymFromAddr(g_dbgEng->GetProcessHandle(), (DWORD )addr, &disp, sym)) {
		if (disp) 
			_snprintf_s(symbol, nsymb, sizeof(symBuf) - 1, "%s+%xh(%08xh)", sym->Name, disp, addr);
		else
			_snprintf_s(symbol, nsymb, sizeof(symBuf) - 1, "%s(%08xh)", sym->Name, addr);

		return strlen(symbol);

	} else {

		// _snprintf(symbol, nsymb, "0x%08x", addr);

		return 0;
	}
	*/
}

//////////////////////////////////////////////////////////////////////////
#if 0

Tracer1::Tracer1(void)
{
	m_mainModMap = NULL;
	m_isCreateProc = false;
	m_lastStepAddr = NULL;
}

Tracer1::~Tracer1(void)
{
}


/*
void test(void) {                      // Old form. So what?
	int i,j,n;
	ulong l;
	char *pasm;
	t_disasm da;
	t_asmmodel am;
	char s[TEXTLEN],errtext[TEXTLEN];

	memset(&da, 0, sizeof(da));
	// Demonstration of Disassembler.
	printf("Disassembler:\n");

	// Quickly determine size of command.
	//l=Disasm("\x81\x05\xE0\x5A\x47\x00\x01\x00\x00\x00\x11\x22\x33\x44\x55\x66",
	//	10,0x400000,&da,DISASM_SIZE);
	//printf("Size of command = %i bytes\n",l);

	//l=Disasm("\xf3\xab",2,0x400000,&da,DISASM_CODE);
	//printf("%3i  %-24s  %-24s   (MASM)\n",l,da.dump,da.result);

	l=Disasm("\xff\x25\x54\x4c\x45\x00",6,0x41a0e0,&da,DISASM_CODE);

	printf("%3i  %-24s  %-24s   (MASM)\n",l,da.dump,da.result);
	
	return;


	// ADD [475AE0],1 MASM mode, lowercase, don't show default segment
	ideal=0; lowercase=1; putdefseg=0;
	l=Disasm("\x81\x05\xE0\x5A\x47\x00\x01\x00\x00\x00",
		10,0x400000,&da,DISASM_CODE);
	printf("%3i  %-24s  %-24s   (MASM)\n",l,da.dump,da.result);

	// ADD [475AE0],1 IDEAL mode, uppercase, show default segment
	ideal=1; lowercase=0; putdefseg=1;
	l=Disasm("\x81\x05\xE0\x5A\x47\x00\x01\x00\x00\x00",
		10,0x400000,&da,DISASM_CODE);
	printf("%3i  %-24s  %-24s   (IDEAL)\n",l,da.dump,da.result);

	// CALL 45187C
	l=Disasm("\xE8\x1F\x14\x00\x00",
		5,0x450458,&da,DISASM_CODE);
	printf("%3i  %-24s  %-24s   jmpconst=%08X\n",l,da.dump,da.result,da.jmpconst);

	// JNZ 450517
	l=Disasm("\x75\x72",
		2,0x4504A3,&da,DISASM_CODE);
	printf("%3i  %-24s  %-24s   jmpconst=%08X\n",l,da.dump,da.result,da.jmpconst);

	// Demonstration of Ass

}
*/

bool Tracer1::InitTracer()
{
	if (!g_dbgEng->RegisterEventHandle(instance()))
		return false;

	ideal = 0; lowercase = 1; putdefseg = 0;iswindowsnt = 1; extraprefix = 1; symbolic = 1;
	DecodeAddr = *TracerDecodeAddr;
	// test();

	return true;
}

//////////////////////////////////////////////////////////////////////////

bool Tracer1::TestAddrRange(ULONG_PTR addr)
{
	for (size_t i = 0; i < m_addrRanges.size(); i ++) {
		if (addr >= m_addrRanges[i].begin && addr <= m_addrRanges[i].end)
			return true;
	}

	return false;
}

bool Tracer1::IsTracedThread(DWORD tid)
{
	return m_tracedThreads.size() == 0 || 
		m_tracedThreads.find(tid) != m_tracedThreads.end();
}

EventHResult Tracer1::OnException(DWORD tid, EXCEPTION_DEBUG_INFO& info)
{
	if (info.ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP || 
		info.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT) {

		if (IsTracedThread(tid)) {

			ThreadInfo* thread = g_dbgEng->GetThread(tid);

			if (TestAddrRange((ULONG_PTR )info.ExceptionRecord.ExceptionAddress)) {
				
				OnStep(thread, info);				
			}

			g_dbgEng->SetSingleFlag(thread->hThread);
		}
	}

	return DbgNext;
}

EventHResult Tracer1::OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info)
{
	if (IsTracedThread(tid)) {

		PVOID startAddr = g_dbgEng->GetThreadStartAddress(info.hThread);

		if (TestAddrRange((ULONG_PTR )startAddr)) {

			g_dbgEng->SetSingleFlag(info.hThread);
		}
	}

	return DbgNext;
}

void GetPathPart(LPTSTR PathName)
{
	size_t len = lstrlen(PathName);
	TCHAR* c = PathName + len - 1;
	while (c != PathName) {
		if (*c == _T('\\')) {
			*c = 0;
			break;
		}

		c --;
	}
}

EventHResult Tracer1::OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info)
{
	MemDataProv prov(info.hProcess);
	CProcessDlg dlg(&prov);
	dlg.m_title = _T("Memory");
	dlg.m_multisel = true;
	while (dlg.DoModal() == IDOK) {

		MemDataProv::MemInfo& memInfo = prov.m_memInfoVec[dlg.m_dwSel - 1];
		m_addrRanges.push_back(AddrRange((ULONG_PTR )memInfo.BaseAddress, 
			((ULONG_PTR )memInfo.BaseAddress) + memInfo.RegionSize));
	}

	ModuleInfo* modInfo = g_dbgEng->GetMainModule();
	m_mainModMap = (VOID* )::LoadLibraryEx(modInfo->szModName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	PIMAGE_NT_HEADERS ntHdrs = ImageNtHeader(m_mainModMap);

	/*
	m_addrRanges.push_back(AddrRange((ULONG_PTR )modInfo->lpBaseOfDll, 
		(ULONG_PTR )modInfo->lpBaseOfDll + (ULONG_PTR )ntHdrs->OptionalHeader.SizeOfImage));

	m_tracedThreads.insert(tid);
	*/

	TCHAR symPath[MAX_PATH + 1];
	strcpy_s(symPath, MAX_PATH, modInfo->szModName);
	GetPathPart(symPath);

	if (!SymInitialize(info.hProcess, symPath, TRUE)) {
		g_dbgEng->Log(L_WARNING, "initializing symbols failed.\n");
	}

	// test();

	if (IsTracedThread(tid)) {

		PVOID startAddr = g_dbgEng->GetThreadStartAddress(info.hThread);

		if (TestAddrRange((ULONG_PTR )startAddr)) {
            g_dbgEng->SetSingleFlag(info.hThread);
		}
	}
	
	return DbgNext;
}

EventHResult Tracer1::OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info)
{
	return DbgNext;
}

EventHResult Tracer1::OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info)
{
	SymCleanup(g_dbgEng->GetProcessHandle());

	if (m_mainModMap)
		FreeLibrary((HMODULE )m_mainModMap);

	return DbgNext;
}

EventHResult Tracer1::OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info)
{
	return DbgNext;
}

EventHResult Tracer1::OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO & info)
{
	return DbgNext;
}

EventHResult Tracer1::OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info)
{
	char buf[1024] = { 0 };
	size_t len = info.nDebugStringLength > sizeof(buf) - 1 ? sizeof(buf) - 1 :
	info.nDebugStringLength ;

	if (g_dbgEng->ReadMemory(info.lpDebugStringData, (BYTE* )buf, len)) {
		if (!IsFiltered(buf))
			g_dbgEng->Log(L_WARNING, "DbgEng::OnDbgStr() - DbgStr: %s\n", buf);
	}

	return DbgContinue;
}

EventHResult Tracer1::OnRipEvent(DWORD tid, RIP_INFO& info)
{
	return DbgNext;
}

//////////////////////////////////////////////////////////////////////////

void Tracer1::OnStep(ThreadInfo* thread, EXCEPTION_DEBUG_INFO& info)
{
	// test();

	PVOID addr = info.ExceptionRecord.ExceptionAddress;

	if (m_lastStepAddr == addr)
		return;

	m_lastStepAddr = addr;

	t_disasm da;
	char code[32];
	
	memset(&da, 0, sizeof(da));
	
	size_t len = g_dbgEng->ReadMemory(addr, (BYTE* )code, 
		sizeof(code));
	
	ulong l = Disasm(code, len, (ulong )addr, &da, DISASM_SIZE);

	l = Disasm(code, l, (ulong )addr, &da, DISASM_CODE);

	g_dbgEng->Log(L_INFO, __LOGPREFIX__" - %p %3i  %-24s  %-24s \n", 
		addr, l, da.dump, da.result);
}

//////////////////////////////////////////////////////////////////////////
// Tracer2

Tracer2::Tracer2(void)
{
	m_isCreateProc = false;
	m_lastStepAddr = NULL;
}

Tracer2::~Tracer2(void)
{
}

bool Tracer2::InitTracer()
{
	if (!g_dbgEng->RegisterEventHandle(instance()))
		return false;

	ideal = 0; lowercase = 1; putdefseg = 0;iswindowsnt = 1; extraprefix = 1; symbolic = 1;
	DecodeAddr = *TracerDecodeAddr;
	// test();

	return true;
}

//////////////////////////////////////////////////////////////////////////

bool Tracer2::TestAddrRange(ULONG_PTR addr)
{
	for (size_t i = 0; i < m_addrRanges.size(); i ++) {
		if (addr >= m_addrRanges[i].begin && addr <= m_addrRanges[i].end)
			return true;
	}

	return false;
}

bool Tracer2::IsTracedThread(DWORD tid)
{
	return m_tracedThreads.size() == 0 || 
		m_tracedThreads.find(tid) != m_tracedThreads.end();
}

PVOID Tracer2::GetBackup(ULONG_PTR addr)
{
	for (size_t i = 0; i < m_addrRanges.size(); i ++) {
		if (addr >= m_addrRanges[i].begin && addr <= m_addrRanges[i].end) {
			return (PVOID )((ULONG_PTR )m_addrRanges[i].backup + addr - 
				m_addrRanges[i].begin);
		}
	}

	return NULL;
}

bool Tracer2::RestoreInst(ULONG_PTR addr)
{
	PVOID backup = GetBackup((ULONG_PTR )addr);
	if (backup) {

		t_disasm da;
		memset(&da, 0, sizeof(da));
		ulong l = Disasm((char* )backup, 32, (ulong )addr, &da, DISASM_SIZE);
		if (l == 0) {
			assert(false);
			return false;
		}
		
		return g_dbgEng->WriteMemory((PVOID )addr, (PBYTE )backup, l) == l;
	}

	return false;
}

bool Tracer2::RestoreData(ULONG_PTR addr, size_t len)
{
	PVOID backup = GetBackup((ULONG_PTR )addr);
	if (backup) {

		return g_dbgEng->WriteMemory((PVOID )addr, (PBYTE )backup, len) == len;
	}

	return false;
}

EventHResult Tracer2::OnException(DWORD tid, EXCEPTION_DEBUG_INFO& info)
{
	EXCEPTION_RECORD& excepRec = info.ExceptionRecord;

	if (excepRec.ExceptionCode == STATUS_BREAKPOINT) {

		ULONG_PTR addr = (ULONG_PTR )excepRec.ExceptionAddress;

		if (TestAddrRange(addr)) {
			if (!RestoreInst((ULONG_PTR )addr)) {

				assert(false);
			}

			OnStep(tid, info);

			ThreadInfo* thread = g_dbgEng->GetThread(tid);
			g_dbgEng->SetProgPtr(thread->hThread, addr);

		} 

	} else if (info.ExceptionRecord.ExceptionCode == STATUS_ACCESS_VIOLATION) {

		ULONG_PTR addr = (ULONG_PTR )excepRec.ExceptionAddress;

		if (TestAddrRange(excepRec.ExceptionInformation[1])) {

			if (!RestoreData((ULONG_PTR )excepRec.ExceptionInformation[1], sizeof(ULONG_PTR))) {

				assert(false);
			}

			OnStep(tid, info);

			ThreadInfo* thread = g_dbgEng->GetThread(tid);
			g_dbgEng->SetProgPtr(thread->hThread, addr);
		}
	}

	return DbgNext;
}

EventHResult Tracer2::OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info)
{
	if (TestAddrRange((ULONG_PTR )g_dbgEng->GetThreadStartAddress(info.hThread))) {
		m_tracedThreads.insert(tid);
	}

	/*
	if (IsTracedThread(tid)) {

	}
	*/

	return DbgNext;
}

bool Tracer2::WriteINT3(MEMORY_BASIC_INFORMATION& memInfo)
{
	BYTE code[1024];
	memset(code, 0xcc, sizeof(code));
	size_t codelen = sizeof(code);
    size_t written = 0;
	while (written < memInfo.RegionSize) {
		if (memInfo.RegionSize - written < codelen)
			codelen = memInfo.RegionSize - written;

		if (!g_dbgEng->WriteMemory((PVOID )(((ULONG_PTR )memInfo.BaseAddress) + written), 
			code, codelen))
		{
			assert(false);
			return false;
		}

		written += codelen;
	}

	return true;
}

void Tracer2::ResetINT3()
{
	for(size_t i = 0; i < m_addrRanges.size(); i ++) {
		WriteINT3(m_addrRanges[i].info);
	}
}

bool Tracer2::AddTraceMemBlk(MEMORY_BASIC_INFORMATION& memInfo)
{
	m_addrRanges.push_back(AddrRange((ULONG_PTR )memInfo.BaseAddress, 
		((ULONG_PTR )memInfo.BaseAddress) + memInfo.RegionSize));
	AddrRange& addrRange = m_addrRanges.back();
	addrRange.info = memInfo;
	addrRange.backup = malloc(memInfo.RegionSize);
	if (g_dbgEng->ReadMemory(memInfo.BaseAddress, (PBYTE )addrRange.backup, 
		memInfo.RegionSize) != memInfo.RegionSize) 
	{
		assert(false);
		return false;	
	}

	/*
	DWORD old;
	VirtualProtectEx(g_dbgEng->GetProcessHandle(), memInfo.BaseAddress, 
		memInfo.RegionSize, PAGE_NOACCESS, &old);
	*/

	return WriteINT3(memInfo);
}

EventHResult Tracer2::OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info)
{
	MemDataProv prov(info.hProcess);
	CProcessDlg dlg(&prov);
	dlg.m_title = _T("Memory");
	dlg.m_multisel = true;
	while (dlg.DoModal() == IDOK) {

		MemDataProv::MemInfo& memInfo = prov.m_memInfoVec[dlg.m_dwSel - 1];
		AddTraceMemBlk(memInfo);
	}

	if (TestAddrRange((ULONG_PTR )g_dbgEng->GetThreadStartAddress(info.hThread))) {
		m_tracedThreads.insert(tid);
	}

	ModuleInfo* modInfo = g_dbgEng->GetMainModule();

	/*
	TCHAR symPath[MAX_PATH];
	strcpy(symPath, modInfo->szModName);
	GetPathPart(symPath);

	if (!SymInitialize(info.hProcess, symPath, TRUE)) {
		g_dbgEng->Log(L_WARNING, "initializing symbols failed.\n");
	}
	*/

	/*
	if (IsTracedThread(tid)) {
		// write 0xcc
	}
	*/

	return DbgNext;
}

EventHResult Tracer2::OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info)
{
	return DbgNext;
}

EventHResult Tracer2::OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info)
{
	SymCleanup(g_dbgEng->GetProcessHandle());
	return DbgNext;
}

EventHResult Tracer2::OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info)
{
	return DbgNext;
}

EventHResult Tracer2::OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO & info)
{
	return DbgNext;
}

EventHResult Tracer2::OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info)
{
	char buf[1024] = { 0 };
	size_t len = info.nDebugStringLength > sizeof(buf) - 1 ? sizeof(buf) - 1 :
	info.nDebugStringLength ;

	if (g_dbgEng->ReadMemory(info.lpDebugStringData, (BYTE* )buf, len)) {
		if (!IsFiltered(buf))
			g_dbgEng->Log(L_WARNING, "DbgEng::OnDbgStr() - DbgStr: %s\n", buf);
	}

	return DbgContinue;
}

EventHResult Tracer2::OnRipEvent(DWORD tid, RIP_INFO& info)
{
	return DbgNext;
}

//////////////////////////////////////////////////////////////////////////

void Tracer2::OnStep(DWORD tid, EXCEPTION_DEBUG_INFO& info)
{
	PVOID addr = info.ExceptionRecord.ExceptionAddress;

	if (m_lastStepAddr == addr)
		return;

	m_lastStepAddr = addr;

	t_disasm da;
	char code[32];

	memset(&da, 0, sizeof(da));

	size_t len = g_dbgEng->ReadMemory(addr, (BYTE* )code, 
		sizeof(code));

	ulong l = Disasm(code, len, (ulong )addr, &da, DISASM_SIZE);

	l = Disasm(code, l, (ulong )addr, &da, DISASM_CODE);
	
	if (da.adrconst)
		RestoreData(da.adrconst, sizeof(PVOID));

	/*
	if (da.cmdtype == C_JMP || da.cmdtype == C_JMC || da.cmdtype == C_CAL) {
		INT N = da.adrconst;
	}
	*/

	g_dbgEng->Log(L_INFO, __LOGPREFIX__" - [%d] %p %3i  %-24s  %-24s \n", 
		tid, addr, l, da.dump, da.result);
}

#endif

//////////////////////////////////////////////////////////////////////////
// Tracer3

Tracer3::Tracer3(void)
{
	m_isCreateProc = false;
	m_lastStepAddr = NULL;
	m_enbale = false;
	m_traceNum = 1;
}

Tracer3::~Tracer3(void)
{
}

bool Tracer3::InitTracer()
{
	g_dbgEng->ClearEventHandles();

	if (!g_dbgEng->RegisterEventHandle(instance()))
		return false;

	ideal = 0; lowercase = 1; putdefseg = 0;iswindowsnt = 1; extraprefix = 1; symbolic = 1;
	DecodeAddr = *TracerDecodeAddr;
	// test();

	SetProcDep(g_dbgEng->GetProcessHandle(), PROCESS_DEP_DISABLE);

	return true;
}

bool Tracer3::TestAddrRange(ULONG_PTR addr)
{
	for (size_t i = 0; i < m_addrRanges.size(); i ++) {
		if (addr >= m_addrRanges[i].begin && addr <= m_addrRanges[i].end)
			return true;
	}

	return false;
}

bool Tracer3::IsTracedThread(DWORD tid)
{
	return m_tracedThreads.size() == 0 || 
		m_tracedThreads.find(tid) != m_tracedThreads.end();
}


EventHResult Tracer3::OnBreakPoint(DWORD tid, BreakPoint& bp, EXCEPTION_DEBUG_INFO& info)
{
	/*
	if (info.ExceptionRecord.ExceptionCode != STATUS_SINGLE_STEP && g_dbgEng->IsBreakPoint(info)) {

		ULONG_PTR addr = (ULONG_PTR )info.ExceptionRecord.ExceptionAddress;

		if (TestAddrRange(addr)) {

			OnStep(tid, info);

			// ThreadInfo* thread = g_dbgEng->GetThread(tid);
			// g_dbgEng->SetProgPtr(thread->hThread, addr);
		}
	}
	*/

	OnStep(tid, info);

	return DbgNext;
}

EventHResult Tracer3::OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info)
{
	/*
	if (TestAddrRange((ULONG_PTR )g_dbgEng->GetThreadStartAddress(info.hThread))) {
		m_tracedThreads.insert(tid);
	}
	*/

	return DbgNext;
}

bool Tracer3::Enable(bool enable)
{
	if (g_dbgEng->GetState() != DbgEng::StateRunning)
		return false;

	if (enable) {

		g_dbgEng->FreezeThreads();
		for (size_t i = 0; i < m_addrRanges.size(); i ++) {
			AddrRange& memInfo = m_addrRanges[i];
			g_dbgEng->SetBreakPoint((PVOID )memInfo.begin, BreakPoint::Access, memInfo.end - memInfo.begin);
		}

		g_dbgEng->UnfreezeThreads();

	} else {

		g_dbgEng->ClearBreakPoints();
		m_traceNum ++;
		// m_hits.clear();
	}

	m_enbale = enable;

	return enable;
}

bool Tracer3::AddTraceMemBlk(ULONG_PTR addr, DWORD width)
{
	if (TestAddrRange((ULONG_PTR )addr))
		return false;

	m_addrRanges.push_back(AddrRange((ULONG_PTR )addr, ((ULONG_PTR )addr) + width));
	AddrRange& addrRange = m_addrRanges.back();
	// addrRange.info = memInfo;
	// g_dbgEng->SetBreakPoint(memInfo.BaseAddress, BreakPoint::Access, memInfo.RegionSize);
	return true;
}

EventHResult Tracer3::OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info)
{
	if (manualSelMemSec) {

		MemDataProv prov(info.hProcess);
		CProcessDlg dlg(&prov);
		dlg.m_title = _T("Memory");
		dlg.m_multisel = true;
		while (dlg.DoModal() == IDOK) {

			MemDataProv::MemInfo& memInfo = prov.m_memInfoVec[dlg.m_dwSel - 1];
			AddTraceMemBlk((ULONG_PTR )memInfo.BaseAddress, memInfo.RegionSize);
		}

	} else if (autoSelectModule) {

		ModuleInfo* modInfo = g_dbgEng->GetMainModule();

		/*
		IMAGE_DOS_HEADER dosHdr;
		g_dbgEng->ReadMemory(modInfo->lpBaseOfDll, (PBYTE )&dosHdr, sizeof(dosHdr));
		IMAGE_NT_HEADERS ntHdrs;
		g_dbgEng->ReadMemory(MakePtr(modInfo->lpBaseOfDll, dosHdr.e_lfanew), (PBYTE )&ntHdrs, sizeof(ntHdrs));
		*/

		PBYTE base = (PBYTE )modInfo->lpBaseOfDll;
		PBYTE bound = base + modInfo->nImageSize; // ntHdrs.OptionalHeader.SizeOfImage;

		MEMORY_BASIC_INFORMATION memInfo;
		
		while (base < bound) {

			SIZE_T r = VirtualQueryEx(g_dbgEng->GetProcessHandle(), (PVOID )base, &memInfo, 
				sizeof(MEMORY_BASIC_INFORMATION));

			if (r != sizeof(MEMORY_BASIC_INFORMATION)) {
				break;
			}

			if (memInfo.State != MEM_COMMIT) {
				base += memInfo.RegionSize;
				continue;
			}

			if (IS_EXECUTE_MEMORY(memInfo.Protect)) {

				AddTraceMemBlk((ULONG_PTR )memInfo.BaseAddress, memInfo.RegionSize);
			}

			base += memInfo.RegionSize;			
		}
	}

	/*
	if (TestAddrRange((ULONG_PTR )g_dbgEng->GetThreadStartAddress(info.hThread))) {
		m_tracedThreads.insert(tid);
	}
	*/

	/*
	ModuleInfo* modInfo = g_dbgEng->GetMainModule();

	TCHAR symPath[MAX_PATH];
	strcpy(symPath, modInfo->szModName);
	GetPathPart(symPath);

	if (!SymInitialize(info.hProcess, symPath, TRUE)) {
		g_dbgEng->Log(L_WARNING, "initializing symbols failed.\n");
	}
	*/

	/*
	if (IsTracedThread(tid)) {
		// write 0xcc
	}
	*/

	return DbgNext;
}

EventHResult Tracer3::OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info)
{
	return DbgNext;
}

EventHResult Tracer3::OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info)
{
	SymCleanup(g_dbgEng->GetProcessHandle());
	return DbgNext;
}

EventHResult Tracer3::OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info)
{
	return DbgNext;
}

EventHResult Tracer3::OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO & info)
{
	return DbgNext;
}

EventHResult Tracer3::OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info)
{
	char buf[1024] = { 0 };
	size_t len = info.nDebugStringLength > sizeof(buf) - 1 ? sizeof(buf) - 1 :
	info.nDebugStringLength ;

	if (g_dbgEng->ReadMemory(info.lpDebugStringData, (BYTE* )buf, len)) {
		if (!IsFiltered(buf))
			g_dbgEng->Log(L_WARNING, __LOGPREFIX__ "DbgStr: %s\n", buf);
	}

	return DbgContinue;
}

EventHResult Tracer3::OnRipEvent(DWORD tid, RIP_INFO& info)
{
	return DbgNext;
}

//////////////////////////////////////////////////////////////////////////

void Tracer3::OnStep(DWORD tid, EXCEPTION_DEBUG_INFO& info)
{
	PVOID addr = info.ExceptionRecord.ExceptionAddress;

	if (m_hits.find((ULONG_PTR )addr) != m_hits.end()) {

		if (m_hitflag)
			return;

		m_hitflag = true;

	} else {

		m_hits.insert((ULONG_PTR )addr);
		m_hitflag = false;
	}

	TraceItem item;
	item.type = ITEM_TYPE_TRACE;
	item.addr = addr;
	item.tid = tid;
	item.hitflag = m_hitflag;
	item.traceNum = m_traceNum;
	ASyncDisasm(item);

	/*
	t_disasm da;
	char code[32];

	memset(&da, 0, sizeof(da));

	size_t len = g_dbgEng->ReadCommand(addr, (BYTE* )code, 
		sizeof(code));

	ulong l = Disasm(code, len, (ulong )addr, &da, DISASM_SIZE);

	l = Disasm(code, l, (ulong )addr, &da, DISASM_CODE);

	g_dbgEng->Log(L_INFO, __LOGPREFIX__" - [%d] ~%d%c%p %3i  %-24s  %-24s \n", 
		m_traceNum, tid, m_hitflag ? '*' : ' ', addr, l, da.dump, da.result);
	*/
}

//////////////////////////////////////////////////////////////////////////
// Tracer4

Tracer4::Tracer4(void)
{
	m_isCreateProc = false;
	m_lastStepAddr = NULL;
	m_enbale = false;
	m_traceNum = 1;
}

Tracer4::~Tracer4(void)
{
}

bool Tracer4::InitTracer()
{
	g_dbgEng->ClearEventHandles();

	if (!g_dbgEng->RegisterEventHandle(instance()))
		return false;

	ideal = 0; lowercase = 1; putdefseg = 0;iswindowsnt = 1; extraprefix = 1; symbolic = 1;
	DecodeAddr = *TracerDecodeAddr;

	SetProcDep(g_dbgEng->GetProcessHandle(), PROCESS_DEP_ENABLE);
	// test();

	return true;
}

bool Tracer4::TestAddrRange(ULONG_PTR addr)
{
	for (size_t i = 0; i < m_addrRanges.size(); i ++) {
		if (addr >= m_addrRanges[i].begin && addr <= m_addrRanges[i].end)
			return true;
	}

	return false;
}

bool Tracer4::IsTracedThread(DWORD tid)
{
	return m_tracedThreads.size() == 0 || 
		m_tracedThreads.find(tid) != m_tracedThreads.end();
}


EventHResult Tracer4::OnBreakPoint(DWORD tid, BreakPoint& bp, EXCEPTION_DEBUG_INFO& info)
{
	/*
	if (info.ExceptionRecord.ExceptionCode != STATUS_SINGLE_STEP && g_dbgEng->IsBreakPoint(info)) {

		ULONG_PTR addr = (ULONG_PTR )info.ExceptionRecord.ExceptionAddress;

		if (TestAddrRange(addr)) {

			OnStep(tid, info);

			// ThreadInfo* thread = g_dbgEng->GetThread(tid);
			// g_dbgEng->SetProgPtr(thread->hThread, addr);
		}
	}
	*/

	OnStep(tid, info);

	return DbgNext;
}

EventHResult Tracer4::OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info)
{
	/*
	if (TestAddrRange((ULONG_PTR )g_dbgEng->GetThreadStartAddress(info.hThread))) {
		m_tracedThreads.insert(tid);
	}
	*/

	return DbgNext;
}

extern ULONG BreakPointPieceSize;

void Tracer4::SetBreakPoints(ULONG_PTR addr, ULONG size)
{
	ULONG n = 0;
	ULONG picecSize;
	while (n < size) {
		if ( size - n < BreakPointPieceSize)
			picecSize = size - n;
		else
			picecSize = BreakPointPieceSize;

		g_dbgEng->SetBreakPoint(PVOID(addr + n), BreakPoint::Access, picecSize, true);

		n += picecSize;
	}
}

bool Tracer4::Enable(bool enable)
{
	if (g_dbgEng->GetState() != DbgEng::StateRunning)
		return false;

	if (enable) {

		g_dbgEng->FreezeThreads();
		for (size_t i = 0; i < m_addrRanges.size(); i ++) {
			AddrRange& memInfo = m_addrRanges[i];
			SetBreakPoints((ULONG_PTR )memInfo.begin, memInfo.end - memInfo.begin);
		}
		g_dbgEng->UnfreezeThreads();

	} else {

		g_dbgEng->ClearBreakPoints();
		m_traceNum ++;
		// m_hits.clear();
	}	

	m_enbale = enable;

	return enable;
}

bool Tracer4::AddTraceMemBlk(ULONG_PTR addr, DWORD width)
{
	if (TestAddrRange((ULONG_PTR )addr))
		return false;

	m_addrRanges.push_back(AddrRange((ULONG_PTR )addr, ((ULONG_PTR )addr) + width));
	AddrRange& addrRange = m_addrRanges.back();
	// addrRange.info = memInfo;
	// g_dbgEng->SetBreakPoint(memInfo.BaseAddress, BreakPoint::Access, memInfo.RegionSize);
	return true;
}

EventHResult Tracer4::OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info)
{
	if (manualSelMemSec) {

		MemDataProv prov(info.hProcess);
		CProcessDlg dlg(&prov);
		dlg.m_title = _T("Memory");
		dlg.m_multisel = true;
		while (dlg.DoModal() == IDOK) {

			MemDataProv::MemInfo& memInfo = prov.m_memInfoVec[dlg.m_dwSel - 1];
			AddTraceMemBlk((ULONG_PTR )memInfo.BaseAddress, memInfo.RegionSize);
		}

	} else if (autoSelectModule) {

		ModuleInfo* modInfo = g_dbgEng->GetMainModule();
		/*
		IMAGE_DOS_HEADER dosHdr;
		g_dbgEng->ReadMemory(modInfo->lpBaseOfDll, (PBYTE )&dosHdr, sizeof(dosHdr));
		IMAGE_NT_HEADERS ntHdrs;
		g_dbgEng->ReadMemory(MakePtr(modInfo->lpBaseOfDll, dosHdr.e_lfanew), (PBYTE )&ntHdrs, sizeof(ntHdrs));
		*/

		PBYTE base = (PBYTE )modInfo->lpBaseOfDll;
		PBYTE bound = base + modInfo->nImageSize; // ntHdrs.OptionalHeader.SizeOfImage;

		MEMORY_BASIC_INFORMATION memInfo;

		while (base < bound) {

			SIZE_T r = VirtualQueryEx(g_dbgEng->GetProcessHandle(), (PVOID )base, &memInfo, 
				sizeof(MEMORY_BASIC_INFORMATION));

			if (r != sizeof(MEMORY_BASIC_INFORMATION)) {
				break;
			}

			if (memInfo.State != MEM_COMMIT) {
				base += memInfo.RegionSize;
				continue;
			}

			if (IS_EXECUTE_MEMORY(memInfo.Protect)) {

				AddTraceMemBlk((ULONG_PTR )memInfo.BaseAddress, memInfo.RegionSize);
			}

			base += memInfo.RegionSize;			
		}
	}

	/*
	if (TestAddrRange((ULONG_PTR )g_dbgEng->GetThreadStartAddress(info.hThread))) {
		m_tracedThreads.insert(tid);
	}
	*/

	/*
	ModuleInfo* modInfo = g_dbgEng->GetMainModule();

	TCHAR symPath[MAX_PATH];
	strcpy(symPath, modInfo->szModName);
	GetPathPart(symPath);

	if (!SymInitialize(info.hProcess, symPath, TRUE)) {
		g_dbgEng->Log(L_WARNING, "initializing symbols failed.\n");
	}
	*/

	/*
	if (IsTracedThread(tid)) {
		// write 0xcc
	}
	*/

	return DbgNext;
}

EventHResult Tracer4::OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info)
{
	return DbgNext;
}

EventHResult Tracer4::OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info)
{
	SymCleanup(g_dbgEng->GetProcessHandle());
	return DbgNext;
}

EventHResult Tracer4::OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info)
{
	return DbgNext;
}

EventHResult Tracer4::OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO & info)
{
	return DbgNext;
}

EventHResult Tracer4::OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info)
{
	char buf[1024] = { 0 };
	size_t len = info.nDebugStringLength > sizeof(buf) - 1 ? sizeof(buf) - 1 :
	info.nDebugStringLength ;

	if (g_dbgEng->ReadMemory(info.lpDebugStringData, (BYTE* )buf, len)) {
		if (!IsFiltered(buf))
			g_dbgEng->Log(L_WARNING, __LOGPREFIX__ "DbgStr: %s\n", buf);
	}

	return DbgContinue;
}

EventHResult Tracer4::OnRipEvent(DWORD tid, RIP_INFO& info)
{
	return DbgNext;
}

//////////////////////////////////////////////////////////////////////////

void Tracer4::OnStep(DWORD tid, EXCEPTION_DEBUG_INFO& info)
{
	PVOID addr = info.ExceptionRecord.ExceptionAddress;

	if (m_hits.find((ULONG_PTR )addr) != m_hits.end()) {

		if (m_hitflag)
			return;

		m_hitflag = true;

	} else {

		m_hits.insert((ULONG_PTR )addr);
		m_hitflag = false;
	}

	TraceItem item;
	item.type = ITEM_TYPE_TRACE;
	item.addr = addr;
	item.tid = tid;
	item.hitflag = m_hitflag;
	item.traceNum = m_traceNum;
	ASyncDisasm(item);

	/*
	t_disasm da;
	char code[32];

	memset(&da, 0, sizeof(da));

	size_t len = g_dbgEng->ReadCommand(addr, (BYTE* )code, 
		sizeof(code));

	ulong l = Disasm(code, len, (ulong )addr, &da, DISASM_SIZE);

	l = Disasm(code, l, (ulong )addr, &da, DISASM_CODE);

	g_dbgEng->Log(L_INFO, __LOGPREFIX__" - [%d] ~%d%c%p %3i  %-24s  %-24s \n", 
		m_traceNum, tid, m_hitflag ? '*' : ' ', addr, l, da.dump, da.result);
	*/


}

//////////////////////////////////////////////////////////////////////////
MsgQueue<TraceItem> gHitQueue;

void ASyncDisasm(TraceItem& item)
{
	gHitQueue.enter(item);
}

void SyncDisasm(TraceItem& item)
{
	PVOID addr = item.addr;

	t_disasm da;
	char code[32];

	memset(&da, 0, sizeof(da));

	size_t len = g_dbgEng->ReadCommand(addr, (BYTE* )code, sizeof(code));

	ulong l = Disasm(code, len, (ulong )addr, &da, DISASM_SIZE);

	l = Disasm(code, l, (ulong )addr, &da, DISASM_CODE);

	g_dbgEng->Log(L_INFO, __LOGPREFIX__ "Trace: [%d] ~%d%c%p %3i  %-24s  %-24s \n", 
		item.traceNum, item.tid, item.hitflag ? '*' : ' ', addr, l, da.dump, da.result);
}

#include "Snap.h"

void DumpSnap(TraceItem& item)
{
	PVOID addr = item.addr;

	if (addr == NULL)
		return;

	t_disasm da;
	char code[32];

	memset(&da, 0, sizeof(da));

	size_t len = Snap::instance().ReadCommand(addr, (BYTE* )code, sizeof(code));

	ulong l = Disasm(code, len, (ulong )addr, &da, DISASM_SIZE);

	l = Disasm(code, l, (ulong )addr, &da, DISASM_CODE);

	g_dbgEng->Log(L_INFO, __LOGPREFIX__ "Snap: [%d] ~%d %p %3i  %-24s  %-24s \n", 
		item.traceNum, item.tid, addr, l, da.dump, da.result);
}

bool OutputThreadQuit = false;
static DWORD WINAPI OutputThread(void* p)
{
	while (!OutputThreadQuit) {
		TraceItem item = gHitQueue.leave();
		if (OutputThreadQuit)
			break;

		if (item.type == ITEM_TYPE_TRACE)
			SyncDisasm(item);
		else
			DumpSnap(item);
	}

	return 0;
}

bool InitOutputThread()
{
	DWORD tid;
	HANDLE h = ::CreateThread(NULL, 0, OutputThread, NULL, 0, &tid);
	if (h == NULL)
		return false;
	CloseHandle(h);
	return true;
}

typedef BOOL (WINAPI *ZwSetInformationProcessPtr)(HANDLE hProcess, DWORD dwClass, DWORD* dwValue, DWORD valSize);
#define ProcessExecuteFlags				0x22

DWORD SetProcDep(HANDLE hProc, DWORD dwVal)
{
	ZwSetInformationProcessPtr ZwSetInformationProcess = (ZwSetInformationProcessPtr )GetProcAddress(
		GetModuleHandle(_T("ntdll.dll")), "ZwSetInformationProcess");
	return ZwSetInformationProcess(hProc, ProcessExecuteFlags, &dwVal, sizeof(dwVal));
}

//////////////////////////////////////////////////////////////////////////
