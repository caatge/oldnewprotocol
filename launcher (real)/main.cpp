#include "windows.h"
#include "netmsg.h"
#include "MinHook.h"
//#include "icvar.h" // included by shared, apparently
#include "shared.h"
#include "silver-bun.h"
#include "dbg.h"

ICvar* g_pCVar = 0;

bool natively32 = false;
bool looks_old = false;
bool loginlined = false;

typedef void(__thiscall* RegisterMessage_t)(void* this_, INetMessage* msg);

int(__thiscall* oConnectionStart)(void* this_, INetChannel* ch);

int __fastcall ConnectionStart(void* ecx, void* edx, INetChannel* nc) {
    int eaxstate = oConnectionStart(ecx, nc);
    SVC_GetCvarValue* lol = new SVC_GetCvarValue();
    void** vtbl = *(void***)nc;

    const int idx = looks_old ? 23 : 24;

    RegisterMessage_t RegisterMessage = (RegisterMessage_t)vtbl[idx];
    RegisterMessage(nc, lol);
    return eaxstate;
}

int(__thiscall* oConnectionStart_BaseClient)(void* this_, INetChannel* ch);

int __fastcall ConnectionStart_BaseClient(void* ecx, void* edx, INetChannel* nc) {
    int eaxstate = oConnectionStart_BaseClient(ecx, nc);
    void** vtbl = *(void***)nc;
    const int idx = looks_old ? 23 : 24;
    RegisterMessage_t RegisterMessage = (RegisterMessage_t)vtbl[idx];
    CLC_RespondCvarValue* lol = new CLC_RespondCvarValue();
    RegisterMessage(nc, lol);
    CLC_FileCRCCheck* lol2 = new CLC_FileCRCCheck();
    RegisterMessage(nc, lol2);
    return eaxstate;
}

std::vector <uint8_t> sendtable_patch32 = { 0x6A, 0x20 };
std::vector <uint8_t> sendtable_patch16 = { 0x6A, 0x10 };

CMemory maxtables_r, maxtables_w;

BOOL (__thiscall* oSVC_ServerInfo_WriteToBuffer)(void* this_, bf_write* write);

BOOL __fastcall SVC_ServerInfo_WriteToBuffer(void* this_, void* edx, bf_write* write) {
    // incase of hosting we want to force it to 16, newer source versions have a check against that and fall back to 16
    maxtables_w.Patch(sendtable_patch16);
    char* os_ = (char*)this_ + 26;
    *os_ = 'q'; // trip new source clients to use 16 maxtables
    return oSVC_ServerInfo_WriteToBuffer(this_, write);
}

BOOL(__thiscall* oSVC_ServerInfo_ReadFromBuffer)(void* this_, bf_read* read);

BOOL __fastcall SVC_ServerInfo_ReadFromBuffer(void* this_, void* edx, bf_read* read) {
    int eaxstate = oSVC_ServerInfo_ReadFromBuffer(this_, read);
    char* os = (char*)this_ + 26;

    if (*os == 'w' || *os == 'l') {
        Msg("send32\n");
        maxtables_r.Patch(sendtable_patch32);
        maxtables_w.Patch(sendtable_patch32);
    }
    else {
        Msg("send16\n");
        maxtables_r.Patch(sendtable_patch16);
        maxtables_w.Patch(sendtable_patch16);
    }

    return eaxstate;
}

#ifdef EXTERNALCONSOLE
int __cdecl spewinternalmaybe(int spewtype, char* Format, va_list ArgList);

decltype(spewinternalmaybe)* original;

int __cdecl spewinternalmaybe(int spewtype, char* Format, va_list ArgList) {
    char msg[2048]{};
    vsprintf_s(msg, Format, ArgList);
    printf("%s", msg);
    return original(spewtype, Format, ArgList);
}
#endif

DWORD __stdcall EngineThread(LPVOID doifuckingknow) {
    HMODULE engine_ = GetModuleHandle("engine.dll");
    while (!engine_) {
        engine_ = GetModuleHandle("engine.dll");
        Sleep(100);
    }
#ifdef EXTERNALCONSOLE

    CModule tier0("tier0.dll");
    auto a = tier0.FindPatternSIMD("B8 ? ? ? ? E8 ? ? ? ? 56");
    MH_CreateHook(a, &spewinternalmaybe, (LPVOID*)&original);
    MH_EnableHook(a);
#endif
    CModule engine("engine.dll");

    CMemory vSVC_UpdateStringTable = engine.GetVirtualMethodTable(".?AVSVC_UpdateStringTable@@");
    
    CMemory SVC_UpdateStringTable_ReadFromBuffer = vSVC_UpdateStringTable.WalkVTable(4).Deref();
    CMemory SVC_UpdateStringTable_WriteToBuffer = vSVC_UpdateStringTable.WalkVTable(5).Deref();

    CModule::ModuleSections_t moduleSection_r(".text", SVC_UpdateStringTable_ReadFromBuffer.GetPtr(), 160); // from function base to 100 bytes ahead
    CModule::ModuleSections_t moduleSection_w(".text", SVC_UpdateStringTable_WriteToBuffer.GetPtr(), 160); // from function base to 100 bytes ahead

    CModule::ModuleSections_t _moduleSection_r(".text", SVC_UpdateStringTable_ReadFromBuffer.GetPtr(), 50); // from function base to 50 bytes ahead
    CModule::ModuleSections_t _moduleSection_w(".text", SVC_UpdateStringTable_WriteToBuffer.GetPtr(), 50); // from function base to 50 bytes ahead
    maxtables_r = engine.FindPatternSIMD("B9 08 00 00 00 BB 01 00 00 00 03 C3 D1 F9", &_moduleSection_r);
    maxtables_w = engine.FindPatternSIMD("B9 08 00 00 00 BB 01 00 00 00 03 C3 D1 F9", &_moduleSection_w);
    if (maxtables_r && maxtables_w) {
        loginlined = true;
        sendtable_patch32 = { 0xB9, 0x10, 0x0, 0x0 };
        sendtable_patch16 = { 0xB9, 0x8, 0x0, 0x0 };
        Msg("==== log2 inlined?\n");
    }
    else {
        maxtables_r = engine.FindPatternSIMD("6A 20", &moduleSection_r); // push 20h
        maxtables_w = engine.FindPatternSIMD("6A 20", &moduleSection_w); // push 20h

        if ((maxtables_r && maxtables_w)) {
            natively32 = true;
        }
        else {
            maxtables_r = engine.FindPatternSIMD("6A 10", &moduleSection_r); // push 10h
            maxtables_w = engine.FindPatternSIMD("6A 10", &moduleSection_w); // push 10h
            natively32 = false;
        }


        if (!maxtables_r || !maxtables_w) {
            MessageBox(NULL, "couldn't find stringtable instructions to patch!\n", "", 0);
            ExitProcess(-1);
        }
    }

    CMemory CBaseClientState_ConnectionStart = engine.FindPatternSIMD("6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 51 53 56 57 6A ? 8B F9 E8 ? ? ? ? 83 C4 ? 89 44 24 ? C7 44 24");
    if (!CBaseClientState_ConnectionStart) CBaseClientState_ConnectionStart = engine.FindPatternSIMD("53 55 56 6A ? 8B E9");
    if (!CBaseClientState_ConnectionStart) CBaseClientState_ConnectionStart = engine.FindPatternSIMD("53 56 57 6A ? 8B F9 E8 ? ? ? ? 33 DB");

    CMemory CBaseClient_ConnectionStart = engine.FindPatternSIMD("6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 51 53 56 6A ? 8B D9");
    if (!CBaseClient_ConnectionStart) {
        CBaseClient_ConnectionStart = engine.FindPatternSIMD("51 53 55 56 57 8B F9 6A"); // 51 53 56 57 8B F9 6A
        looks_old = true;
    }

    if (!CBaseClient_ConnectionStart) {
        CBaseClient_ConnectionStart = engine.FindPatternSIMD("51 53 56 57 8B F9 6A");
        looks_old = true;
    }

    CMemory vSVC_ServerInfo = engine.GetVirtualMethodTable(".?AVSVC_ServerInfo@@");

    CMemory _SVC_ServerInfo_ReadFromBuffer = vSVC_ServerInfo.WalkVTable(4).Deref();
    CMemory _SVC_ServerInfo_WriteToBuffer = vSVC_ServerInfo.WalkVTable(5).Deref();

    Msg("=========== offsets ===========\n");
    Msg("= topatch1: %p \n", maxtables_r.GetPtr());
    Msg("= topatch2: %p \n", maxtables_w.GetPtr());
    Msg("= natively: %s \n", natively32 ? "32" : "16");
    Msg("= CBaseClientState::ConnectionStart: %p \n", CBaseClientState_ConnectionStart.GetPtr());
    Msg("= CBaseClient::ConnectionStart: %p \n", CBaseClient_ConnectionStart.GetPtr());
    Msg("= SVC_ServerInfo::WriteToBuffer: %p \n", _SVC_ServerInfo_WriteToBuffer.GetPtr());
    Msg("= SVC_ServerInfo::ReadFromBuffer: %p \n", _SVC_ServerInfo_ReadFromBuffer.GetPtr());

    if (!natively32) {
        if (!(CBaseClientState_ConnectionStart && CBaseClient_ConnectionStart && _SVC_ServerInfo_ReadFromBuffer)) {
            MessageBox(NULL, "couldn't find one or more functions", "", 0);
            ExitProcess(-1);
        }

        MH_CreateHook((LPVOID)CBaseClientState_ConnectionStart.GetPtr(), &ConnectionStart, (LPVOID*)&oConnectionStart);
        MH_EnableHook((LPVOID)CBaseClientState_ConnectionStart.GetPtr());

        MH_CreateHook((LPVOID)CBaseClient_ConnectionStart.GetPtr(), &ConnectionStart_BaseClient, (LPVOID*)&oConnectionStart_BaseClient);
        MH_EnableHook((LPVOID)CBaseClient_ConnectionStart.GetPtr());

        MH_CreateHook((LPVOID)_SVC_ServerInfo_ReadFromBuffer.GetPtr(), &SVC_ServerInfo_ReadFromBuffer, (LPVOID*)&oSVC_ServerInfo_ReadFromBuffer);
        MH_EnableHook((LPVOID)_SVC_ServerInfo_ReadFromBuffer.GetPtr());
    }

    if (!(_SVC_ServerInfo_WriteToBuffer)) {
        MessageBox(NULL, "couldn't find SVC_ServerInfo::WriteToBuffer", "", 0);
        ExitProcess(-1);
    }

    if (looks_old) {
        //ProcessSounds
        CMemory process_sounds = engine.FindPatternSIMD("81 EC ? ? ? ? 53 33 DB 55 56");
        if (!process_sounds) {
            process_sounds = engine.FindPatternSIMD("81 EC ? ? ? ? 53 8B D9 55 8D 44 24");
        }
        process_sounds.Patch({ 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00 });
    }

    MH_CreateHook((LPVOID)_SVC_ServerInfo_WriteToBuffer.GetPtr(), &SVC_ServerInfo_WriteToBuffer, (LPVOID*)&oSVC_ServerInfo_WriteToBuffer);
    MH_EnableHook((LPVOID)_SVC_ServerInfo_WriteToBuffer.GetPtr());

    HMODULE vstdlib = GetModuleHandle("vstdlib.dll");
    if (!vstdlib) {
        MessageBox(NULL, "couldn't get vstdlib", "", 0);
        ExitProcess(-1);
    }

    g_pCVar = (ICvar*)((CreateInterfaceFn)GetProcAddress(vstdlib, "CreateInterface"))(VENGINE_CVAR_INTERFACE_VERSION, NULL);

    return 1;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
    DisableThreadLibraryCalls(hinstDLL);
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DWORD th;
        MH_Initialize();
#ifdef EXTERNALCONSOLE
        AllocConsole();
        SetConsoleTitleW(L"half life 3");
        FILE* fDummy;
        freopen_s(&fDummy, "CONIN$", "r", stdin);
        freopen_s(&fDummy, "CONOUT$", "w", stderr);
        freopen_s(&fDummy, "CONOUT$", "w", stdout);
#endif
        CreateThread(0, 0, &EngineThread, 0, 0, &th);
    }
    if (fdwReason == DLL_PROCESS_DETACH) {
        MH_Uninitialize();
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}