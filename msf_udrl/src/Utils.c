#include <Macros.h>
#include <winternl.h>
#include <Funcs.h>
#include <winnt.h>

SEC( text, B ) PVOID HashString( PVOID String, UINT_PTR Length)
{
	ULONG 	Hash 	= 5381;
	PUCHAR 	Ptr 	= String;
	
	do
	{
		UCHAR character = *Ptr;

		if ( ! Length )
		{
			if ( !*Ptr ) break;
		}
		else
		{
			if ( (ULONG) (Ptr - (PUCHAR)String ) >= Length ) break;
			if ( !*Ptr ) ++Ptr;
		}

		if ( character >= 'a' )
		{
			character -= 0x20;
		}

		Hash = ( (Hash<<5) + Hash ) + character;
		++Ptr;
	} while ( TRUE );

	return Hash;
}

SEC( text, B ) PVOID LdrModulePeb ( PVOID hModuleHash )
{
	PLDR_DATA_TABLE_ENTRY pModule      = ( PLDR_DATA_TABLE_ENTRY ) ( ( PPEB ) PPEB_PTR )->Ldr->InMemoryOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY pFirstModule = pModule;
	do
	{
        if ( pModule->FullDllName.Buffer && pModule->FullDllName.Length )
        {
            DWORD ModuleHash  = HashString( pModule->FullDllName.Buffer, pModule->FullDllName.Length );
            DWORD ModuleHash2 = HashString( pModule->FullDllName.Buffer, pModule->FullDllName.Length - 8); // no ".dll"

            if ( ModuleHash == hModuleHash || ModuleHash2 == hModuleHash )
            {
                return ( UINT_PTR ) pModule->Reserved2[ 0 ];
            }
        }
        pModule = ( PLDR_DATA_TABLE_ENTRY ) pModule->Reserved1[ 0 ];
	} while ( pModule && pModule != pFirstModule );

	return 0;
}

SEC( text, B ) PVOID LdrFunctionAddr( UINT_PTR Module, UINT_PTR FunctionHash )
{
	PIMAGE_NT_HEADERS       ModuleNtHeader          = NULL;
	PIMAGE_EXPORT_DIRECTORY ModuleExportedDirectory = NULL;
	PDWORD                	AddressOfFunctions      = NULL;
	PDWORD                  AddressOfNames          = NULL;
	PWORD                   AddressOfNameOrdinals   = NULL;
    DWORD                   ExportDirVirtualAddress = NULL;
    DWORD                   ExportDirSize           = NULL;

	ModuleNtHeader          = (PVOID) ( Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
    ExportDirVirtualAddress = ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    ExportDirSize           = ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
	ModuleExportedDirectory = (PVOID) ( Module + ExportDirVirtualAddress );

	AddressOfNames          = (PVOID) ( Module + ModuleExportedDirectory->AddressOfNames );
	AddressOfFunctions      = (PVOID) ( Module + ModuleExportedDirectory->AddressOfFunctions );
	AddressOfNameOrdinals   = (PVOID) ( Module + ModuleExportedDirectory->AddressOfNameOrdinals );

	for (DWORD i = 0; i < ModuleExportedDirectory->NumberOfNames; i++)
	{
        PVOID FuncName = (PVOID) ( Module + AddressOfNames[ i ] );
        PVOID FuncAddr = (PVOID) ( Module + AddressOfFunctions[ AddressOfNameOrdinals [ i ] ] );
        
        if ( HashString( FuncName, 0 ) == FunctionHash )
        {
            // This handles forwarders
            if ( FuncAddr > Module + ModuleNtHeader->OptionalHeader.DataDirectory[ 0 ].VirtualAddress && 
                 FuncAddr < Module + ModuleNtHeader->OptionalHeader.DataDirectory[ 0 ].VirtualAddress + ModuleNtHeader->OptionalHeader.DataDirectory[ 0 ].Size
               ) // Forwarders are outside .text
            {
                CHAR ModuleName[ MAX_PATH ] = { 0 };
                DWORD Offset                = 0;
                LPCSTR ExportModule         = NULL;
                SIZE_T ModuleAndExportLen   = 0;
                PVOID ModuleAddr            = NULL;
                DWORD64 ModuleHash          = 0;
                LPCSTR ExportName           = NULL;

                ExportModule         = FuncAddr;
                ModuleAndExportLen   = KStringLengthA( FuncAddr );

                for ( ; Offset < ModuleAndExportLen ; Offset++ )
                {
                    if ( HashString( ExportModule + Offset, 1 ) == 0x2b5d3) // Hashed "."
                        break;
                }

                RtlSecureZeroMemory( ModuleName, Offset * 2 );
                KCharStringToWCharString( ModuleName, ExportModule, Offset );

                ModuleAddr     = LdrModulePeb( HashString( ModuleName, Offset * 2 ) );

                if ( !ModuleAddr ) // Module not in PEB, spoof the load
                {
                    API Api = { 0 };
                    Api.LoadLibraryA = LdrFunctionAddr( LdrModulePeb( K32_HASH ), H_LOADLIBRARYA );
                    ModuleAddr = Api.LoadLibraryA( ExportModule );
                }

                ModuleHash   = HashString( ExportModule + Offset + 1, 0 );
                ExportName   = ExportModule + Offset + 1;

                return LdrFunctionAddr( ModuleAddr, HashString( ExportName, 0 ) );
            }

            return FuncAddr;
        }
	}
}

SEC( text, B ) VOID KaynLdrReloc( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir )
{
    PIMAGE_BASE_RELOCATION  pImageBR = BaseRelocDir;
    PVOID                   OffsetIB = KaynImage - ImageBase ;
    PIMAGE_RELOC            Reloc    = NULL;

    while( pImageBR->VirtualAddress != 0 )
    {
        Reloc = ( PIMAGE_RELOC ) ( pImageBR + 1 );

        while ( ( PBYTE ) Reloc != ( PBYTE ) pImageBR + pImageBR->SizeOfBlock )
        {
            if ( Reloc->type == IMAGE_REL_TYPE )
                *( ULONG_PTR* ) ( ( UINT_PTR ) ( KaynImage ) + pImageBR->VirtualAddress + Reloc->offset ) += ( ULONG_PTR ) OffsetIB;

            else if ( Reloc->type != IMAGE_REL_BASED_ABSOLUTE )
                __debugbreak(); // TODO: handle this error

            Reloc++;
        }

        pImageBR = ( PIMAGE_BASE_RELOCATION ) Reloc;
    }
}

SEC( text, B ) SIZE_T KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

SEC( text, B ) SIZE_T KStringLengthA( LPCSTR String )
{
    LPCSTR String2 = String;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

SEC( text, B ) SIZE_T KStringLengthW( LPCWSTR String )
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}
// Vx Underground
SEC( text, B ) PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

SEC( text, B ) PVOID WINAPI RtlSecureZeroMemory(PVOID ptr,SIZE_T cnt)
{
  volatile PCHAR vptr = (volatile PCHAR)ptr;
  while (cnt != 0)
    {
      *vptr++ = 0;
      cnt--;
    }
  return ptr;
}

// Vx Underground
SEC( text, B ) INT StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}