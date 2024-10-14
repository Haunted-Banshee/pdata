#include <Structs.h>

PVOID   GetRIP( VOID );
PVOID   Start();
PVOID   End();
PVOID   KaynCaller();
PVOID   Fixup();
VOID    KaynLdrReloc( PVOID KaynImage, PVOID ImageBase, PVOID Dir );
PVOID   CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length);
PVOID   LdrModulePeb ( PVOID hModuleHash );
PVOID   LdrFunctionAddr( UINT_PTR Module, UINT_PTR FunctionHash );
PVOID   HashString( PVOID String, UINT_PTR Length);
SIZE_T  KStringLengthA( LPCSTR String );
SIZE_T  KStringLengthW(LPCWSTR String);
SIZE_T  KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );
PVOID   WINAPI RtlSecureZeroMemory(PVOID ptr, SIZE_T cnt);
SEC( text, B ) INT StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2);