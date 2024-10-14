#include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#define true 1
#define MAX_STACK_SIZE 12000
#define RBP_OP_INFO 0x5
#define NtCurrentProcess()  ( HANDLE ) ( ( HANDLE ) - 1 )

#define GET_SYMBOL( x )     ( ULONG_PTR )( GetRIP( ) - ( ( ULONG_PTR ) & GetRIP - ( ULONG_PTR ) x ) )
#define SEC( s, x )         __attribute__( ( section( "." #s "$" #x "" ) ) )
#define PPEB_PTR __readgsqword( 0x60 )

#define NTDLL_HASH                      0x70e61753
#define K32_HASH                        0xadd31df0

#define H_LOADLIBRARYA                  0xb7072fdb
#define H_LOADLIBRARYEXA                0x9592af38
#define H_GETPROCADDRESS                0xdecfc1bf
#define H_VIRTUALPROTECT                0xe857500d
#define H_VIRTUALALLOC                  0x97bc257

#define W32( x )     __typeof__( x ) * x
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64

