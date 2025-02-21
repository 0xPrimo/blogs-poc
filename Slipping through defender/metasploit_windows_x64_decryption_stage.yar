rule msfvenom_shellcode_decoding
{
    meta:
	    author = "0xPrimo"
        desc   = "Decryption stage of generated metasploit shellcode"

    strings:
        /*
            00000037  41                 inc     ecx
            00000038  c1c90d             ror     ecx, 0xd
            0000003b  41                 inc     ecx
            0000003c  01c1               add     ecx, eax
            0000003e  e2ed               loop    0x2d

        */
        $a   = { 48 ?? ?? ac 3c ?? }
        
        /*
            00000035  2c20               sub     al, 0x20
            00000037  41                 inc     ecx
            00000038  c1c90d             ror     ecx, 0xd
            0000003b  41                 inc     ecx
            0000003c  01c1               add     ecx, eax
            0000003e  e2ed               loop    0x2d

        */
        $b   = { 2c ?? 41 c1 c9 ?? 41 01 c1 e2 ed }

    condition:
        all of them
}
