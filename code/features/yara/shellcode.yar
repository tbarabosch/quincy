rule get_current_eip {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects x86 shellcode that determines its own position in memory."
    strings:
        $c0 = { E80100000058 }
        $c1 = { D9EE9BD97424F4 }
        $c2 = { E80000000058 }
        $c3 = { E8FFFFFFFFC359 }
        $c4 = { D9EB9BD97424F45B }
        $c5 = { E8000000005D }
        $c6 = { E80000000058 } // call +5; pop eax
        $c7 = { E8000000005B } // call +5; pop ebx
        $c8 = { E80000000059 } // call +5; pop ecx
        $c9 = { E8000000005a } // call +5; pop edx
        $c10 = { E8000000005e } // call +5; pop esi
        $c11 = { E8000000005f } // call +5; pop edi
        $c20 = { E800000000E9 } // call +5; jmp
	condition:
        any of them
}