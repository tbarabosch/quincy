rule api_hashing {
    strings:
        $c0 = {AC84C07407C1CF0D01C7EBF481FF}
        $c1 = {AC84C07407C1CF0701C7EBF481FF}
    condition:
        any of them
}

// http://nagareshwar.securityxploded.com/2013/09/21/using-peb-to-get-base-address-of-kernelbase-dll/
//mov eax,  fs:[30h]            ; peb address
//mov eax, [eax+18h]        ; PEB->Ldr
//mov ebx, [eax+30h]       ; PEB-> InInitializationOrderModuleList.Flink
//mov ebx, [ebx]                 ; 1st module entry
//mov ebx, [ebx+20h]       ; kernelbase.dll
rule get_kernelbase {
    strings:
        $c0 = { 64A1300000008B40188B58308B1B8B5B20 }
    condition:
        $c0
}

// http://nagareshwar.securityxploded.com/2013/09/21/using-peb-to-get-base-address-of-kernelbase-dll/
//mov eax,  fs:[30h]            ; peb address
//mov eax, [eax+18h]        ; PEB->Ldr
//mov ebx, [eax+30h]       ; PEB-> InInitializationOrderModuleList.Flink
//mov ebx, [ebx]                 ; 1st module entry
rule get_ntdll {
    strings:
        $c0 = {64A1300000008B40188B58308B1B}
    condition:
        $c0
}

// mov eax,  fs:[0x30]
rule get_peb {
    strings:
        $c0 = {64A130000000}
    condition:
        $c0
}

//mov eax,  fs:[0x30]
//mov eax, [eax+0x2]
rule peb_being_debugged {
    strings:
        $c0 = {64A1300000008B4002}
    condition:
        $c0
}

//0x00090009 31c0             XOR EAX, EAX
//0x0009000b 648b4018         MOV EAX, [FS:EAX+0x18]
//0x0009000f 8b4030           MOV EAX, [EAX+0x30]
//0x00090012 8b400c           MOV EAX, [EAX+0xc]
rule peb_action {
    strings:
        $c0 = {31c0648b40188b40308b400c}
    condition:
        $c0
}