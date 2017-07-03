rule dynamic_loading_of_APIs {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects dynamic API loading on Windows."
    strings:
        $a1 = "GetProcAddress"
        $a2 = "LoadLibraryA"
        $a3 = "LoadLibraryW"
        $a4 = "LdrLoadDll"
        $a5 = "LoadLibraryExW"
        $a6 = "LoadLibraryExA"

        $dll1 = "ntdll.dll" nocase
        $dll2 = "kernel32.dll" nocase
        $dll3 = "crypt32.dll" nocase
        $dll4 = "user32.dll" nocase
        $dll5 = "advapi32.dll" nocase
        $dll6 = "wininet.dll" nocase
        $dll7 = "shlwapi.dll" nocase
        $dll8 = "ws2_32.dll" nocase
        $dll9 = "urlmon.dll" nocase
        $dll10 = "nspr4.dll" nocase

    condition:
        2 of ($a*) and 8 of ($dll*)
}


