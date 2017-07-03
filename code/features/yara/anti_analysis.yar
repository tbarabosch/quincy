import "pe"

rule Check_FindWindowA_iat {

    meta:
        Author = "http://twitter.com/j0sm1"
        Description = "it's checked if FindWindowA() is imported"
        Date = "20/04/2015"
        Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#OllyFindWindow"

    strings:
        $ollydbg = "OLLYDBG"
        $windbg = "WinDbgFrameClass"

    condition:
        pe.imports("user32.dll","FindWindowA") and ($ollydbg or $windbg)
}

rule DebuggerCheck__MemoryWorkingSet : AntiDebug DebuggerCheck {
    meta:
        author = "Fernando Mercês"
        date = "2015-06"
        description = "Anti-debug process memory working set size check"
        reference = "http://www.gironsec.com/blog/2015/06/anti-debugger-trick-quicky/"

    condition:
        pe.imports("kernel32.dll", "K32GetProcessMemoryInfo") and
        pe.imports("kernel32.dll", "GetCurrentProcess")
}

rule anti_dbgtools {
    meta:
        author = "x0r"
        description = "Checks for the presence of known debug tools"
	version = "0.1"
    strings:
        $f1 = "procexp.exe" nocase
        $f2 = "procmon.exe" nocase
        $f3 = "processmonitor.exe" nocase
        $f4 = "wireshark.exe" nocase
        $f5 = "fiddler.exe" nocase
        $f6 = "windbg.exe" nocase
        $f7 = "ollydbg.exe" nocase
        $f8 = "winhex.exe" nocase
        $f9 = "processhacker.exe" nocase
        $f10 = "hiew32.exe" nocase
        $c11 = "\\\\.\\NTICE"
        $c12 = "\\\\.\\SICE"
        $c13 = "\\\\.\\Syser"
        $c14 = "\\\\.\\SyserBoot"
        $c15 = "\\\\.\\SyserDbgMsg"
    condition:
        any of them
}

rule disable_antivirus {
    meta:
        author = "x0r"
        description = "Disable AntiVirus"
	version = "0.2"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" nocase
        $p2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase
        $p3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase
        $c1 = "RegSetValue"
        $r1 = "AntiVirusDisableNotify"
        $r2 = "DontReportInfectionInformation"
        $r3 = "DisableAntiSpyware"
        $r4 = "RunInvalidSignatures"
        $r5 = "AntiVirusOverride"
        $r6 = "CheckExeSignatures"
        $f1 = "blackd.exe" nocase
        $f2 = "blackice.exe" nocase
        $f3 = "lockdown.exe" nocase
        $f4 = "lockdown2000.exe" nocase
        $f5 = "taskkill.exe" nocase
        $f6 = "tskill.exe" nocase
        $f7 = "smc.exe" nocase
        $f8 = "sniffem.exe" nocase
        $f9 = "zapro.exe" nocase
        $f10 = "zlclient.exe" nocase
        $f11 = "zonealarm.exe" nocase
    condition:
        ($c1 and $p1 and 1 of ($f*)) or ($c1 and $p2) or 1 of ($r*) or $p3
}

rule disable_uax {
    meta:
        author = "x0r"
        description = "Disable User Access Control"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
        $r1 = "UACDisableNotify"
    condition:
        all of them
}

rule disable_firewall {
    meta:
        author = "x0r"
        description = "Disable Firewall"
	version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" nocase
        $c1 = "RegSetValue"
        $r1 = "FirewallPolicy"
        $r2 = "EnableFirewall"
        $r3 = "FirewallDisableNotify"
        $s1 = "netsh firewall add allowedprogram"
    condition:
        (1 of ($p*) and $c1 and 1 of ($r*)) or $s1
}

rule disable_registry {
    meta:
        author = "x0r"
        description = "Disable Registry editor"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $c1 = "RegSetValue"
        $r1 = "DisableRegistryTools"
        $r2 = "DisableRegedit"
    condition:
        1 of ($p*) and $c1 and 1 of ($r*)
}

rule disable_taskmanager {
    meta:
        author = "x0r"
        description = "Disable Task Manager"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $r1 = "DisableTaskMgr"
    condition:
        1 of ($p*) and 1 of ($r*)
}