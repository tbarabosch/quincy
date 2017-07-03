import "pe"

rule Check_DriveSize
{
    meta:
        Author = "Nick Hoffman"
        Description = "Rule tries to catch uses of DeviceIOControl being used to get the drive size"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $physicaldrive = "\\\\.\\PhysicalDrive0" wide ascii nocase
        $dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15} //push 7405ch ; push esi (handle) then call deviceoiocontrol IOCTL_DISK_GET_LENGTH_INFO
    condition:
        pe.imports("kernel32.dll","CreateFileA") and
        pe.imports("kernel32.dll","DeviceIoControl") and
        $dwIoControlCode and
        $physicaldrive
}

rule Check_FilePaths
{
    meta:
        Author = "Nick Hoffman"
        Description = "Checks for filepaths containing popular sandbox names"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"
    strings:
        $path1 = "SANDBOX" wide ascii
        $path2 = "\\SAMPLE" wide ascii
        $path3 = "\\VIRUS" wide ascii
    condition:
        all of ($path*) and pe.imports("kernel32.dll","GetModuleFileNameA")
}

rule Check_UserNames
{
    meta:
        Author = "Nick Hoffman"
        Description = "Looks for malware checking for common sandbox usernames"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"
    strings:
        $user1 = "MALTEST" wide ascii
        $user2 = "TEQUILABOOMBOOM" wide ascii
        $user3 = "SANDBOX" wide ascii
        $user4 = "VIRUS" wide ascii
        $user5 = "MALWARE" wide ascii
    condition:
        all of ($user*)  and pe.imports("advapi32.dll","GetUserNameA")
}

rule antisb_joesanbox {
     meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Joe Sandbox"
        version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $c1 = "RegQueryValue"
        $s1 = "55274-640-2673064-23950"
    condition:
        all of them
}

rule antisb_anubis {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Anubis"
        version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $c1 = "RegQueryValue"
        $s1 = "76487-337-8429955-22614"
        $s2 = "76487-640-1457236-23837"
    condition:
        $p1 and $c1 and 1 of ($s*)
}

rule antisb_sandboxie {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Sandboxie"
        version = "0.1"
    strings:
        $f1 = "SbieDLL.dll" nocase
    condition:
        all of them
}

rule antisb_cwsandbox {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for CWSandbox"
        version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $s1 = "76487-644-3177037-23510"
    condition:
        all of them
}

rule antivm_vmware {
    meta:
        author = "x0r"
        description = "AntiVM checks for VMWare"
        version = "0.1"
    strings:
        $s1 = "vmware.exe" nocase
        $s2 = "vmware-authd.exe" nocase
        $s3 = "vmware-hostd.exe" nocase
        $s4 = "vmware-tray.exe" nocase
        $s5 = "vmware-vmx.exe" nocase
        $s6 = "vmnetdhcp.exe" nocase
        $s7 = "vpxclient.exe" nocase
        $s8 = { b868584d56bb00000000b90a000000ba58560000ed }
    condition:
        any of them
}

rule antivm_bios {
    meta:
        author = "x0r"
        description = "AntiVM checks for Bios version"
    version = "0.2"
    strings:
        $p1 = "HARDWARE\\DESCRIPTION\\System" nocase
        $p2 = "HARDWARE\\DESCRIPTION\\System\\BIOS" nocase
        $c1 = "RegQueryValue"
        $r1 = "SystemBiosVersion"
        $r2 = "VideoBiosVersion"
        $r3 = "SystemManufacturer"
    condition:
        1 of ($p*) and 1 of ($c*) and 1 of ($r*)
}
