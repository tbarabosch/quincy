import "pe"

rule Check_Qemu_Description
{
    meta:
        Author = "Nick Hoffman"
        Description = "Checks for QEMU systembiosversion key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"
    strings:
        $key = "HARDWARE\\Description\\System" nocase wide ascii
        $value = "SystemBiosVersion" nocase wide ascii
        $data = "QEMU" wide nocase ascii
    condition:
        all of them
}

rule WMI_VM_Detect : WMI_VM_Detect
{
    meta:
        version = 2
        threat = "Using WMI to detect virtual machines via querying video card information"
        behaviour_class = "Evasion"
        author = "Joe Giron"
        date = "2015-09-25"
        description = "Detection of Virtual Appliances through the use of WMI for use of evasion."
    strings:
        $selstr = "SELECT Description FROM Win32_VideoController" nocase ascii wide
        $selstr2 = "SELECT * FROM Win32_VideoController" nocase ascii wide
        $vm1 = "virtualbox graphics adapter" nocase ascii wide
        $vm2 = "vmware svga ii" nocase ascii wide
        $vm3 = "vm additions s3 trio32/64" nocase ascii wide
        $vm4 = "parallel" nocase ascii wide
        $vm5 = "remotefx" nocase ascii wide
        $vm6 = "cirrus logic" nocase ascii wide
        $vm7 = "matrox" nocase ascii wide
    condition:
        any of ($selstr*) and any of ($vm*)
}

rule Check_Qemu_DeviceMap
{
    meta:
        Author = "Nick Hoffman"
        Description = "Checks for Qemu reg keys"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"
    strings:
        $key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $value = "Identifier" nocase wide ascii
        $data = "QEMU" wide nocase ascii
    condition:
        all of them
}

rule Check_VBox_Description
{
    meta:
        Author = "Nick Hoffman"
        Description = "Checks Vbox description reg key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"
    strings:
        $key = "HARDWARE\\Description\\System" nocase wide ascii
        $value = "SystemBiosVersion" nocase wide ascii
        $data = "VBOX" nocase wide ascii
    condition:
        all of them
}
rule Check_VBox_DeviceMap
{
    meta:
        Author = "Nick Hoffman"
        Description = "Checks Vbox registry keys"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"
    strings:
        $key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $value = "Identifier" nocase wide ascii
        $data = "VBOX" nocase wide ascii
    condition:
        all of them
}
rule Check_VBox_VideoDrivers
{
    meta:
        Author = "Nick Hoffman"
        Description = "Checks for reg keys of Vbox video drivers"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"
    strings:
        $key = "HARDWARE\\Description\\System" nocase wide ascii
        $value = "VideoBiosVersion" wide nocase ascii
        $data = "VIRTUALBOX" nocase wide ascii
    condition:
        all of them
}
rule Check_VMWare_DeviceMap
{
    meta:
        Author = "Nick Hoffman"
        Description = "Checks for the existence of VmWare Registry Keys"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"
    strings:
        $key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" wide ascii nocase
        $value = "Identifier" wide nocase ascii
        $data = "VMware" wide nocase ascii
    condition:
        all of them
}
rule Check_VmTools
{
    meta:
        Author = "Nick Hoffman"
        Description = "Checks for the existence of VmTools reg key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"
    strings:
        $ ="SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii wide
    condition:
        any of them
}
rule Check_Wine
{
    meta:
        Author = "Nick Hoffman"
        Description = "Checks for the existence of Wine"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"
    strings:
        $ ="wine_get_unix_file_name"
    condition:
        any of them
}

rule vmdetect
{
    meta:
        author = "nex"
        description = "Possibly employs anti-virtualization techniques"

    strings:
        // Binary tricks
        $vmware = {56 4D 58 68}
        $virtualpc = {0F 3F 07 0B}
        $ssexy = {66 0F 70 ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F EF}
        $vmcheckdll = {45 C7 00 01}
        $redpill = {0F 01 0D 00 00 00 00 C3}

        // Random strings
        $vmware1 = "VMXh"
        $vmware2 = "Ven_VMware_" nocase
        $vmware3 = "Prod_VMware_Virtual_" nocase
        $vmware4 = "hgfs.sys" nocase
        $vmware5 = "mhgfs.sys" nocase
        $vmware6 = "prleth.sys" nocase
        $vmware7 = "prlfs.sys" nocase
        $vmware8 = "prlmouse.sys" nocase
        $vmware9 = "prlvideo.sys" nocase
        $vmware10 = "prl_pv32.sys" nocase
        $vmware11 = "vpc-s3.sys" nocase
        $vmware12 = "vmsrvc.sys" nocase
        $vmware13 = "vmx86.sys" nocase
        $vmware14 = "vmnet.sys" nocase
        $vmware15 = "vmicheartbeat" nocase
        $vmware16 = "vmicvss" nocase
        $vmware17 = "vmicshutdown" nocase
        $vmware18 = "vmicexchange" nocase
        $vmware19 = "vmdebug" nocase
        $vmware20 = "vmmouse" nocase
        $vmware21 = "vmtools" nocase
        $vmware22 = "VMMEMCTL" nocase
        $vmware23 = "vmx86" nocase
        $vmware24 = "vmware" nocase
        $virtualpc1 = "vpcbus" nocase
        $virtualpc2 = "vpc-s3" nocase
        $virtualpc3 = "vpcuhub" nocase
        $virtualpc4 = "msvmmouf" nocase
        $xen1 = "xenevtchn" nocase
        $xen2 = "xennet" nocase
        $xen3 = "xennet6" nocase
        $xen4 = "xensvc" nocase
        $xen5 = "xenvdb" nocase
        $xen6 = "XenVMM" nocase

        // MAC addresses
        $vmware_mac_1a = "00-05-69"
        $vmware_mac_1b = "00:05:69"
        $vmware_mac_1c = "000569"
        $vmware_mac_2a = "00-50-56"
        $vmware_mac_2b = "00:50:56"
        $vmware_mac_2c = "005056"
        $vmware_mac_3a = "00-0C-29" nocase
        $vmware_mac_3b = "00:0C:29" nocase
        $vmware_mac_3c = "000C29" nocase
        $vmware_mac_4a = "00-1C-14" nocase
        $vmware_mac_4b = "00:1C:14" nocase
        $vmware_mac_4c = "001C14" nocase

    condition:
        6 of them
}

rule vmdetect_misc : vmdetect
{
    meta:
        author = "@abhinavbom"
        maltype = "NA"
        version = "0.1"
        date = "31/10/2015"
        description = "Following Rule is referenced from AlienVault's Yara rule repository.This rule contains additional processes and driver names."
    strings:
        $wine1 = "wine_get_unix_file_name" ascii wide

        $vmware1 = "vmmouse.sys" ascii wide
        $vmware2 = "VMware Virtual IDE Hard Drive" ascii wide

        $miscvm1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase ascii wide
        $miscvm2 = "SYSTEM\\\\ControlSet001\\\\Services\\\\Disk\\\\Enum" nocase ascii wide

        // Drivers
        $vmdrv1 = "hgfs.sys" ascii wide
        $vmdrv2 = "vmhgfs.sys" ascii wide
        $vmdrv3 = "prleth.sys" ascii wide
        $vmdrv4 = "prlfs.sys" ascii wide
        $vmdrv5 = "prlmouse.sys" ascii wide
        $vmdrv6 = "prlvideo.sys" ascii wide
        $vmdrv7 = "prl_pv32.sys" ascii wide
        $vmdrv8 = "vpc-s3.sys" ascii wide
        $vmdrv9 = "vmsrvc.sys" ascii wide
        $vmdrv10 = "vmx86.sys" ascii wide
        $vmdrv11 = "vmnet.sys" ascii wide

        // SYSTEM\ControlSet001\Services
        $vmsrvc1 = "vmicheartbeat" ascii wide
        $vmsrvc2 = "vmicvss" ascii wide
        $vmsrvc3 = "vmicshutdown" ascii wide
        $vmsrvc4 = "vmicexchange" ascii wide
        $vmsrvc5 = "vmci" ascii wide
        $vmsrvc6 = "vmdebug" ascii wide
        $vmsrvc7 = "vmmouse" ascii wide
        $vmsrvc8 = "VMTools" ascii wide
        $vmsrvc9 = "VMMEMCTL" ascii wide
        $vmsrvc10 = "vmware" ascii wide
        $vmsrvc11 = "vmx86" ascii wide
        $vmsrvc12 = "vpcbus" ascii wide
        $vmsrvc13 = "vpc-s3" ascii wide
        $vmsrvc14 = "vpcuhub" ascii wide
        $vmsrvc15 = "msvmmouf" ascii wide
        $vmsrvc16 = "VBoxMouse" ascii wide
        $vmsrvc17 = "VBoxGuest" ascii wide
        $vmsrvc18 = "VBoxSF" ascii wide
        $vmsrvc19 = "xenevtchn" ascii wide
        $vmsrvc20 = "xennet" ascii wide
        $vmsrvc21 = "xennet6" ascii wide
        $vmsrvc22 = "xensvc" ascii wide
        $vmsrvc23 = "xenvdb" ascii wide

        // Processes
        $miscproc1 = "vmware2" ascii wide
        $miscproc2 = "vmount2" ascii wide
        $miscproc3 = "vmusrvc" ascii wide
        $miscproc4 = "vmsrvc" ascii wide
        $miscproc5 = "vboxservice" ascii wide
        $miscproc6 = "vboxtray" ascii wide
        $miscproc7 = "xenservice" ascii wide

        $vmware_mac_1a = "00-05-69"
        $vmware_mac_1b = "00:05:69"
        $vmware_mac_2a = "00-50-56"
        $vmware_mac_2b = "00:50:56"
        $vmware_mac_3a = "00-0C-29"
        $vmware_mac_3b = "00:0C:29"
        $vmware_mac_4a = "00-1C-14"
        $vmware_mac_4b = "00:1C:14"
        $virtualbox_mac_1a = "08-00-27"
        $virtualbox_mac_1b = "08:00:27"

    condition:
        6 of them
}