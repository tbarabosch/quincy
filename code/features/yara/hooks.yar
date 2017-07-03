rule banking_hooks {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects function names that are commonly hooked by banking Trojans."
    strings:
        $s1 = "PR_GetError"
        $s2 = "PR_GetOSError"
        $s3 = "PR_SetError"
        $s4 = "NSPR4.DLL"
        $s5 = "nss3.dll"
        $s6 = "PR_Read"
        $s7 = "PR_Write"
        $s8 = "PR_Close"
        $s9 = "PR_GetNameForIdentity"
    condition:
       2 of them
}