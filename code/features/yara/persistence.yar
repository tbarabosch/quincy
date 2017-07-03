rule autorun {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects common persistence points on Windows."
    strings:
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" nocase
        $s3 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    condition:
        any of them
}


