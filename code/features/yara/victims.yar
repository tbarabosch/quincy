rule code_injection_victims {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects common HBCIA victim processes."
    strings:
        $v0 = "Shell_TrayWnd" nocase
        $v1 = "explorer" nocase
        $v2 = "chrome" nocase
        $v3 = "svchost" nocase
        $v4 = "firefox" nocase
        $v5 = "opera" nocase
        $v6 = "PR_Write"
        $v7 = "rundll" nocase
        $v8 = "safari" nocase
        $v9 = "netscape" nocase
        $v10 = "Chrome_WidgetWin_0"
        $v11 = "OperaWindowClass"
        $v12 = "MozillaWindowClass"
        $v13 = "IEFrame"
        $v14 = "mozilla" nocase
        $v15 = "nspr4" nocase
        $v16 = "lsass" nocase
    condition:
        4 of them
}
