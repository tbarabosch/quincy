rule banks {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects banking vocabulary and bank names to find banking Trojans and web injects."
    strings:
        $s2 = "bank" nocase
        $s3 = "finance"
        $s4 = "bankofamerica*"
        $s5 = "citibank"
        $s6 = "ingdirect"
        $s7 = "hsbc"
        $s8 = "portal"
        $s10 = "bnpparibas"
        $s11 = "balance"
        $s12 = "ibank2"
        $s13 = "debit"
        $s14 = "account" nocase
        $s15 = "amount" nocase
    condition:
            2 of them
}