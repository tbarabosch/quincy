rule BLOWFISH_Constants: crypto {
   meta:
        author = "phoul (@phoul)"
        description = "Look for Blowfish constants"
        date = "2014-01"
        version = "0.1"
   strings:
        $c0 = { D1310BA6 }
        $c1 = { A60B31D1 }
        $c2 = { 98DFB5AC }
        $c3 = { ACB5DF98 }
        $c4 = { 2FFD72DB }
        $c5 = { DB72FD2F }
        $c6 = { D01ADFB7 }
        $c7 = { B7DF1AD0 }
        $c8 = { 4B7A70E9 }
        $c9 = { E9707A4B }
        $c10 = { F64C261C }
        $c11 = { 1C264CF6 }
    condition:
                6 of them
}

rule RSA_Pub_Key: crypto {
strings:
    $s1 = {31415352}
    $s2 = "RSA1"

condition:
    any of them
}

rule RC6_Constants : crypto {
        meta:
            author = "chort (@chort0)"
            description = "Look for RC6 magic constants in binary"
            reference = "https://twitter.com/mikko/status/417620511397400576"
            reference2 = "https://twitter.com/dyngnosis/status/418105168517804033"
            date = "2013-12"
            version = "0.2"
        strings:
            $c1 = { B7E15163 }
            $c2 = { 9E3779B9 }
            $c3 = { 6351E1B7 }
            $c4 = { B979379E }
        condition:
            2 of them
}

rule aes_Constants : crypto {
    strings:
        $c0 = { c66363a5 }
        $c1 = { f87c7c84 }
        $c2 = { ee777799 }
        $c3 = { f67b7b8d }
        $c4 = { fff2f20d }
        $c5 = { d66b6bbd }
        $c6 = { de6f6fb1 }
        $c7 = { 91c5c554 }
        $c8 = { 60303050 }
        $c9 = { 02010103 }
    condition:
        5 of them
}