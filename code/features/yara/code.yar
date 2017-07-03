rule function_prolog {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects x86 function prologues"
    strings:
        $c0 = { 558BEC83C4 }
        $c1 = { 558BEC81EC }
        $c2 = { 558BECEB }
        $c3 = { 558BECE8 }
        $c4 = { 558BECE9 }
        $c5 = { 558BEC83EC }
        $c6 = { 558BEC56 }
        $c7 = { 5589E583EC }
        $c8 = { 5589E55657 }
        $c9 = { 81EC[4]5657}
        $c10 = { 55 89 E5 51 57 56 }
        $c11 = { C8 00 00 00 53 57 56 }
    condition:
        any of them
}