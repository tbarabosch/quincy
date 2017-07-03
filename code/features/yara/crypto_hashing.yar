rule MD5_Constants : crypto {
    meta:
        author = "phoul (@phoul)"
        description = "Look for MD5 constants"
        date = "2014-01"
        version = "0.2"
    strings:
        // Init constants
        $c0 = { 67452301 }
        $c1 = { efcdab89 }
        $c2 = { 98badcfe }
        $c3 = { 10325476 }
        $c4 = { 01234567 }
        $c5 = { 89ABCDEF }
        $c6 = { FEDCBA98 }
        $c7 = { 76543210 }
        // Round 2
        $c8 = { F4D50d87 }
        $c9 = { 78A46AD7 }
    condition:
            5 of them
}

rule RIPEMD160_Constants : crypto {
    meta:
        author = "phoul (@phoul)"
        description = "Look for RIPEMD-160 constants"
        date = "2014-01"
        version = "0.1"
    strings:
        $c0 = { 67452301 }
        $c1 = { EFCDAB89 }
        $c2 = { 98BADCFE }
        $c3 = { 10325476 }
        $c4 = { C3D2E1F0 }
        $c5 = { 01234567 }
        $c6 = { 89ABCDEF }
        $c7 = { FEDCBA98 }
        $c8 = { 76543210 }
        $c9 = { F0E1D2C3 }
    condition:
        5 of them
}

rule SHA1_Constants : crypto {
    meta:
        author = "phoul (@phoul)"
        description = "Look for SHA1 constants"
        date = "2014-01"
        version = "0.1"
    strings:
        $c0 = { 67452301 }
        $c1 = { EFCDAB89 }
        $c2 = { 98BADCFE }
        $c3 = { 10325476 }
        $c4 = { C3D2E1F0 }
        $c5 = { 01234567 }
        $c6 = { 89ABCDEF }
        $c7 = { FEDCBA98 }
        $c8 = { 76543210 }
        $c9 = { F0E1D2C3 }
    condition:
        5 of them
}

rule SHA256_Constants : crypto {
    strings:
        $c0 = { 428a2f98 }
        $c1 = { 71374491 }
        $c2 = { b5c0fbcf }
        $c3 = { e9b5dba5 }
        $c4 = { 3956c25b }
        $c5 = { 59f111f1 }
        $c6 = { 923f82a4 }
        $c7 = { ab1c5ed5 }
        $c8 = { d807aa98 }
        $c9 = { 12835b01 }
    condition:
        5 of them
}

rule crc32_Constants : crypto {
    strings:
        $c0 = { 706af48f }
        $c1 = { e963a535 }
        $c2 = { 9e6495a3 }
        $c3 = { 0edb8832 }
        $c4 = { 79dcb8a4 }
        $c5 = { e0d5e91e }
        $c6 = { 97d2d988 }
        $c7 = { 09b64c2b }
        $c8 = { 7eb17cbd }
        $c9 = { e7b82d07 }
    condition:
        5 of them
}

rule SHA512_Constants : crypto {
    meta:
        author = "phoul (@phoul)"
        description = "Look for SHA384/SHA512 constants"
        date = "2014-01"
        version = "0.1"
    strings:
        $c0 = { 428a2f98 }
        $c1 = { 982F8A42 }
        $c2 = { 71374491 }
        $c3 = { 91443771 }
        $c4 = { B5C0FBCF }
        $c5 = { CFFBC0B5 }
        $c6 = { E9B5DBA5 }
        $c7 = { A5DBB5E9 }
        $c8 = { D728AE22 }
        $c9 = { 22AE28D7 }
    condition:
        5 of them
}

rule WHIRLPOOL_Constants : crypto {
    meta:
        author = "phoul (@phoul)"
        description = "Look for WhirlPool constants"
        date = "2014-02"
        version = "0.1"
    strings:
        $c0 = { 18186018c07830d8 }
        $c1 = { d83078c018601818 }
        $c2 = { 23238c2305af4626 }
        $c3 = { 2646af05238c2323 }
    condition:
        2 of them
}