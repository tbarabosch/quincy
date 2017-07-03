rule base64_alphabet: crypto {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects base64 algorithms"
    strings:
        $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        $s2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    condition:
        any of them
}