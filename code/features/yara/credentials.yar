rule keylogger {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects key logging"
    strings:
        $s1 = "keylog" nocase
    condition:
        $s1
}

rule passwords {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects password stealing."
    strings:
        $s1 = "password" nocase
        $s2 = "login" nocase
        $s3 = "facebook" nocase
        $s4 = "yandex" nocase
        $s5 = "mail.ru" nocase
        $s9 = "yahoo" nocase
        $s10 = "aol" nocase
        $s11 = "paypal" nocase
        $s12 = "amazon" nocase
        $s13 = "AddressBook"
    condition:
        3 of them
}