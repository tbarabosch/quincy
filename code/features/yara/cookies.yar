rule cookies {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects cookie stealing related activies."
    strings:
        $s0 = "moz_cookies"
        $s1 = "cookies.sqlite"
        $s2 = "\\Mozilla\\Firefox\\Profiles"
        $s3 = "*.sol"
        $s4 = "Macromedia\\Flash Player\\"
        $s5 = "\\Cookies\\index.dat"
    condition:
       2 of them
}