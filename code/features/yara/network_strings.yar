rule vad_contains_network_strings {
    meta:
        author = "Thomas Barabosch"
        version = "0.1"
        description = "Detects memory areas that are most likely communicate via the network."
    strings:
        $n0 = "http"
        $n1 = "https"
        $n2 = "www"
        $n3 = "POST"
        $n4 = "GET"
        $n5 = "HTTP/1.1"
        $n6 = "Accept:"
        $n7 = "User-Agent:"
        $n8 = "Accept-Language:"
        $n9 = "Content-Length:"
        $n10 = "Connection:"
        $n11 = "text/html"
        $n12 = "text/plain"
        $n13 = "gzip"
        $n14 = "Content-Type"
        $n15 = "Transfer-Encoding"
        $n16 = "Cache-Control:"
        $n17 = "HTTP/1.0 200"
        $n18 = "Host:"
    condition:
        5 of them
}