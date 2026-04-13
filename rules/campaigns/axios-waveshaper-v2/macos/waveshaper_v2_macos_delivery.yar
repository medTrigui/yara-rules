rule waveshaper_v2_macos_delivery
{
    meta:
        description = "WaveShaper v2 macOS delivery"
        author = "Mohamed Trigui"
        reference = ""
        date_created = "2026/04/12"
        date_modified = "2026/04/12"
        version = "1.0"
        category = "delivery"
        platform = "macOS"
        family = "WAVESHAPER.V2"
        confidence = "high"

    strings:
        $s1 = "do shell script" ascii wide
        $s2 = "curl -o /Library/Caches/com.apple.act.mond" ascii wide
        $s3 = "-d packages.npm.org/product0" ascii wide
        $s4 = "chmod 770 /Library/Caches/com.apple.act.mond" ascii wide
        $s5 = "/bin/zsh -c \"/Library/Caches/com.apple.act.mond" ascii wide
        $s6 = "&> /dev/null" ascii wide

    condition:
        filesize < 20KB and
        5 of them
}
