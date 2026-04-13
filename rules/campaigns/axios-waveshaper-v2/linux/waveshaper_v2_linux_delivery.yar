rule waveshaper_v2_linux_delivery
{
    meta:
        description = "WaveShaper v2 Linux delivery"
        author = "Mohamed Trigui"
        reference = ""
        date_created = "2026/04/12"
        date_modified = "2026/04/12"
        version = "1.0"
        category = "delivery"
        platform = "Linux"
        family = "WAVESHAPER.V2"
        confidence = "high"

    strings:
        $s1 = "/bin/sh -c" ascii wide
        $s2 = "curl -o /tmp/ld.py" ascii wide
        $s3 = "-d packages.npm.org/product2" ascii wide
        $s4 = "nohup python3 /tmp/ld.py" ascii wide
        $s5 = "> /dev/null 2>&1 &" ascii wide
        $s6 = "sfrclak.com:8000/6202033" ascii wide

    condition:
        filesize < 20KB and
        4 of them
}
