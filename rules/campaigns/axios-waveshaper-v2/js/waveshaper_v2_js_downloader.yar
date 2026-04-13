rule waveshaper_v2_js_downloader
{
    meta:
        description = "WaveShaper v2 JavaScript downloader"
        author = "Mohamed Trigui"
        reference = ""
        date_created = "2026/04/12"
        date_modified = "2026/04/12"
        version = "1.0"
        category = "downloader"
        platform = "Any"
        family = "WAVESHAPER.V2"
        confidence = "high"

    strings:
        $ss1 = "OrDeR_7077" ascii wide fullword
        $ss2 = "String.fromCharCode(S^a^333)" ascii wide
        $ss3 = "\"TE9DQUw^\".replaceAll(\"^\",\"=\")" ascii wide
        $ss4 = "\"UFM_\".replaceAll(\"_\",\"=\")" ascii wide
        $ss5 = "\"U0NSXw--\".replaceAll(\"-\",\"=\")" ascii wide
        $ss6 = "\"UFNfQg--\".replaceAll(\"-\",\"=\")" ascii wide
        $ss7 = "\"d2hlcmUgcG93ZXJzaGVsbA((\".replaceAll(\"(\",\"=\")" ascii wide
    condition:
        uint16(0) != 0x5A4D and filesize < 100KB and all of them
}