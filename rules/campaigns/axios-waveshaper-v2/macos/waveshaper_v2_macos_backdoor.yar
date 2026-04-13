rule waveshaper_v2_macos_backdoor
{
    meta:
        description = "WaveShaper v2 macOS backdoor"
        author = "Mohamed Trigui"
        reference = ""
        date_created = "2026/04/12"
        date_modified = "2026/04/12"
        version = "1.0"
        category = "backdoor"
        platform = "macOS"
        family = "WAVESHAPER.V2"
        confidence = "high"

    strings:
        $ua   = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)" ascii

        $msg1 = "FirstInfo" ascii
        $msg2 = "BaseInfo" ascii
        $msg3 = "CmdResult" ascii

        $ind1 = "rsp_kill" ascii
        $ind2 = "rsp_peinject" ascii
        $ind3 = "rsp_runscript" ascii
        $ind4 = "rsp_rundir" ascii

        $ind5 = "kern.osproductversion" ascii
        $ind6 = "kern.boottime" ascii
        $ind7 = "hw.model" ascii
        $ind8 = "/usr/bin/osascript" ascii

    condition:
        (
            uint32(0) == 0xfeedfacf or
            uint32(0) == 0xfeedface or
            uint32be(0) == 0xcafebabe
        ) and
        filesize < 5MB and
        $ua and
        2 of ($msg*) and
        4 of ($ind*)
}