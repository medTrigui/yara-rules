rule waveshaper_v2_windows_backdoor
{
    meta:
        description = "WaveShaper v2 Windows backdoor"
        author = "Mohamed Trigui"
        reference = ""
        date_created = "2026/04/12"
        date_modified = "2026/04/12"
        version = "1.0"
        category = "backdoor"
        platform = "Windows"
        family = "WAVESHAPER.V2"
        confidence = "high"

     strings:
        $ss1 = "packages.npm.org/product1" ascii wide nocase
        $ss2 = "Extension.SubRoutine" ascii wide nocase
        $ss3 = "rsp_peinject" ascii wide nocase
        $ss4 = "rsp_runscript" ascii wide nocase
        $ss5 = "rsp_rundir" ascii wide nocase
        $ss6 = "Init-Dir-Info" ascii wide nocase
        $ss7 = "Do-Action-Ijt" ascii wide nocase
        $ss8 = "Do-Action-Scpt" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and filesize < 100KB and 5 of ($ss*)
}
