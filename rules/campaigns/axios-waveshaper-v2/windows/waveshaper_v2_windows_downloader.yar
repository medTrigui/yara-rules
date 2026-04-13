rule waveshaper_v2_windows_downloader
{
    meta:
        description = "WaveShaper v2 Windows downloader"
        author = "Mohamed Trigui"
        reference = ""
        date_created = "2026/04/12"
        date_modified = "2026/04/12"
        version = "1.0"
        category = "downloader"
        platform = "Windows"
        family = "WAVESHAPER.V2"
        confidence = "high"

     strings:
        $ss1 = "start /min powershell -w h" ascii wide nocase
        $ss2 = "[scriptblock]::Create([System.Text.Encoding]::UTF8.GetString" ascii wide nocase
        $ss3 = "Invoke-WebRequest -UseBasicParsing" ascii wide nocase
        $ss4 = "-Method POST -Body" ascii wide nocase
        $ss5 = "packages.npm.org/product1" ascii wide nocase
    condition:
        uint16(0) != 0x5A4D and filesize < 5KB and all of them
}
