rule waveshaper_v2_linux_backdoor
{
    meta:
        description = "WaveShaper v2 Linux backdoor"
        author = "Mohamed Trigui"
        reference = ""
        date_created = "2026/04/12"
        date_modified = "2026/04/12"
        version = "1.0"
        category = "backdoor"
        platform = "Linux"
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

        $ind5  = "/proc/sys/kernel/hostname" ascii
        $ind6  = "/sys/class/dmi/id/product_name" ascii
        $ind7  = "/var/log/dpkg.log" ascii
        $ind8  = "subprocess.run" ascii
        $ind9  = "shell=True" ascii
        $ind10 = "python3 -c" ascii
        $ind11 = "os.getlogin()" ascii
        $ind12 = "platform.release()" ascii
        $ind13 = "platform.machine()" ascii

    condition:
        filesize < 500KB and
        $ua and
        2 of ($msg*) and
        6 of ($ind*)
}
