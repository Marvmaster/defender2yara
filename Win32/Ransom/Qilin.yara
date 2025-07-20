rule Ransom_Win32_Qilin_MA_2147895933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Qilin.MA!MTB"
        threat_id = "2147895933"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Qilin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If you modify files - our decrypt software won't able to recover data " ascii //weight: 1
        $x_1_2 = "We have downloaded compromising and sensitive data from you" ascii //weight: 1
        $x_1_3 = ".README-RECOVER-.txt" ascii //weight: 1
        $x_1_4 = "to help you get the cipher key. We encourage you to consider your decisions" ascii //weight: 1
        $x_1_5 = "-- Credentials " ascii //weight: 1
        $x_1_6 = "-- Qilin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

rule Ransom_Win32_Qilin_AK_2147913418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Qilin.AK"
        threat_id = "2147913418"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Qilin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Payload executed and encryption process started" ascii //weight: 10
        $x_1_2 = "[ERROR|WALL] Error writing wallpaper to disk" ascii //weight: 1
        $x_1_3 = "HvHyper-VVMwareVMwareVMwareVBoxVBoxVBoxVirtualBoxKVMKVMKVM" ascii //weight: 1
        $x_1_4 = "[INFO|MUTEX] Ownership of mutex taken successfully" ascii //weight: 1
        $x_1_5 = "[INFO|VM] Machine detected as physical" ascii //weight: 1
        $x_1_6 = "[INFO|VM] Machine detected as a virtual machine" ascii //weight: 1
        $x_1_7 = "[INFO|VM] Could be false positive. Performing other checks" ascii //weight: 1
        $x_1_8 = "[INFO|VM] No guest VM key detected. Marking as false positive" ascii //weight: 1
        $x_1_9 = "[INFO|VM] Hyper-V guest key detected. This is a VM" ascii //weight: 1
        $x_1_10 = "[INFO|VM] Machine detected as VM inside  hypervisor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

