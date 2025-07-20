rule VirTool_WinNT_Higlieder_A_2147575030_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Higlieder.gen!A"
        threat_id = "2147575030"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Higlieder"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reliz\\driver_rootkit\\driver\\m_hook" ascii //weight: 1
        $x_1_2 = "\\Device\\m_hook" wide //weight: 1
        $x_1_3 = "\\DosDevices\\m_hook" wide //weight: 1
        $x_1_4 = "filtnt.sys" wide //weight: 1
        $x_1_5 = "guardnt.sys" wide //weight: 1
        $x_1_6 = "_AVPM.EXE" wide //weight: 1
        $x_1_7 = "_AVPCC.EXE" wide //weight: 1
        $x_1_8 = "_AVP32.EXE" wide //weight: 1
        $x_1_9 = "zonealarm.exe" wide //weight: 1
        $x_1_10 = "zlclient.exe" wide //weight: 1
        $x_1_11 = "ZAUINST.EXE" wide //weight: 1
        $x_1_12 = "zatutor.exe" wide //weight: 1
        $x_1_13 = "SYNMGR.EXE" wide //weight: 1
        $x_1_14 = "SymWSC.exe" wide //weight: 1
        $x_1_15 = "SymSPort.exe" wide //weight: 1
        $x_1_16 = "SymProxySvc.exe" wide //weight: 1
        $x_1_17 = "symlcsvc.exe" wide //weight: 1
        $x_1_18 = "SCAN32.EXE" wide //weight: 1
        $x_1_19 = "SAVScan.exe" wide //weight: 1
        $x_1_20 = "savprogress.exe" wide //weight: 1
        $x_1_21 = "SAVMain.exe" wide //weight: 1
        $x_1_22 = "SAVAdminService.exe" wide //weight: 1
        $x_1_23 = "RuLaunch.exe" wide //weight: 1
        $x_1_24 = "RTVSCN95.EXE" wide //weight: 1
        $x_1_25 = "Rtvscan.exe" wide //weight: 1
        $x_1_26 = "NAVW32.EXE" wide //weight: 1
        $x_1_27 = "NavLu32.exe" wide //weight: 1
        $x_1_28 = "NAVAPW32.EXE" wide //weight: 1
        $x_1_29 = "navapsvc.exe" wide //weight: 1
        $x_1_30 = "KAVSvcUI.EXE" wide //weight: 1
        $x_1_31 = "KAVSvc.exe" wide //weight: 1
        $x_1_32 = "KAVStart.exe" wide //weight: 1
        $x_1_33 = "KavPFW.exe" wide //weight: 1
        $x_1_34 = "KAVPF.exe" wide //weight: 1
        $x_1_35 = "kavmm.exe" wide //weight: 1
        $x_1_36 = "KAV.exe" wide //weight: 1
        $x_1_37 = "InoUpTNG.exe" wide //weight: 1
        $x_1_38 = "InoTask.exe" wide //weight: 1
        $x_1_39 = "InoRT.exe" wide //weight: 1
        $x_1_40 = "InoRpc.exe" wide //weight: 1
        $x_1_41 = "InocIT.exe" wide //weight: 1
        $x_1_42 = "INETUPD.EXE" wide //weight: 1
        $x_1_43 = "IFACE.EXE" wide //weight: 1
        $x_1_44 = "ICSUPPNT.EXE" wide //weight: 1
        $x_1_45 = "ICSUPP95.EXE" wide //weight: 1
        $x_1_46 = "ICSSUPPNT.EXE" wide //weight: 1
        $x_1_47 = "ICMON.EXE" wide //weight: 1
        $x_1_48 = "ICLOADNT.EXE" wide //weight: 1
        $x_1_49 = "ICLOAD95.EXE" wide //weight: 1
        $x_1_50 = "GUARD.EXE" wide //weight: 1
        $x_1_51 = "GIANTAntiSpywareUpdater.exe" wide //weight: 1
        $x_1_52 = "GIANTAntiSpywareMain.exe" wide //weight: 1
        $x_1_53 = "gcasServ.exe" wide //weight: 1
        $x_1_54 = "gcasDtServ.exe" wide //weight: 1
        $x_1_55 = "F-StopW.EXE" wide //weight: 1
        $x_1_56 = "F-Sched.exe" wide //weight: 1
        $x_1_57 = "F-PROT95.EXE" wide //weight: 1
        $x_1_58 = "F-AGNT95.EXE" wide //weight: 1
        $x_1_59 = "EzAntivirusRegistrationCheck.exe" wide //weight: 1
        $x_1_60 = "ewidoctrl.exe" wide //weight: 1
        $x_1_61 = "ESCANHNT.EXE" wide //weight: 1
        $x_1_62 = "ESCANH95.EXE" wide //weight: 1
        $x_1_63 = "DRWEBUPW.EXE" wide //weight: 1
        $x_1_64 = "drwebscd.exe" wide //weight: 1
        $x_1_65 = "drweb32w.exe" wide //weight: 1
        $x_1_66 = "drwadins.exe" wide //weight: 1
        $x_1_67 = "DrVirus.exe" wide //weight: 1
        $x_1_68 = "AVP32.EXE" wide //weight: 1
        $x_1_69 = "AVP.EXE" wide //weight: 1
        $x_1_70 = "AVKWCtl.exe" wide //weight: 1
        $x_1_71 = "AVKService.exe" wide //weight: 1
        $x_1_72 = "AvkServ.exe" wide //weight: 1
        $x_1_73 = "avinitnt.exe" wide //weight: 1
        $x_1_74 = "avgupsvc.exe" wide //weight: 1
        $x_1_75 = "AVGUARD.EXE" wide //weight: 1
        $x_1_76 = "AVGSERV.EXE" wide //weight: 1
        $x_1_77 = "AVGNT.EXE" wide //weight: 1
        $x_1_78 = "avgfwsrv.exe" wide //weight: 1
        $x_1_79 = "avgemc.exe" wide //weight: 1
        $x_1_80 = "AVGCTRL.EXE" wide //weight: 1
        $x_1_81 = "AVGCC32.EXE" wide //weight: 1
        $x_1_82 = "avgcc.exe" wide //weight: 1
        $x_1_83 = "avgamsvr.exe" wide //weight: 1
        $x_1_84 = "AVENGINE.EXE" wide //weight: 1
        $x_1_85 = "AntiVirService" wide //weight: 1
        $x_1_86 = "AntiVirScheduler" wide //weight: 1
        $x_1_87 = "Anti-Trojan.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (70 of ($x*))
}

