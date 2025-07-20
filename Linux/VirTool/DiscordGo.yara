rule VirTool_Linux_DiscordGo_A_2147888110_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Linux/DiscordGo.A!MTB"
        threat_id = "2147888110"
        type = "VirTool"
        platform = "Linux: Linux platform"
        family = "DiscordGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "discordgo.User" ascii //weight: 1
        $x_1_2 = "discordgo.Intent" ascii //weight: 1
        $x_1_3 = "UserAvatarDecode" ascii //weight: 1
        $x_1_4 = "github.com/bwmarrin/discordgo" ascii //weight: 1
        $x_1_5 = "os/exec" ascii //weight: 1
        $x_1_6 = "DiscordGo/pkg/agent" ascii //weight: 1
        $x_1_7 = "github.com/gorilla/websocket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint32(0) == 0x464c457f) and
        (all of ($x*))
}

