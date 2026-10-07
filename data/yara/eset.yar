/*
 * 115 rules selected from https://github.com/eset/malware-ioc
 * at commit 17baf44964a77368e9149f4f593eb098beddf1c5
 * License: BSD-2-Clause (see LICENSES.txt next to this file)
 * Modified by Guard: rules were selected, deduplicated and reformatted
 * (data/yara/README.md says how); rule logic is unchanged.
 */

import "elf"
import "pe"
rule ramFS
{
	meta:
		Author = "Joan Calvet"
		Date = "2015/07/14"
		Description = "RamFS -- custom file system used by Animal Farm malware"
		Reference = "http://www.welivesecurity.com/2015/06/30/dino-spying-malware-analyzed/"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$mz = { 4d 5a }
		$s01 = "Check: Error in File_List"
		$s02 = "Check: Error in FreeFileHeader_List"
		$s03 = "CD-->[%s]"
		$s04 = "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]"
		$s05 = "tr4qa589" fullword
		$s06 = "xT0rvwz" fullword
		$c01 = "INSTALL" fullword
		$c02 = "EXTRACT" fullword
		$c03 = "DELETE" fullword
		$c04 = "EXEC" fullword
		$c05 = "INJECT" fullword
		$c06 = "SLEEP" fullword
		$c07 = "KILL" fullword
		$c08 = "AUTODEL" fullword
		$c09 = "CD" fullword
		$c10 = "MD" fullword

	condition:
		($mz at 0 ) and ( ( 1 of ( $s* ) ) or ( all of ( $c* ) ) )
}

rule dino
{
	meta:
		Author = "Joan Calvet"
		Date = "2015/07/14"
		Description = "Dino backdoor"
		Reference = "http://www.welivesecurity.com/2015/06/30/dino-spying-malware-analyzed/"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$ = "PsmIsANiceM0du1eWith0SugarInsideA"
		$ = "destroyPSM"
		$ = "FM_PENDING_DOWN_%X"
		$ = "%s was canceled after %d try (reached MaxTry parameter)"
		$ = "you forgot value name"
		$ = "wakeup successfully scheduled in %d minutes"
		$ = "BD started at %s"
		$ = "decyphering failed on bd"

	condition:
		any of them
}

import "pe"

private rule IIS_Native_Module
{
	meta:
		description = "Signature to match an IIS native module (clean or malicious)"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$e1 = "This module subscribed to event"
		$e2 = "CHttpModule::OnBeginRequest"
		$e3 = "CHttpModule::OnPostBeginRequest"
		$e4 = "CHttpModule::OnAuthenticateRequest"
		$e5 = "CHttpModule::OnPostAuthenticateRequest"
		$e6 = "CHttpModule::OnAuthorizeRequest"
		$e7 = "CHttpModule::OnPostAuthorizeRequest"
		$e8 = "CHttpModule::OnResolveRequestCache"
		$e9 = "CHttpModule::OnPostResolveRequestCache"
		$e10 = "CHttpModule::OnMapRequestHandler"
		$e11 = "CHttpModule::OnPostMapRequestHandler"
		$e12 = "CHttpModule::OnAcquireRequestState"
		$e13 = "CHttpModule::OnPostAcquireRequestState"
		$e14 = "CHttpModule::OnPreExecuteRequestHandler"
		$e15 = "CHttpModule::OnPostPreExecuteRequestHandler"
		$e16 = "CHttpModule::OnExecuteRequestHandler"
		$e17 = "CHttpModule::OnPostExecuteRequestHandler"
		$e18 = "CHttpModule::OnReleaseRequestState"
		$e19 = "CHttpModule::OnPostReleaseRequestState"
		$e20 = "CHttpModule::OnUpdateRequestCache"
		$e21 = "CHttpModule::OnPostUpdateRequestCache"
		$e22 = "CHttpModule::OnLogRequest"
		$e23 = "CHttpModule::OnPostLogRequest"
		$e24 = "CHttpModule::OnEndRequest"
		$e25 = "CHttpModule::OnPostEndRequest"
		$e26 = "CHttpModule::OnSendResponse"
		$e27 = "CHttpModule::OnMapPath"
		$e28 = "CHttpModule::OnReadEntity"
		$e29 = "CHttpModule::OnCustomRequestNotification"
		$e30 = "CHttpModule::OnAsyncCompletion"
		$e31 = "CGlobalModule::OnGlobalStopListening"
		$e32 = "CGlobalModule::OnGlobalCacheCleanup"
		$e33 = "CGlobalModule::OnGlobalCacheOperation"
		$e34 = "CGlobalModule::OnGlobalHealthCheck"
		$e35 = "CGlobalModule::OnGlobalConfigurationChange"
		$e36 = "CGlobalModule::OnGlobalFileChange"
		$e37 = "CGlobalModule::OnGlobalApplicationStart"
		$e38 = "CGlobalModule::OnGlobalApplicationResolveModules"
		$e39 = "CGlobalModule::OnGlobalApplicationStop"
		$e40 = "CGlobalModule::OnGlobalRSCAQuery"
		$e41 = "CGlobalModule::OnGlobalTraceEvent"
		$e42 = "CGlobalModule::OnGlobalCustomNotification"
		$e43 = "CGlobalModule::OnGlobalThreadCleanup"
		$e44 = "CGlobalModule::OnGlobalApplicationPreload"

	condition:
		uint16( 0 ) == 0x5A4D and pe.exports ( "RegisterModule" ) and any of ( $e* )
}

rule IIS_Group01_IISRaid
{
	meta:
		description = "Detects Group 1 native IIS malware family (IIS-Raid derivates)"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "cmd.exe" ascii wide
		$s2 = "CMD"
		$s3 = "PIN"
		$s4 = "INJ"
		$s5 = "DMP"
		$s6 = "UPL"
		$s7 = "DOW"
		$s8 = "C:\\Windows\\System32\\credwiz.exe" ascii wide
		$p1 = "C:\\Windows\\Temp\\creds.db"
		$p2 = "C:\\Windows\\Temp\\thumbs.db"
		$p3 = "C:\\Windows\\Temp\\AAD30E0F.tmp"
		$p4 = "X-Chrome-Variations"
		$p5 = "X-Cache"
		$p6 = "X-Via"
		$p7 = "COM_InterProt"
		$p8 = "X-FFEServer"
		$p9 = "X-Content-Type-Options"
		$p10 = "Strict-Transport-Security"
		$p11 = "X-Password"
		$p12 = "XXXYYY-Ref"
		$p13 = "X-BLOG"
		$p14 = "X-BlogEngine"

	condition:
		IIS_Native_Module and 3 of ( $s* ) and any of ( $p* )
}

rule IIS_Group02
{
	meta:
		description = "Detects Group 2 native IIS malware family"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "HttpModule.pdb" ascii wide
		$s2 = "([\\w+%]+)=([^&]*)"
		$s3 = "([\\w+%]+)=([^!]*)"
		$s4 = "cmd.exe"
		$s5 = "C:\\Users\\Iso\\Documents\\Visual Studio 2013\\Projects\\IIS 5\\x64\\Release\\Vi.pdb" ascii wide
		$s6 = "AVRSAFunction"

	condition:
		IIS_Native_Module and 3 of ( $s* )
}

rule IIS_Group03
{
	meta:
		description = "Detects Group 3 native IIS malware family"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "IIS-Backdoor.dll"
		$s2 = "CryptStringToBinaryA"
		$s3 = "CreateProcessA"
		$s4 = "X-Cookie"

	condition:
		IIS_Native_Module and 3 of ( $s* )
}

rule IIS_Group04_RGDoor
{
	meta:
		description = "Detects Group 4 native IIS malware family (RGDoor)"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		reference = "https://unit42.paloaltonetworks.com/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$i1 = "RGSESSIONID="
		$s2 = "upload$"
		$s3 = "download$"
		$s4 = "cmd$"
		$s5 = "cmd.exe"

	condition:
		IIS_Native_Module and ( $i1 or all of ( $s* ) )
}

rule IIS_Group05_IIStealer
{
	meta:
		description = "Detects Group 5 native IIS malware family (IIStealer)"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "tojLrGzFMbcDTKcH" ascii wide
		$s2 = "4vUOj3IutgtrpVwh" ascii wide
		$s3 = "SoUnRCxgREXMu9bM" ascii wide
		$s4 = "9Zr1Z78OkgaXj1Xr" ascii wide
		$s5 = "cache.txt" ascii wide
		$s6 = "/checkout/checkout.aspx" ascii wide
		$s7 = "/checkout/Payment.aspx" ascii wide
		$s8 = "/privacy.aspx"
		$s9 = "X-IIS-Data"
		$s10 = "POST"
		$s11 = {C7 ?? CF 2F 00 63 00 C7 ?? D3 68 00 65 00 C7 ?? D7 63 00 6B 00 C7 ?? DB 6F 00 75 00 C7 ?? DF 74 00 2F 00 C7 ?? E3 63 00 68 00 C7 ?? E7 65 00 63 00 C7 ?? EB 6B 00 6F 00 C7 ?? EF 75 00 74 00 C7 ?? F3 2E 00 61 00 C7 ?? F7 73 00 70 00 C7 ?? FB 78 00 00 00}
		$s12 = {C7 ?? AF 2F 00 70 00 C7 ?? B3 72 00 69 00 C7 ?? B7 76 00 61 00 C7 ?? BB 63 00 79 00 C7 ?? BF 2E 00 61 00 C7 ?? C3 73 00 70 00 C7 ?? C7 78 00 00 00}

	condition:
		IIS_Native_Module and 3 of ( $s* )
}

rule IIS_Group06_ISN
{
	meta:
		description = "Detects Group 6 native IIS malware family (ISN)"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/the-curious-case-of-the-malicious-iis-module/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "isn7 config reloaded"
		$s2 = "isn7 config NOT reloaded, not found or empty"
		$s3 = "isn7 log deleted"
		$s4 = "isn7 log not deleted, ERROR 0x%X"
		$s5 = "isn7 log NOT found"
		$s6 = "isn_reloadconfig"
		$s7 = "D:\\soft\\Programming\\C++\\projects\\isapi\\isn7"
		$s8 = "get POST failed %d"
		$s9 = "isn7.dll"

	condition:
		IIS_Native_Module and 3 of ( $s* )
}

rule IIS_Group07_IISpy
{
	meta:
		description = "Detects Group 7 native IIS malware family (IISpy)"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "/credential/username"
		$s2 = "/credential/password"
		$s3 = "/computer/domain"
		$s4 = "/computer/name"
		$s5 = "/password"
		$s6 = "/cmd"
		$s7 = "%.8s%.8s=%.8s%.16s%.8s%.16s"
		$s8 = "ImpersonateLoggedOnUser"
		$s9 = "WNetAddConnection2W"
		$t1 = "X-Forwarded-Proto"
		$t2 = "Sec-Fetch-Mode"
		$t3 = "Sec-Fetch-Site"
		$t4 = "Cookie"
		$t5 = {49 45 4E 44 AE 42 60 82}
		$t6 = {89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52}

	condition:
		IIS_Native_Module and 2 of ( $s* ) and any of ( $t* )
}

rule IIS_Group08
{
	meta:
		description = "Detects Group 8 native IIS malware family"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$i1 = "FliterSecurity.dll"
		$i2 = "IIS7NativeModule.dll"
		$i3 = "Ver1.0."
		$s1 = "Cmd"
		$s2 = "Realy path : %s"
		$s3 = "Logged On Users : %d"
		$s4 = "Connect OK!"
		$s5 = "You are fucked!"
		$s6 = "Shit!Error"
		$s7 = "Where is the God!!"
		$s8 = "Shit!Download False!"
		$s9 = "Good!Run OK!"
		$s10 = "Shit!Run False!"
		$s11 = "Good!Download OK!"
		$s12 = "[%d]safedog"
		$s13 = "ed81bfc09d069121"
		$s14 = "a9478ef01967d190"
		$s15 = "af964b7479e5aea2"
		$s16 = "1f9e6526bea65b59"
		$s17 = "2b9e9de34f782d31"
		$s18 = "33cc5da72ac9d7bb"
		$s19 = "b1d71f4c2596cd55"
		$s20 = "101fb9d9e86d9e6c"

	condition:
		IIS_Native_Module and 1 of ( $i* ) and 3 of ( $s* )
}

rule IIS_Group09
{
	meta:
		description = "Detects Group 9 native IIS malware family"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$i1 = "FliterSecurity.dll"
		$i2 = {56565656565656565656565656565656}
		$i3 = "app|hot|alp|svf|fkj|mry|poc|doc|20" xor
		$i4 = "yisouspider|yisou|soso|sogou|m.sogou|sogo|sogou|so.com|baidu|bing|360" xor
		$i5 = "baidu|m.baidu|soso|sogou|m.sogou|sogo|sogou|so.com|google|youdao" xor
		$i6 = "118|abc|1go|evk" xor
		$s1 = "AVCFuckHttpModuleFactory"
		$s2 = "X-Forward"
		$s3 = "fuck32.dat"
		$s4 = "fuck64.dat"
		$s5 = "&ipzz1="
		$s6 = "&ipzz2="
		$s7 = "&uuu="
		$s8 = "http://20.3323sf.c" xor
		$s9 = "http://bj.whtjz.c" xor
		$s10 = "http://bj2.wzrpx.c" xor
		$s11 = "http://cs.whtjz.c" xor
		$s12 = "http://df.e652.c" xor
		$s13 = "http://dfcp.yyphw.c" xor
		$s14 = "http://es.csdsx.c" xor
		$s15 = "http://hz.wzrpx.c" xor
		$s16 = "http://id.3323sf.c" xor
		$s17 = "http://qp.008php.c" xor
		$s18 = "http://qp.nmnsw.c" xor
		$s19 = "http://sc.300bt.c" xor
		$s20 = "http://sc.wzrpx.c" xor
		$s21 = "http://sf2223.c" xor
		$s22 = "http://sx.cmdxb.c" xor
		$s23 = "http://sz.ycfhx.c" xor
		$s24 = "http://xpq.0660sf.c" xor
		$s25 = "http://xsc.b1174.c" xor

	condition:
		IIS_Native_Module and any of ( $i* ) and 3 of ( $s* )
}

rule IIS_Group10
{
	meta:
		description = "Detects Group 10 native IIS malware family"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "IIS7.dll"
		$s2 = "<title>(.*?)title(.*?)>"
		$s3 = "<meta(.*?)name(.*?)=(.*?)keywords(.*?)>"
		$s4 = "<meta(.*?)name(.*?)=(.*?)description(.*?)>"
		$s5 = "js.breakavs.co"
		$s6 = "&#24494;&#20449;&#32676;&#45;&#36187;&#36710;&#80;&#75;&#49;&#48;&#32676;&#12304;&#36827;&#32676;&#24494;&#20449;&#102;&#117;&#110;&#53;&#55;&#54;&#52;&#52;&#12305;&#95;&#24184;&#36816;&#39134;&#33351;&#95;&#24184;&#36816;&#50;&#56;&#32676;"
		$s7 = "&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#80;&#75;&#49;&#48;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#112;&#107;&#49;&#48;&#24494;&#20449;&#32676;&#44;&#80;&#75;&#49;&#48;&#24494;&#20449;&#32676;&#44;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#32676;&#44;"
		$s8 = "&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#12304;&#36827;&#32676;&#24494;&#20449;&#21495;&#102;&#117;&#110;&#53;&#55;&#54;&#52;&#52;&#12305;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;"
		$e1 = "Baiduspider"
		$e2 = "Sosospider"
		$e3 = "Sogou web spider"
		$e4 = "360Spider"
		$e5 = "YisouSpider"
		$e6 = "sogou.com"
		$e7 = "soso.com"
		$e8 = "uc.cn"
		$e9 = "baidu.com"
		$e10 = "sm.cn"

	condition:
		IIS_Native_Module and 2 of ( $e* ) and 3 of ( $s* )
}

rule IIS_Group11
{
	meta:
		description = "Detects Group 11 native IIS malware family"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "DnsQuery_A"
		$s2 = "&reurl="
		$s3 = "&jump=1"
		$s4 = "JVVRaeof"
		$s5 = "ncpmg::0"
		$s6 = "zkpzz0cnnuqwnw0eqo"
		$s7 = "jvvr<11yyy0cnnuqwnw0eqo130rjrAeofqwv?"

	condition:
		IIS_Native_Module and 3 of ( $s* )
}

rule IIS_Group12
{
	meta:
		description = "Detects Group 12 native IIS malware family"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "C:\\inetpub\\temp\\IIS Temporary Compressed Files\\"
		$s2 = "F5XFFHttpModule.dll"
		$s3 = "gtest_redir"
		$s4 = "\\cmd.exe" nocase
		$s5 = "iuuq;00"
		$s6 = "?xhost="
		$s7 = "&reurl="
		$s8 = "?jump=1"
		$s9 = "app|zqb"
		$s10 = "ifeng|ivc|sogou|so.com|baidu|google|youdao|yahoo|bing|118114|biso|gougou|sooule|360|sm|uc"
		$s11 = "sogou|so.com|baidu|google|youdao|yahoo|bing|gougou|sooule|360|sm.cn|uc"
		$s12 = "Hotcss/|Hotjs/"
		$s13 = "HotImg/|HotPic/"
		$s14 = "msf connect error !!"
		$s15 = "download ok !!"
		$s16 = "download error !! "
		$s17 = "param error !!"
		$s18 = "Real Path: "
		$s19 = "unknown cmd !"
		$b1 = {15 BD 01 2E [-] 5E 40 08 97 [-] CF 8C BE 30 [-] 28 42 C6 3B}
		$b2 = {E1 0A DC 39 [-] 49 BA 59 AB [-] BE 56 E0 57 [-] F2 0F 88 3E}

	condition:
		IIS_Native_Module and 5 of them
}

rule IIS_Group13_IISerpent
{
	meta:
		description = "Detects Group 13 native IIS malware family (IISerpent)"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "/mconfig/lunlian.txt"
		$s2 = "http://sb.qrfy.ne"
		$s3 = "folderlinkpath"
		$s4 = "folderlinkcount"
		$s5 = "onlymobilespider"
		$s6 = "redirectreferer"
		$s7 = "loadSuccessfull : "
		$s8 = "spider"
		$s9 = "<a href="
		$s11 = "?ReloadModuleConfig=1"
		$s12 = "?DisplayModuleConfig=1"

	condition:
		IIS_Native_Module and 5 of them
}

rule IIS_Group14
{
	meta:
		description = "Detects Group 14 native IIS malware family"
		author = "ESET Research"
		date = "2021-08-04"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$i1 = "agent-self: %s"
		$i2 = "/utf.php?key="
		$i3 = "/self.php?v="
		$i4 = "<script type=\"text/javascript\" src=\"//speed.wlaspsd.co"
		$i5 = "now.asmkpo.co"
		$s1 = "Baiduspider"
		$s2 = "360Spider"
		$s3 = "Sogou"
		$s4 = "YisouSpider"
		$s6 = "HTTP_X_FORWARDED_FOR"

	condition:
		IIS_Native_Module and 2 of ( $i* ) or 5 of them
}

private rule PrikormkaDropper
{
	strings:
		$mz = { 4D 5A }
		$kd00 = "KDSTORAGE" wide
		$kd01 = "KDSTORAGE_64" wide
		$kd02 = "KDRUNDRV32" wide
		$kd03 = "KDRAR" wide
		$bin00 = {69 65 04 15 00 14 1E 4A 16 42 08 6C 21 61 24 0F}
		$bin01 = {76 6F 05 04 16 1B 0D 5E 0D 42 08 6C 20 45 18 16}
		$bin02 = {4D 00 4D 00 43 00 00 00 67 00 75 00 69 00 64 00 56 00 47 00 41 00 00 00 5F 00 73 00 76 00 67 00}
		$inj00 = "?AVCinj2008Dlg@@" ascii
		$inj01 = "?AVCinj2008App@@" ascii

	condition:
		($mz at 0 ) and ( ( any of ( $bin* ) ) or ( 3 of ( $kd* ) ) or ( all of ( $inj* ) ) )
}

private rule PrikormkaModule
{
	strings:
		$mz = { 4D 5A }
		$str00 = {6D 70 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
		$str01 = {68 6C 70 75 63 74 66 2E 64 6C 6C 00 43 79 63 6C 65}
		$str02 = {00 6B 6C 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
		$str03 = {69 6F 6D 75 73 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67}
		$str04 = {61 74 69 6D 6C 2E 64 6C 6C 00 4B 69 63 6B 49 6E 50 6F 69 6E 74}
		$str05 = {73 6E 6D 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}
		$str06 = {73 63 72 73 68 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}
		$str07 = {50 52 55 5C 17 51 58 17 5E 4A}
		$str08 = {60 4A 55 55 4E 53 58 4B 17 52 57 17 5E 4A}
		$str09 = {55 52 5D 4E 5B 4A 5D 17 51 58 17 5E 4A}
		$str10 = {60 4A 55 55 4E 61 17 51 58 17 5E 4A}
		$str11 = {39 5D 17 1D 1C 0A 3C 57 59 3B 1C 1E 57 58 4C 54 0F}
		$str12 = "ZxWinDeffContex" ascii wide
		$str13 = "Paramore756Contex43" wide
		$str14 = "Zw_&one@ldrContext43" wide
		$str15 = "A95BL765MNG2GPRS"
		$str16 = "helpldr.dll" wide fullword
		$str17 = "swma.dll" wide fullword
		$str18 = "iomus.dll" wide fullword
		$str19 = "atiml.dll" wide fullword
		$str20 = "hlpuctf.dll" wide fullword
		$str21 = "hauthuid.dll" ascii wide fullword
		$str22 = "[roboconid][%s]" ascii fullword
		$str23 = "[objectset][%s]" ascii fullword
		$str24 = "rbcon.ini" wide fullword
		$str25 = "%s%02d.%02d.%02d_%02d.%02d.%02d.skw" ascii fullword
		$str26 = "%02d.%02d.%02d_%02d.%02d.%02d.%02d.rem" wide fullword
		$str27 = ":\\!PROJECTS!\\Mina\\2015\\" ascii
		$str28 = "\\PZZ\\RMO\\" ascii
		$str29 = ":\\work\\PZZ" ascii
		$str30 = "C:\\Users\\mlk\\" ascii
		$str31 = ":\\W o r k S p a c e\\" ascii
		$str32 = "D:\\My\\Projects_All\\2015\\" ascii
		$str33 = "\\TOOLS PZZ\\Bezzahod\\" ascii

	condition:
		($mz at 0 ) and ( any of ( $str* ) )
}

private rule PrikormkaEarlyVersion
{
	strings:
		$mz = { 4D 5A }
		$str00 = "IntelRestore" ascii fullword
		$str01 = "Resent" wide fullword
		$str02 = "ocp8.1" wide fullword
		$str03 = "rsfvxd.dat" ascii fullword
		$str04 = "tsb386.dat" ascii fullword
		$str05 = "frmmlg.dat" ascii fullword
		$str06 = "smdhost.dll" ascii fullword
		$str07 = "KDLLCFX" wide fullword
		$str08 = "KDLLRUNDRV" wide fullword

	condition:
		($mz at 0 ) and ( 2 of ( $str* ) )
}

rule Prikormka
{
	meta:
		Author = "Anton Cherepanov"
		Date = "2016/05/10"
		Description = "Operation Groundbait"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "threatintel@eset.com"
		License = "BSD 2-Clause"

	condition:
		PrikormkaDropper or PrikormkaModule or PrikormkaEarlyVersion
}

rule apt_Windows_InvisiMole_Logs
{
	meta:
		description = "Detects log files with collected created by InvisiMole's RC2CL backdoor"
		author = "ESET Research"
		date = "2021-05-17"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	condition:
		uint32( 0 ) == 0x08F1CAA1 or uint32( 0 ) == 0x08F1CAA2 or uint32( 0 ) == 0x08F1CCC0 or uint32( 0 ) == 0x08F2AFC0 or uint32( 0 ) == 0x083AE4DF or uint32( 0 ) == 0x18F2CBB1 or uint32( 0 ) == 0x1900ABBA or uint32( 0 ) == 0x24F2CEA1 or uint32( 0 ) == 0xDA012193 or uint32( 0 ) == 0xDA018993 or uint32( 0 ) == 0xDA018995 or uint32( 0 ) == 0xDD018991
}

rule apt_Windows_InvisiMole_SFX_Dropper
{
	meta:
		description = "Detects trojanized InvisiMole files: patched RAR SFX droppers with added InvisiMole blobs (config encrypted XOR 2A at the end of a file)"
		author = "ESET Research"
		date = "2021-05-17"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$encrypted_config = {5F 59 4F 58 19 18 04 4E 46 46 2A 5D 59 5A 58 43 44 5E 4C 7D 2A 0F 2A 59 2A 78 2A 4B 2A 58 2A 0E 2A 6F 2A 72 2A 4B 2A 0F 2A 4E 2A 04 2A 0F 2A 4E 2A 76 2A 0F 2A 79 2A 2A 2A 79 42 4F 46 46 6F 52 4F 49 5F 5E 4F 7D 2A 79 42 4F 46 46 19 18 04 4E 46 46 2A 7C 43 58 5E 5F 4B 46 6B 46 46 45 49 2A 66 45 4B 4E 66 43 48 58 4B 58 53 6B}

	condition:
		uint16( 0 ) == 0x5A4D and $encrypted_config
}

rule apt_Windows_InvisiMole_CPL_Loader
{
	meta:
		description = "CPL loader"
		author = "ESET Research"
		date = "2021-05-17"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "WScr%steObject(\"WScr%s.Run(\"::{20d04fe0-3a%s30309d}\\\\::{21EC%sDD-08002B3030%s\", 0);"
		$s2 = "\\Control.js" wide
		$s3 = "\\Control Panel.lnk" wide
		$s4 = "FPC 3.0.4 [2019/04/13] for x86_64 - Win64"
		$s5 = "FPC 3.0.4 [2019/04/13] for i386 - Win32"
		$s6 = "imageapplet.dat" wide
		$s7 = "wkssvmtx"

	condition:
		uint16( 0 ) == 0x5A4D and ( 3 of them )
}

import "pe"

rule apt_Windows_InvisiMole_Wrapper_DLL
{
	meta:
		description = "Detects InvisiMole wrapper DLL with embedded RC2CL and RC2FM backdoors, by export and resource names"
		author = "ESET Research"
		date = "2021-05-17"
		reference = "https://www.welivesecurity.com/2018/06/07/invisimole-equipped-spyware-undercover/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	condition:
		pe.exports( "GetDataLength" ) and for any y in ( 0 .. pe.number_of_resources - 1 ) : ( pe.resources [ y ] . type == pe.RESOURCE_TYPE_RCDATA and pe.resources [ y ] . name_string == "R\x00C\x002\x00C\x00L\x00" ) and for any y in ( 0 .. pe.number_of_resources - 1 ) : ( pe.resources [ y ] . type == pe.RESOURCE_TYPE_RCDATA and pe.resources [ y ] . name_string == "R\x00C\x002\x00F\x00M\x00" )
}

private rule InvisiMole_Blob
{
	meta:
		description = "Detects InvisiMole blobs by magic values"
		author = "ESET Research"
		date = "2021-05-17"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$magic_old_32 = {F9 FF D0 DE}
		$magic_old_64 = {64 FF D0 DE}
		$magic_new_32 = {86 DA 11 CE}
		$magic_new_64 = {64 DA 11 CE}

	condition:
		($magic_old_32 at 0 ) or ( $magic_old_64 at 0 ) or ( $magic_new_32 at 0 ) or ( $magic_new_64 at 0 )
}

rule apt_Windows_InvisiMole_DNS_Downloader
{
	meta:
		description = "InvisiMole DNS downloader"
		author = "ESET Research"
		date = "2021-05-17"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$d = "DnsQuery_A"
		$s1 = "Wireshark-is-running-{9CA78EEA-EA4D-4490-9240-FC01FCEF464B}" xor
		$s2 = "AddIns\\" ascii wide xor
		$s3 = "pcornomeex." xor
		$s4 = "weriahsek.rxe" xor
		$s5 = "dpmupaceex." xor
		$s6 = "TCPViewClass" xor
		$s7 = "PROCMON_WINDOW_CLASS" xor
		$s8 = "Key%C"
		$s9 = "AutoEx%C" xor
		$s10 = "MSO~"
		$s11 = "MDE~"
		$s12 = "DNS PLUGIN, Step %d" xor
		$s13 = "rundll32.exe \"%s\",StartUI"

	condition:
		(( uint16( 0 ) == 0x5A4D ) or InvisiMole_Blob ) and $d and 5 of ( $s* )
}

rule apt_Windows_InvisiMole_RC2CL_Backdoor
{
	meta:
		description = "InvisiMole RC2CL backdoor"
		author = "ESET Research"
		date = "2021-05-17"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "RC2CL" wide
		$s2 = "hp12KsNh92Dwd" wide
		$s3 = "ZLib package %s: files: %d, total size: %d" wide
		$s4 = "\\Un4seen" wide
		$s5 = {9E 01 3A AD}
		$s6 = "~mrc_" wide
		$s7 = "~src_" wide
		$s8 = "~wbc_" wide
		$s9 = "zdf_" wide
		$s10 = "~S0PM" wide
		$s11 = "~A0FM" wide
		$s12 = "~70Z63\\" wide
		$s13 = "~E070C" wide
		$s14 = "~N031E" wide
		$s15 = "%szdf_%s.data" wide
		$s16 = "%spicture.crd" wide
		$s17 = "%s70zf_%s.cab" wide
		$s18 = "%spreview.crd" wide
		$s19 = "Value_Bck" wide
		$s20 = "Value_WSFX_ZC" wide
		$s21 = "MachineAccessStateData" wide
		$s22 = "SettingsSR2" wide

	condition:
		(( uint16( 0 ) == 0x5A4D ) or InvisiMole_Blob ) and 5 of ( $s* )
}

rule apt_Windows_InvisiMole
{
	meta:
		description = "InvisiMole magic values, keys and strings"
		author = "ESET Research"
		date = "2021-05-17"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "CryptProtectData"
		$s2 = "CryptUnprotectData"
		$s3 = {9E 01 3A AD}
		$s4 = "GET /getversion2a/%d%.2X%.2X/U%sN HTTP/1.1"
		$s5 = "PULSAR_LOADER.dll"
		$check_magic_old_32 = {3? F9 FF D0 DE}
		$check_magic_old_64 = {3? 64 FF D0 DE}
		$check_magic_new_32 = {81 3? 86 DA 11 CE}
		$check_magic_new_64 = {81 3? 64 DA 11 CE}

	condition:
		(( uint16( 0 ) == 0x5A4D ) or InvisiMole_Blob ) and ( any of ( $check_magic* ) ) and ( 2 of ( $s* ) )
}

rule apt_Windows_InvisiMole_C2
{
	meta:
		description = "InvisiMole C&C servers"
		author = "ESET Research"
		date = "2021-05-17"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "46.165.220.228" ascii wide
		$s2 = "80.255.3.66" ascii wide
		$s3 = "85.17.26.174" ascii wide
		$s4 = "185.193.38.55" ascii wide
		$s5 = "194.187.249.157" ascii wide
		$s6 = "195.154.255.211" ascii wide
		$s7 = "153.re" ascii wide fullword
		$s8 = "adstat.red" ascii wide
		$s9 = "adtrax.net" ascii wide
		$s10 = "akamai.sytes.net" ascii wide
		$s11 = "amz-eu401.com" ascii wide
		$s12 = "blabla234342.sytes.net" ascii wide
		$s13 = "mx1.be" ascii wide fullword
		$s14 = "statad.de" ascii wide
		$s15 = "time.servehttp.com" ascii wide
		$s16 = "upd.re" ascii wide fullword
		$s17 = "update.xn--6frz82g" ascii wide
		$s18 = "updatecloud.sytes.net" ascii wide
		$s19 = "updchecking.sytes.net" ascii wide
		$s20 = "wlsts.net" ascii wide
		$s21 = "ro2.host" ascii wide fullword
		$s22 = "2ld.xyz" ascii wide fullword
		$s23 = "the-haba.com" ascii wide
		$s24 = "82.202.172.134" ascii wide
		$s25 = "update.xn--6frz82g" ascii wide

	condition:
		(( uint16( 0 ) == 0x5A4D ) or InvisiMole_Blob ) and $s21 and any of them
}

rule keydnap_downloader
{
	meta:
		description = "OSX/Keydnap Downloader"
		author = "Marc-Etienne M.Léveillé"
		date = "2016-07-06"
		reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
		version = "1"

	strings:
		$ = "icloudsyncd"
		$ = "killall Terminal"
		$ = "open %s"

	condition:
		2 of them
}

rule keydnap_backdoor_packer
{
	meta:
		description = "OSX/Keydnap packed backdoor"
		author = "Marc-Etienne M.Léveillé"
		date = "2016-07-06"
		reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
		version = "1"

	strings:
		$upx_string = "This file is packed with the UPX"
		$packer_magic = "ASS7"
		$upx_magic = "UPX!"

	condition:
		$upx_string and $packer_magic and not $upx_magic
}

rule keydnap_backdoor
{
	meta:
		description = "Unpacked OSX/Keydnap backdoor"
		author = "Marc-Etienne M.Léveillé"
		date = "2016-07-06"
		reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
		version = "1"

	strings:
		$ = "api/osx/get_task"
		$ = "api/osx/cmd_executed"
		$ = "Loader-"
		$ = "u2RLhh+!LGd9p8!ZtuKcN"
		$ = "com.apple.iCloud.sync.daemon"

	condition:
		2 of them
}

rule kobalos
{
	meta:
		description = "Kobalos malware"
		author = "Marc-Etienne M.Léveillé"
		date = "2020-11-02"
		reference = "http://www.welivesecurity.com"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$encrypted_strings_sizes = {
            05 00 00 00 09 00 00 00  04 00 00 00 06 00 00 00
            08 00 00 00 08 00 00 00  02 00 00 00 02 00 00 00
            01 00 00 00 01 00 00 00  05 00 00 00 07 00 00 00
            05 00 00 00 05 00 00 00  05 00 00 00 0A 00 00 00
        }
		$password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
		$rsa_512_mod_header = { 10 11 02 00 09 02 00 }
		$strings_rc4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }

	condition:
		any of them
}

rule kobalos_ssh_credential_stealer
{
	meta:
		description = "Kobalos SSH credential stealer seen in OpenSSH client"
		author = "Marc-Etienne M.Léveillé"
		date = "2020-11-02"
		reference = "http://www.welivesecurity.com"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

	condition:
		any of them
}

private rule is_elf
{
	strings:
		$header = { 7F 45 4C 46 }

	condition:
		$header at 0
}

rule moose_1
{
	meta:
		Author = "Thomas Dupuy"
		Date = "2015/04/21"
		Description = "Linux/Moose malware"
		Reference = "http://www.welivesecurity.com/wp-content/uploads/2015/05/Dissecting-LinuxMoose.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s0 = "Status: OK"
		$s1 = "--scrypt"
		$s2 = "stratum+tcp://"
		$s3 = "cmd.so"
		$s4 = "/Challenge"
		$s7 = "processor"
		$s9 = "cpu model"
		$s21 = "password is wrong"
		$s22 = "password:"
		$s23 = "uthentication failed"
		$s24 = "sh"
		$s25 = "ps"
		$s26 = "echo -n -e "
		$s27 = "chmod"
		$s28 = "elan2"
		$s29 = "elan3"
		$s30 = "chmod: not found"
		$s31 = "cat /proc/cpuinfo"
		$s32 = "/proc/%s/cmdline"
		$s33 = "kill %s"

	condition:
		is_elf and all of them
}

rule moose_2
{
	meta:
		Author = "Thomas Dupuy"
		Date = "2016/10/02"
		Description = "Linux/Moose malware active since September 2015"
		Reference = "http://www.welivesecurity.com/2016/11/02/linuxmoose-still-breathing/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "Modules are loaded"
		$s2 = "--scrypt"
		$s3 = "http://"
		$s4 = "https://"
		$s5 = "processor "
		$s6 = "cpu model "
		$s7 = "Host: www.challpok.cn"
		$s8 = "Cookie: PHPSESSID=%s; nhash=%s; chash=%s"
		$s9 = "fail!"
		$s10 = "H3lL0WoRlD"
		$s11 = "crondd"
		$s12 = "cat /proc/cpuinfo"
		$s13 = "Set-Cookie: PHPSESSID="
		$s14 = "Set-Cookie: LP="
		$s15 = "Set-Cookie: WL="
		$s16 = "Set-Cookie: CP="
		$s17 = "Loading modules..."
		$s18 = "-nobg"

	condition:
		is_elf and 5 of them
}

rule mozi_killswitch
{
	meta:
		description = "Mozi botnet kill switch"
		author = "Ivan Besina"
		date = "2023-09-29"
		reference = "http://www.welivesecurity.com"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$iptables1 = "iptables -I INPUT  -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "iptables -I OUTPUT -p tcp --sport 30005 -j DROP"
		$haha = "/haha"
		$networks = "/usr/networks"

	condition:
		all of them and filesize < 500KB
}

rule mumblehard_packer
{
	meta:
		description = "Mumblehard i386 assembly code responsible for decrypting Perl code"
		author = "Marc-Etienne M.Léveillé"
		date = "2015-04-07"
		reference = "http://www.welivesecurity.com"
		version = "1"

	strings:
		$decrypt = { 31 db  [1-10]  ba ?? 00 00 00  [0-6]  (56 5f |  89 F7)
                     39 d3 75 13 81 fa ?? 00 00 00 75 02 31 d2 81 c2 ?? 00 00
                     00 31 db 43 ac 30 d8 aa 43 e2 e2 }

	condition:
		$decrypt
}

import "pe"

rule RichHeaders_Lazarus_NukeSped_IconicPayloads_3CX_Q12023
{
	meta:
		description = "Rich Headers-based rule covering the IconicLoader and IconicStealer from the 3CX supply chain incident, and also payloads from the cryptocurrency campaigns from 2022-12"
		author = "ESET Research"
		date = "2023-03-31"
		hash = "3B88CDA62CDD918B62EF5AA8C5A73A46F176D18B"
		hash = "CAD1120D91B812ACAFEF7175F949DD1B09C6C21A"
		hash = "5B03294B72C0CAA5FB20E7817002C600645EB475"
		hash = "7491BD61ED15298CE5EE5FFD01C8C82A2CDB40EC"

	condition:
		pe.rich_signature.toolid( 259 , 30818 ) == 9 and pe.rich_signature.toolid ( 256 , 31329 ) == 1 and pe.rich_signature.toolid ( 261 , 30818 ) >= 30 and pe.rich_signature.toolid ( 261 , 30818 ) <= 38 and pe.rich_signature.toolid ( 261 , 29395 ) >= 134 and pe.rich_signature.toolid ( 261 , 29395 ) <= 164 and pe.rich_signature.toolid ( 257 , 29395 ) >= 6 and pe.rich_signature.toolid ( 257 , 29395 ) <= 14
}

rule linux_rakos
{
	meta:
		description = "Linux/Rakos.A executable"
		author = "Peter Kálnai"
		date = "2016-12-13"
		reference = "http://www.welivesecurity.com/2016/12/20/new-linuxrakos-threat-devices-servers-ssh-scan/"
		version = "1"
		contact = "threatintel@eset.com"
		license = "BSD 2-Clause"

	strings:
		$ = "upgrade/vars.yaml"
		$ = "MUTTER"
		$ = "/tmp/.javaxxx"
		$ = "uckmydi"

	condition:
		3 of them
}

rule cw_Windows_Redline_panel_tab_headers
{
	meta:
		description = "Matches view headers in Redline Panel"
		author = "ESET Research"
		date = "2022-10-11"
		last_modified = "2024-11-12"
		hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
		reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = 2

	strings:
		$ = "RedLine | Log In"
		$ = "RedLine | Autofilles Viewer"
		$ = "RedLine | Choose Browser"
		$ = "RedLine | Cookie Viewer"
		$ = "RedLine | Credit Card Viewer"
		$ = "RedLine | Files Viewer"
		$ = "RedLine | Log saver"
		$ = "RedLine | System Info Viewer"

	condition:
		uint16( 0 ) == 0x5A4D and 6 of them
}

rule cw_Windows_Redline_panel_distinctive_strings
{
	meta:
		description = "Matches rare strings found in Redline panel"
		author = "ESET Research"
		date = "2022-10-11"
		last_modified = "2024-11-12"
		hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
		reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = 2

	strings:
		$env_var = "%DSK_23%"
		$fn_name = "IsGratherThan"
		$telegram0 = "Telegram: @REDLINESUPPORT"
		$telegram1 = "https://t.me/REDLINESUPPORT"

	condition:
		uint16( 0 ) == 0x5A4D and any of them
}

rule cw_Windows_Redline_panel_prompts
{
	meta:
		description = "Matches prompt messages in Redline panel"
		author = "ESET Research"
		date = "2022-10-11"
		last_modified = "2024-11-12"
		hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
		reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = 2

	strings:
		$ = "Choose directory to save log"
		$ = "Select log to set comment"
		$ = "Please enter an action to create new task"
		$ = "Please enter a target to create new task"
		$ = "Please enter a final point to create new task"
		$ = "Please enter a correct action to create new task"
		$ = "Please enter a correct final point to create new task"
		$ = "Please enter an action to edit task"
		$ = "Please enter a target to edit task"
		$ = "Please enter a final point to edit task"
		$ = "Please enter a correct action to edit task"
		$ = "Please enter a correct final point to edit task"
		$ = "Please enter a correct status to edit task"
		$ = "Please, enter a domains"
		$ = "Please, enter a valid server ip"
		$ = "Choose a file to pump"
		$ = "Enter a valid count of bytes"
		$ = "Enter a valid count of bytes. Must be more then zero"
		$ = "Disconnected. Reboot your panel"

	condition:
		uint16( 0 ) == 0x5A4D and 10 of them
}

rule cw_Windows_Redline_panel_status_message_strings
{
	meta:
		description = "Matches error/success messages in Redline panel"
		author = "ESET Research"
		date = "2022-10-11"
		last_modified = "2024-11-12"
		hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
		reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = 1

	strings:
		$ = "All Browsers are empty"
		$ = "Client [{0}:{1}:{2}] completed task with {3} ID."
		$ = "A List of logs cleared"
		$ = "Browsers not found"
		$ = "Browsers is empty"
		$ = "Done. Check your build file"
		$ = "You must to enable assembly info or certificate in settings"
		$ = "Duplicate log from "
		$ = "Password list is empty"
		$ = "Cookie list is empty"
		$ = "FTPs not found"
		$ = "Files not found"

	condition:
		uint16( 0 ) == 0x5A4D and 8 of them
}

rule cw_Windows_Redline_panel_commands
{
	meta:
		description = "Matches commands and functionalities in Redline panel"
		author = "ESET Research"
		date = "2022-10-11"
		last_modified = "2024-11-12"
		hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
		reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = 2

	strings:
		$cmd0 = "Download"
		$cmd1 = "RunPE"
		$cmd2 = "DownloadAndEx"
		$cmd3 = "OpenLink"
		$cmd4 = "Cmd"
		$action0 = "GrabBrowsers"
		$action1 = "GrabFiles"
		$action2 = "GrabImClients"
		$action3 = "AntiDuplicate"
		$action4 = "grabBrowsers"
		$action5 = "grabFiles"
		$action6 = "grabImClients"
		$action7 = "antiDuplicate"

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $cmd* ) and 4 of ( $action* )
}

import "pe"

rule SparklingGoblin_ChaCha20Loader_RichHeader
{
	meta:
		author = "ESET Research"
		copyright = "ESET Research"
		description = "Rule matching ChaCha20 loaders rich header"
		date = "2021-03-30"
		reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		hash = "09FFE37A54BC4EBEBD8D56098E4C76232F35D821"
		hash = "29B147B76BB0D9E09F7297487CB972E6A2905586"
		hash = "33F2C3DE2457B758FC5824A2B253AD7C7C2E9E37"
		hash = "45BEF297CE78521EAC6EE39E7603E18360E67C5A"
		hash = "4CEC7CDC78D95C70555A153963064F216DAE8799"
		hash = "4D4C1A062A0390B20732BA4D65317827F2339B80"
		hash = "4F6949A4906B834E83FF951E135E0850FE49D5E4"

	condition:
		pe.rich_signature.length>= 104 and pe.rich_signature.length <= 112 and pe.rich_signature.toolid ( 241 , 40116 ) >= 5 and pe.rich_signature.toolid ( 241 , 40116 ) <= 10 and pe.rich_signature.toolid ( 147 , 30729 ) == 11 and pe.rich_signature.toolid ( 264 , 24215 ) >= 15 and pe.rich_signature.toolid ( 264 , 24215 ) <= 16
}

rule SparklingGoblin_ChaCha20
{
	meta:
		author = "ESET Research"
		copyright = "ESET Research"
		description = "SparklingGoblin ChaCha20 implementations"
		date = "2021-05-20"
		reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		hash = "2EDBEA43F5C40C867E5B6BBD93CC972525DF598B"
		hash = "B6D245D3D49B06645C0578804064CE0C072CBE0F"
		hash = "8BE6D5F040D0085C62B1459AFC627707B0DE89CF"
		hash = "4668302969FE122874FB2447A80378DCB671C86B"
		hash = "9BDECB08E16A23D271D0A3E836D9E7F83D7E2C3B"
		hash = "9CE7650F2C08C391A35D69956E171932D116B8BD"
		hash = "91B32E030A1F286E7D502CA17E107D4BFBD7394A"

	strings:
		$chunk_1 = {
            8B 4D ??
            56
            8B 75 ??
            57
            8B 7D ??
            8B 04 BB
            01 04 93
            8B 04 B3
            33 04 93
            C1 C0 10
            89 04 B3
            01 04 8B
            8B 04 BB
            33 04 8B
            C1 C0 0C
            89 04 BB
            01 04 93
            8B 04 B3
            33 04 93
            C1 C0 08
            89 04 B3
            01 04 8B
            8B 04 BB
            33 04 8B
            C1 C0 07
            89 04 BB
        }
		$chunk_2 = {
            03 4D ??
            44 03 C0
            03 55 ??
            33 F1
            45 33 D8
            C1 C6 10
            44 33 F2
            41 C1 C3 10
            41 03 FB
            41 C1 C6 10
            45 03 E6
            41 03 DA
            44 33 CB
            44 03 EE
            41 C1 C1 10
            8B C7
            33 45 ??
            45 03 F9
            C1 C0 0C
            44 03 C0
            45 33 D8
            44 89 45 ??
            41 C1 C3 08
            41 03 FB
            44 8B C7
            44 33 C0
            41 8B C5
            33 45 ??
            C1 C0 0C
            03 C8
            41 C1 C0 07
            33 F1
            89 4D ??
            C1 C6 08
            44 03 EE
            41 8B CD
            33 C8
            41 8B C4
            33 45 ??
            C1 C0 0C
            03 D0
            C1 C1 07
            44 33 F2
            89 55 ??
            41 C1 C6 08
            45 03 E6
            41 8B D4
            33 D0
            41 8B C7
            41 33 C2
            C1 C2 07
            C1 C0 0C
            03 D8
            44 33 CB
            41 C1 C1 08
            45 03 F9
            45 8B D7
            44 33 D0
            8B 45 ??
            03 C1
            41 C1 C2 07
            44 33 C8
            89 45 ??
            41 C1 C1 10
            45 03 E1
            41 8B C4
            33 C1
            8B 4D ??
            C1 C0 0C
            03 C8
            44 33 C9
            89 4D ??
            89 4D ??
            41 C1 C1 08
            45 03 E1
            41 8B CC
            33 C8
            8B 45 ??
            C1 C1 07
            89 4D ??
            89 4D ??
            03 C2
            41 03 D8
            89 45 ??
            41 33 C3
            C1 C0 10
            44 03 F8
            41 8B CF
            33 CA
            8B 55 ??
        }
		$chunk_3 = {
            C7 45 ?? 65 78 70 61
            4C 8D 45 ??
            C7 45 ?? 6E 64 20 33
            4D 8B F9
            C7 45 ?? 32 2D 62 79
            4C 2B C1
            C7 45 ?? 74 65 20 6B
        }
		$chunk_4 = {
            0F B6 02
            0F B6 4A ??
            C1 E1 08
            0B C8
            0F B6 42 ??
            C1 E1 08
            0B C8
            0F B6 42 ??
            C1 E1 08
            0B C8
            41 89 0C 10
            48 8D 52 ??
            49 83 E9 01
        }
		$chunk_5 = {
            03 4D ??
            44 03 C0
            03 55 ??
            33 F1
            41 33 F8
            C1 C6 10
            44 33 F2
            C1 C7 10
            44 03 DF
            41 C1 C6 10
            45 03 E6
            44 03 CB
            45 33 D1
            44 03 EE
            41 C1 C2 10
            41 8B C3
            33 45 ??
            45 03 FA
            C1 C0 0C
            44 03 C0
            41 33 F8
            44 89 45 ??
            C1 C7 08
            44 03 DF
            45 8B C3
            44 33 C0
            41 8B C5
            33 45 ??
            C1 C0 0C
            03 C8
            41 C1 C0 07
            33 F1
            89 4D ??
            C1 C6 08
            44 03 EE
            41 8B CD
            33 C8
            41 8B C4
            33 45 ??
            C1 C0 0C
            03 D0
            C1 C1 07
            44 33 F2
            89 55 ??
            41 C1 C6 08
            45 03 E6
            41 8B D4
            33 D0
            41 8B C7
            33 C3
            C1 C2 07
            C1 C0 0C
            44 03 C8
            45 33 D1
            41 C1 C2 08
            45 03 FA
            41 8B DF
            33 D8
            8B 45 ??
            03 C1
            C1 C3 07
            44 33 D0
            89 45 ??
            41 C1 C2 10
            45 03 E2
            41 8B C4
            33 C1
            8B 4D ??
            C1 C0 0C
            03 C8
            44 33 D1
            89 4D ??
            89 4D ??
            41 C1 C2 08
            45 03 E2
            41 8B CC
            33 C8
            8B 45 ??
            C1 C1 07
            89 4D ??
            89 4D ??
            03 C2
            45 03 C8
            89 45 ??
            33 C7
            C1 C0 10
            44 03 F8
            41 8B CF
            33 CA
            8B 55 ??
            C1 C1 0C
            03 D1
            8B FA
            89 55 ??
            33 F8
            89 55 ??
            8B 55 ??
            03 D3
            C1 C7 08
            44 03 FF
            41 8B C7
            33 C1
            C1 C0 07
            89 45 ??
            89 45 ??
            8B C2
            33 C6
            C1 C0 10
            44 03 D8
            41 33 DB
            C1 C3 0C
            03 D3
            8B F2
            89 55 ??
            33 F0
            41 8B C1
            41 33 C6
            C1 C6 08
            C1 C0 10
            44 03 DE
            44 03 E8
            41 33 DB
            41 8B CD
            C1 C3 07
            41 33 C8
            44 8B 45 ??
            C1 C1 0C
            44 03 C9
            45 8B F1
            44 33 F0
            41 C1 C6 08
            45 03 EE
            41 8B C5
            33 C1
            8B 4D ??
            C1 C0 07
        }

	condition:
		any of them and filesize < 450KB
}

rule SparklingGoblin_EtwEventWrite
{
	meta:
		author = "ESET Research"
		copyright = "ESET Research"
		description = "SparklingGoblin EtwEventWrite patching"
		date = "2021-05-20"
		reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		hash = "2EDBEA43F5C40C867E5B6BBD93CC972525DF598B"
		hash = "B6D245D3D49B06645C0578804064CE0C072CBE0F"
		hash = "8BE6D5F040D0085C62B1459AFC627707B0DE89CF"
		hash = "4668302969FE122874FB2447A80378DCB671C86B"
		hash = "9BDECB08E16A23D271D0A3E836D9E7F83D7E2C3B"
		hash = "9CE7650F2C08C391A35D69956E171932D116B8BD"

	strings:
		$chunk_1 = {
            48 8D 0D ?? ?? ?? ??
            C7 44 24 ?? 48 31 C0 C3
            FF 15 ?? ?? ?? ??
            48 8B C8
            48 8D 15 ?? ?? ?? ??
            FF 15 ?? ?? ?? ??
            83 64 24 ?? 00
            4C 8D 4C 24 ??
            BF 04 00 00 00
            48 8B C8
            8B D7
            48 8B D8
            44 8D 47 ??
            FF 15 ?? ?? ?? ??
            44 8B C7
            48 8D 54 24 ??
            48 8B CB
            E8 ?? ?? ?? ??
            44 8B 44 24 ??
            4C 8D 4C 24 ??
            8B D7
            48 8B CB
            FF 15 ?? ?? ?? ??
            48 8B 05 ?? ?? ?? ??
        }
		$chunk_2 = {
            55
            8B EC
            51
            51
            57
            68 08 1A 41 00
            66 C7 45 ?? C2 14
            C6 45 ?? 00
            FF 15 ?? ?? ?? ??
            68 10 1A 41 00
            50
            FF 15 ?? ?? ?? ??
            83 65 ?? 00
            8B F8
            8D 45 ??
            50
            6A 40
            6A 03
            57
            FF 15 ?? ?? ?? ??
            6A 03
            8D 45 ??
            50
            57
            E8 ?? ?? ?? ??
            83 C4 0C
            8D 45 ??
            50
            FF 75 ??
            6A 03
            57
            FF 15 ?? ?? ?? ??
        }
		$chunk_3 = {
            48 8D 0D ?? ?? ?? ??
            C7 44 24 ?? 48 31 C0 C3
            FF 15 ?? ?? ?? ??
            48 8B C8
            48 8D 15 ?? ?? ?? ??
            FF 15 ?? ?? ?? ??
        }

	condition:
		any of them
}

rule SparklingGoblin_Mutex
{
	meta:
		author = "ESET Research"
		copyright = "ESET Research"
		description = "SparklingGoblin ChaCha20 loaders mutexes"
		date = "2021-05-20"
		reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		hash = "2EDBEA43F5C40C867E5B6BBD93CC972525DF598B"
		hash = "B6D245D3D49B06645C0578804064CE0C072CBE0F"
		hash = "8BE6D5F040D0085C62B1459AFC627707B0DE89CF"
		hash = "4668302969FE122874FB2447A80378DCB671C86B"
		hash = "9BDECB08E16A23D271D0A3E836D9E7F83D7E2C3B"
		hash = "9CE7650F2C08C391A35D69956E171932D116B8BD"

	strings:
		$mutex_1 = "kREwdFrOlvASgP4zWZyV89m6T2K0bIno"
		$mutex_2 = "v5EPQFOImpTLaGZes3Nl1JSKHku8AyCw"

	condition:
		any of them
}

private rule ssh_client : sshdoor
{
	meta:
		description = "Signature to match the clean (or not) OpenSSH client (ssh)"
		author = "Marc-Etienne M.Leveille"
		email = "leveille@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$usage = "usage: ssh ["
		$old_version = "-L listen-port:host:port"

	condition:
		$usage or $old_version
}

private rule ssh_daemon : sshdoor
{
	meta:
		description = "Signature to match the clean (or not) OpenSSH daemon (sshd)"
		author = "Marc-Etienne M.Leveille"
		email = "leveille@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$usage = "usage: sshd ["
		$old_version = "Listen on the specified port (default: 22)"

	condition:
		$usage or $old_version
}

private rule ssh_add : sshdoor
{
	meta:
		description = "Signature to match the clean (or not) OpenSSH add (ssh-add)"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$usage = "usage: %s [options] [file ...]\n"
		$log = "Could not open a connection to your authentication agent.\n"

	condition:
		$usage and $log
}

private rule ssh_askpass : sshdoor
{
	meta:
		description = "Signature to match the clean (or not) OpenSSH daemon (sshd)"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$pass = "Enter your OpenSSH passphrase:"
		$log = "Could not grab %s. A malicious client may be eavesdropping on you"

	condition:
		$pass and $log
}

private rule ssh_keygen : sshdoor
{
	meta:
		description = "Signature to match the clean (or not) OpenSSH keygen (ssh-keygen)"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$pass = "Enter new passphrase (empty for no passphrase):"
		$log = "revoking certificates by key ID requires specification of a CA key"

	condition:
		$pass and $log
}

private rule ssh_keyscan : sshdoor
{
	meta:
		description = "Signature to match the clean (or not) OpenSSH keyscan (ssh-keyscan)"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$usage = "usage: %s [-46Hv] [-f file] [-p port] [-T timeout] [-t type]"

	condition:
		$usage
}

private rule ssh_binary : sshdoor
{
	meta:
		description = "Signature to match any clean (or not) SSH binary"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"

	condition:
		ssh_client or ssh_daemon or ssh_add or ssh_askpass or ssh_keygen or ssh_keyscan
}

rule abafar
{
	meta:
		description = "Rule to detect Abafar family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$log_c = "%s:%s@%s"
		$log_d = "%s:%s from %s"

	condition:
		ssh_binary and any of them
}

rule akiva
{
	meta:
		description = "Rule to detect Akiva family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$log = /(To|From):\s(%s\s\-\s)?%s:%s\n/

	condition:
		ssh_binary and $log
}

rule alderaan
{
	meta:
		description = "Rule to detect Alderaan family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$log = /login\s(in|at):\s(%s\s)?%s:%s\n/

	condition:
		ssh_binary and $log
}

rule ando
{
	meta:
		description = "Rule to detect Ando family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$s1 = "%s:%s\n"
		$s2 = "HISTFILE"
		$i = "fopen64"
		$m1 = "cat "
		$m2 = "mail -s"

	condition:
		ssh_binary and all of ( $s* ) and ( $i or all of ( $m* ) )
}

rule anoat
{
	meta:
		description = "Rule to detect Anoat family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$log = "%s at: %s | user: %s, pass: %s\n"

	condition:
		ssh_binary and $log
}

private rule stack_string
{
	meta:
		description = "Rule to detect use of string-stacking"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$bp = /(\xC6\x45.{2}){25}/
		$bp_dw = /(\xC7\x45.{5}){20}/
		$bp_off = /(\xC6\x85.{5}){25}/
		$sp = /(\xC6\x44\x24.{2}){25}/
		$sp_off = /(\xC6\x84\x24.{5}){25}/

	condition:
		any of them
}

rule atollon
{
	meta:
		description = "Rule to detect Atollon family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$f1 = "PEM_read_RSA_PUBKEY"
		$f2 = "RAND_add"
		$log = "%s:%s"
		$rand = "/dev/urandom"

	condition:
		ssh_binary and stack_string and all of them
}

rule batuu
{
	meta:
		description = "Rule to detect Batuu family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$args = "ssh: ~(av[%d]: %s\n)"
		$log = "readpass: %s\n"

	condition:
		ssh_binary and any of them
}

rule bespin
{
	meta:
		description = "Rule to detect Bespin family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$log1 = "%Y-%m-%d %H:%M:%S"
		$log2 = "%s %s%s"
		$log3 = "[%s]"

	condition:
		ssh_binary and all of them
}

rule bonadan
{
	meta:
		description = "Rule to detect Bonadan family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$s1 = "g_server"
		$s2 = "mine.sock"
		$s3 = "tspeed"
		$e1 = "6106#x=%d#%s#%s#speed=%s"
		$e2 = "usmars.mynetgear.com"
		$e3 = "user=%s#os=%s#eip=%s#cpu=%s#mem=%s"

	condition:
		ssh_binary and any of them
}

rule borleias
{
	meta:
		description = "Rule to detect Borleias family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$log = "%Y-%m-%d %H:%M:%S [%s]"

	condition:
		ssh_binary and all of them
}

rule chandrila
{
	meta:
		description = "Rule to detect Chandrila family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$log = "S%s %s:%s"
		$magic = { 05 71 92 7D }

	condition:
		ssh_binary and all of them
}

rule coruscant
{
	meta:
		description = "Rule to detect Coruscant family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$s1 = "%s:%s@%s\n"
		$s2 = "POST"
		$s3 = "HTTP/1.1"

	condition:
		ssh_binary and all of them
}

rule crait
{
	meta:
		description = "Signature to detect Crait family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$i1 = "flock"
		$i2 = "fchmod"
		$i3 = "sendto"

	condition:
		ssh_binary and 2 of them
}

rule endor
{
	meta:
		description = "Rule to detect Endor family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$u = "user: %s"
		$p = "password: %s"

	condition:
		ssh_binary and $u and $p in ( @u .. @u + 20 )
}

rule jakuu
{
	meta:
		description = "Rule to detect Jakuu family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		notes = "Strings can be encrypted"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$dec = /GET\s\/\?(s|c)id=/
		$enc1 = "getifaddrs"
		$enc2 = "usleep"
		$ns = "gethostbyname"
		$log = "%s:%s"
		$rc4 = { A1 71 31 17 11 1A 22 27 55 00 66 A3 10 FE C2 10 22 32 6E 95 90 84 F9 11 73 62 95 5F 4D 3B DB DC }

	condition:
		ssh_binary and $log and $ns and ( $dec or all of ( $enc* ) or $rc4 )
}

rule kamino
{
	meta:
		description = "Rule to detect Kamino family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$s1 = "/var/log/wtmp"
		$s2 = "/var/log/secure"
		$s3 = "/var/log/auth.log"
		$s4 = "/var/log/messages"
		$s5 = "/var/log/audit/audit.log"
		$s6 = "/var/log/httpd-access.log"
		$s7 = "/var/log/httpd-error.log"
		$s8 = "/var/log/xferlog"
		$i1 = "BIO_f_base64"
		$i2 = "PEM_read_bio_RSA_PUBKEY"
		$i3 = "srand"
		$i4 = "gethostbyname"

	condition:
		ssh_binary and 5 of ( $s* ) and 3 of ( $i* )
}

rule kessel
{
	meta:
		description = "Rule to detect Kessel family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$rc4 = "Xee5chu1Ohshasheed1u"
		$s1 = "ssh:%s:%s:%s:%s"
		$s2 = "sshkey:%s:%s:%s:%s:%s"
		$s3 = "sshd:%s:%s"
		$i1 = "spy_report"
		$i2 = "protoShellCMD"
		$i3 = "protoUploadFile"
		$i4 = "protoSendReport"
		$i5 = "tunRecvDNS"
		$i6 = "tunPackMSG"

	condition:
		ssh_binary and ( 2 of ( $s* ) or 2 of ( $i* ) or $rc4 )
}

rule mimban
{
	meta:
		description = "Rule to detect Mimban family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$s1 = "<|||%s|||%s|||%d|||>"
		$s2 = />\|\|\|%s\|\|\|%s\|\|\|\d\|\|\|%s\|\|\|%s\|\|\|%s\|\|\|%s\|\|\|</
		$s3 = "-----BEGIN PUBLIC KEY-----"
		$i1 = "BIO_f_base64"
		$i2 = "PEM_read_bio_RSA_PUBKEY"
		$i3 = "gethostbyname"

	condition:
		ssh_binary and 2 of ( $s* ) and 2 of ( $i* )
}

rule ondaron
{
	meta:
		description = "Rule to detect Ondaron family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$daemon = "user:password --> %s:%s\n"
		$client = /user(,|:)(a,)?password@host \-\-> %s(,|:)(b,)?%s@%s\n/

	condition:
		ssh_binary and ( $daemon or $client )
}

rule polis_massa
{
	meta:
		description = "Rule to detect Polis Massa family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$log = /\b\w+(:|\s-+>)\s%s(:%d)?\s\t(\w+)?:\s%s\s\t(\w+)?:\s%s/

	condition:
		ssh_binary and $log
}

rule quarren
{
	meta:
		description = "Rule to detect Quarren family"
		author = "Hugo Porcher"
		email = "hugo.porcher@eset.com"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
		date = "2018-12-05"
		license = "BSD 2-Clause"

	strings:
		$log = "h: %s, u: %s, p: %s\n"

	condition:
		ssh_binary and $log
}

import "pe"

rule beds_plugin
{
	meta:
		Author = "Frédéric Vachon"
		Date = "2017-07-17"
		Description = "Stantinko BEDS' plugins"
		Reference = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	condition:
		pe.exports( "CheckDLLStatus" ) and pe.exports ( "GetPluginData" ) and pe.exports ( "InitializePlugin" ) and pe.exports ( "IsReleased" ) and pe.exports ( "ReleaseDLL" )
}

import "pe"

rule beds_dropper
{
	meta:
		Author = "Frédéric Vachon"
		Date = "2017-07-17"
		Description = "BEDS dropper"
		Reference = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	condition:
		pe.imphash( ) == "a7ead4ef90d9981e25728e824a1ba3ef"
}

rule facebook_bot
{
	meta:
		Author = "Frédéric Vachon"
		Date = "2017-07-17"
		Description = "Stantinko's Facebook bot"
		Reference = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "m_upload_pic&return_uri=https%3A%2F%2Fm.facebook.com%2Fprofile.php" fullword ascii
		$s2 = "D:\\work\\brut\\cms\\facebook\\facebookbot\\Release\\facebookbot.pdb" fullword ascii
		$s3 = "https%3A%2F%2Fm.facebook.com%2Fcomment%2Freplies%2F%3Fctoken%3D" fullword ascii
		$s4 = "reg_fb_gate=https%3A%2F%2Fm.facebook.com%2Freg" fullword ascii
		$s5 = "reg_fb_ref=https%3A%2F%2Fm.facebook.com%2Freg%2F" fullword ascii
		$s6 = "&return_uri_error=https%3A%2F%2Fm.facebook.com%2Fprofile.php" fullword ascii
		$x1 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36" fullword ascii
		$x2 = "registration@facebookmail.com" fullword ascii
		$x3 = "https://m.facebook.com/profile.php?mds=" fullword ascii
		$x4 = "https://upload.facebook.com/_mupload_/composer/?profile&domain=" fullword ascii
		$x5 = "http://staticxx.facebook.com/connect/xd_arbiter.php?version=42#cb=ff43b202c" fullword ascii
		$x6 = "https://upload.facebook.com/_mupload_/photo/x/saveunpublished/" fullword ascii
		$x7 = "m.facebook.com&ref=m_upload_pic&waterfall_source=" fullword ascii
		$x8 = "payload.commentID" fullword ascii
		$x9 = "profile.login" fullword ascii

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( 1 of ( $s* ) or 3 of ( $x* ) ) ) or ( all of them )
}

rule pds_plugins
{
	meta:
		Author = "Frédéric Vachon"
		Date = "2017-07-17"
		Description = "Stantinko PDS' plugins"
		Reference = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "std::_Vector_val<CHTTPPostItem *,std::allocator<CHTTPPostItem *> >" fullword ascii
		$s2 = "std::_Vector_val<CHTTPHeader *,std::allocator<CHTTPHeader *> >" fullword ascii
		$s3 = "std::vector<CHTTPHeader *,std::allocator<CHTTPHeader *> >" fullword ascii
		$s4 = "std::vector<CHTTPPostItem *,std::allocator<CHTTPPostItem *> >" fullword ascii
		$s5 = "CHTTPHeaderManager" fullword ascii
		$s6 = "CHTTPPostItemManager *" fullword ascii
		$s7 = "CHTTPHeaderManager *" fullword ascii
		$s8 = "CHTTPPostItemManager" fullword ascii
		$s9 = "CHTTPHeader" fullword ascii
		$s10 = "CHTTPPostItem" fullword ascii
		$s11 = "std::vector<CCookie *,std::allocator<CCookie *> >" fullword ascii
		$s12 = "std::_Vector_val<CCookie *,std::allocator<CCookie *> >" fullword ascii
		$s13 = "CCookieManager *" fullword ascii

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( 2 of ( $s* ) ) )
}

rule stantinko_pdb
{
	meta:
		Author = "Frédéric Vachon"
		Date = "2017-07-17"
		Description = "Stantinko malware family PDB path"
		Reference = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "D:\\work\\service\\service\\" ascii

	condition:
		all of them
}

rule stantinko_droppers
{
	meta:
		Author = "Marc-Etienne M.Léveillé"
		Date = "2017-07-17"
		Description = "Stantinko droppers"
		Reference = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = {55 8B EC 83 EC 08 53 56 BE 80 F4 45 00 57 81 EE 80 0E 41 00 56 E8 6D 23 00 00 56 8B D8 68 80 0E 41 00 53 89 5D F8 E8 65 73 00 00 8B 0D FC F5 45}
		$s2 = {7E 5E 7F 8C 08 46 00 00 AB 57 1A BB 91 5C 00 00 FA CC FD 76 90 3A 00 00}

	condition:
		uint16( 0 ) == 0x5A4D and 1 of them
}

import "pe"

rule stantinko_d3d
{
	meta:
		Author = "Marc-Etienne M.Léveillé"
		Date = "2017-07-17"
		Description = "Stantinko d3dadapter component"
		Reference = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	condition:
		pe.exports( "EntryPoint" ) and pe.exports ( "ServiceMain" ) and pe.imports ( "WININET.DLL" , "HttpAddRequestHeadersA" )
}

rule stantinko_ihctrl32
{
	meta:
		Author = "Marc-Etienne M.Léveillé"
		Date = "2017-07-17"
		Description = "Stantinko ihctrl32 component"
		Reference = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "ihctrl32.dll"
		$s2 = "win32_hlp"
		$s3 = "Ihctrl32Main"
		$s4 = "I%citi%c%size%s%c%ci%s"
		$s5 = "Global\\Intel_hctrl32"

	condition:
		2 of them
}

rule stantinko_wsaudio
{
	meta:
		Author = "Marc-Etienne M.Léveillé"
		Date = "2017-07-17"
		Description = "Stantinko wsaudio component"
		Reference = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "GetInterface"
		$s2 = "wsaudio.dll"
		$s3 = "Global\\Wsaudio_Initialize"
		$s4 = "SOFTWARE\\Classes\\%s.FieldListCtrl.1\\"

	condition:
		2 of them
}

rule stantinko_ghstore
{
	meta:
		Author = "Marc-Etienne M.Léveillé"
		Date = "2017-07-17"
		Description = "Stantinko ghstore component"
		Reference = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
		Source = "https://github.com/eset/malware-ioc/"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "G%cost%sSt%c%s%s%ce%sr" wide
		$s2 = "%cho%ct%sS%sa%c%s%crve%c" wide
		$s3 = "Par%c%ce%c%c%s" wide
		$s4 = "S%c%curity%c%s%c%s" wide
		$s5 = "Sys%c%s%c%c%su%c%s%clS%c%s%serv%s%ces" wide

	condition:
		3 of them
}

rule apt_Windows_TA410_Tendyron_dropper
{
	meta:
		description = "TA410 Tendyron Dropper"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2020-12-09"

	strings:
		$s1 = "Global\\{F473B3BE-08EE-4710-A727-9E248F804F4A}" wide
		$s2 = "Global\\8D32CCB321B2" wide
		$s3 = "Global\\E4FE94F75490" wide
		$s4 = "Program Files (x86)\\Internet Explorer\\iexplore.exe" wide
		$s5 = "\\RPC Control\\OLE" wide
		$s6 = "ALPC Port" wide

	condition:
		int16 ( 0 ) == 0x5A4D and 4 of them
}

rule apt_Windows_TA410_Tendyron_installer
{
	meta:
		description = "TA410 Tendyron Installer"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2020-12-09"

	strings:
		$s1 = "Tendyron" wide
		$s2 = "OnKeyToken_KEB.dll" wide
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "Global\\8D32CCB321B2"
		$s5 = "\\RTFExploit\\"

	condition:
		int16 ( 0 ) == 0x5A4D and 3 of them
}

rule apt_Windows_TA410_Tendyron_Downloader
{
	meta:
		description = "TA410 Tendyron Downloader"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2020-12-09"

	strings:
		$chunk_1 = {
            8A 10
            80 F2 5C
            80 C2 5C
            88 10
            40
            83 E9 01
            75 ??
        }
		$s1 = "startModule" fullword

	condition:
		int16 ( 0 ) == 0x5A4D and all of them
}

rule apt_Windows_TA410_X4_strings
{
	meta:
		description = "Matches various strings found in TA410 X4"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2020-10-09"

	strings:
		$s1 = "[X]InLoadSC" ascii wide nocase
		$s3 = "MachineKeys\\Log\\rsa.txt" ascii wide nocase
		$s4 = "MachineKeys\\Log\\output.log" ascii wide nocase

	condition:
		any of them
}

rule apt_Windows_TA410_X4_hash_values
{
	meta:
		description = "Matches X4 hash function found in TA410 X4"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2020-10-09"

	strings:
		$s1 = {D1 10 76 C2 B6 03}
		$s2 = {71 3E A8 0D}
		$s3 = {DC 78 94 0E}
		$s4 = {40 0D E7 D6 06}
		$s5 = {83 BB FD E8 06}
		$s6 = {92 9D 9B FF EC 03}
		$s7 = {DD 0E FC FA F5 03}
		$s8 = {15 60 1E FB F5 03}

	condition:
		uint16( 0 ) == 0x5a4d and 4 of them
}

rule apt_Windows_TA410_X4_hash_fct
{
	meta:
		description = "Matches X4 hash function found in TA410 X4"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2020-10-09"

	strings:
		$chunk_1 = {
            0F B6 01
            84 C0
            74 ??
            48 69 D2 83 00 00 00
            48 0F BE C0
            48 03 D0
            48 FF C1
            E9 ?? ?? ?? ??
        }

	condition:
		uint16( 0 ) == 0x5a4d and any of them
}

rule apt_Windows_TA410_LookBack_decryption
{
	meta:
		description = "Matches encryption/decryption function used by LookBack."
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$initialize = {
            8B C6           //mov eax, esi
            99              //cdq
            83 E2 03        //and edx, 3
            03 C2           //add eax, edx
            C1 F8 02        //sar eax, 2
            8A C8           //mov cl, al
            02 C0           //add al, al
            02 C8           //add cl, al
            88 4C 34 10         //mov byte ptr [esp + esi + 0x10], cl
            46              //inc esi
            81 FE 00 01 00 00       //cmp esi, 0x100
            72 ??
        }
		$generate = {
            8A 94 1C 10 01 ?? ??    //mov dl, byte ptr [esp + ebx + 0x110]
            8D 8C 24 10 01 ?? ??    //lea ecx, [esp + 0x110]
            0F B6 C3        //movzx eax, bl
            0F B6 44 04 10      //movzx eax, byte ptr [esp + eax + 0x10]
            32 C2           //xor al, dl
            02 F0           //add dh, al
            0F B6 C6        //movzx eax, dh
            03 C8           //add ecx, eax
            0F B6 01        //movzx eax, byte ptr [ecx]
            88 84 1C 10 01 ?? ??    //mov byte ptr [esp + ebx + 0x110], al
            43              //inc ebx
            88 11           //mov byte ptr [ecx], dl
            81 FB 00 06 00 00       //cmp ebx, 0x600
            72 ??           //jb 0x10025930
        }
		$decrypt = {
            0F B6 C6        //movzx eax, dh
            8D 8C 24 10 01 ?? ??    //lea ecx, [esp + 0x110]
            03 C8           //add ecx, eax
            8A 19           //mov bl, byte ptr [ecx]
            8A C3           //mov al, bl
            02 C6           //add al, dh
            FE C6           //inc dh
            02 F8           //add bh, al
            0F B6 C7        //movzx eax, bh
            8A 94 04 10 01 ?? ??    //mov dl, byte ptr [esp + eax + 0x110]
            88 9C 04 10 01 ?? ??    //mov byte ptr [esp + eax + 0x110], bl
            88 11           //mov byte ptr [ecx], dl
            0F B6 C2        //movzx eax, dl
            0F B6 CB        //movzx ecx, bl
            33 C8           //xor ecx, eax
            8A 84 0C 10 01 ?? ??    //mov al, byte ptr [esp + ecx + 0x110]
            30 04 2E        //xor byte ptr [esi + ebp], al
            46              //inc esi
            3B F7           //cmp esi, edi
            7C ??           //jl 0x10025980
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule apt_Windows_TA410_LookBack_loader
{
	meta:
		description = "Matches the modified function in LookBack libcurl loader."
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$chunk_1 = {
            FF 15 ?? ?? ?? ??      //call dword ptr [0x100530e0]
            6A 40          //push 0x40
            68 00 10 00 00     //push 0x1000
            68 F0 04 00 00     //push 0x4f0
            6A 00          //push 0
            FF 15 ?? ?? ?? ??      //call dword ptr [0x100530d4]
            8B E8          //mov ebp, eax
            B9 3C 01 00 00     //mov ecx, 0x13c
            BE 60 30 06 10     //mov esi, 0x10063060
            8B FD          //mov edi, ebp
            68 F0 04 00 00     //push 0x4f0
            F3 A5          //rep movsd dword ptr es:[edi], dword ptr [esi]
            55             //push ebp
            E8 ?? ?? ?? ??     //call 0x100258d0
            8B 0D ?? ?? ?? ??      //mov ecx, dword ptr [0x100530e4]
            A1 ?? ?? ?? ??     //mov eax, dword ptr [0x100530c8]
            68 6C 02 00 00     //push 0x26c
            89 4C 24 ??        //mov dword ptr [esp + 0x1c], ecx
            89 44 24 ??        //mov dword ptr [esp + 0x20], eax
            FF 15 ?? ?? ?? ??      //call dword ptr [0x10063038]
            8B D8          //mov ebx, eax
            B9 9B 00 00 00     //mov ecx, 0x9b
            BE 50 35 06 10     //mov esi, 0x10063550
            8B FB          //mov edi, ebx
            68 6C 02 00 00      //push 0x26c
            F3 A5          //rep movsd dword ptr es:[edi], dword ptr [esi]
            53             //push ebx
            E8 ?? ?? ?? ??     //call 0x100258d0
            83 C4 14           //add esp, 0x14
            8D 44 24 ??        //lea eax, [esp + 0x10]
            50             //push eax
            53             //push ebx
            8D 44 24 ??        //lea eax, [esp + 0x3c]
            50             //push eax
            A1 ?? ?? ?? ??     //mov eax, dword ptr [0x10063058]
            FF 74 24 ??        //push dword ptr [esp + 0x28]
            03 C5          //add eax, ebp
            FF D0          //call eax
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

import "pe"

rule apt_Windows_TA410_LookBack_strings
{
	meta:
		description = "Matches multiple strings and export names in TA410 LookBack."
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$s1 = "SodomMainFree" ascii wide
		$s2 = "SodomMainInit" ascii wide
		$s3 = "SodomNormal.bin" ascii wide
		$s4 = "SodomHttp.bin" ascii wide
		$s5 = "sodom.ini" ascii wide
		$s6 = "SodomMainProc" ascii wide

	condition:
		uint16( 0 ) == 0x5a4d and ( 2 of them or pe.exports ( "SodomBodyLoad" ) or pe.exports ( "SodomBodyLoadTest" ) )
}

rule apt_Windows_TA410_LookBack_HTTP
{
	meta:
		description = "Matches LookBack's hardcoded HTTP request"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$s1 = "POST http://%s/status.php?r=%d%d HTTP/1.1\x0d\nAccept: text/html, application/xhtml+xml, */*\x0d\nAccept-Language: en-us\x0d\nUser-Agent: %s\x0d\nContent-Type: application/x-www-form-urlencoded\x0d\nAccept-Encoding: gzip, deflate\x0d\nHost: %s\x0d\nContent-Length: %d\x0d\nConnection: Keep-Alive\x0d\nCache-Control: no-cache\x0d\n\x0d\n" ascii wide
		$s2 = "id=1&op=report&status="

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule apt_Windows_TA410_LookBack_magic
{
	meta:
		description = "Matches message header creation in LookBack."
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$s1 = {
            C7 03 C2 2E AB 48           //mov dword ptr [ebx], 0x48ab2ec2
            ( A1 | 8B 15 ) ?? ?? ?? ??      //mov (eax | edx), x
            [0-1]               //push ebp
            89 ?3 04            //mov dword ptr [ebc + 4], reg
            8B 4? 24 ??             //mov reg, dword ptr [esp + X]
            89 4? 08            //mov dword ptr [ebx + 8], ??
            89 ?? 0C            //mov dword ptr [ebx + 0xc], ??
            8B 4? 24 ??             //mov reg, dword ptr [esp + X]
            [1-2]               //push 1 or 2 args
            E8 ?? ?? ?? ??          //call
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_loader_strings
{
	meta:
		description = "Matches various strings found in TA410 FlowCloud first stage."
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$key = "y983nfdicu3j2dcn09wur9*^&initialize(y4r3inf;'fdskaf'SKF"
		$s2 = "startModule" fullword
		$s4 = "auto_start_module" wide
		$s5 = "load_main_module_after_install" wide
		$s6 = "terminate_if_fail" wide
		$s7 = "clear_run_mru" wide
		$s8 = "install_to_vista" wide
		$s9 = "load_ext_module" wide
		$s10 = "sll_only" wide
		$s11 = "fail_if_already_installed" wide
		$s12 = "clear_hardware_info" wide
		$s13 = "av_check" wide fullword
		$s14 = "check_rs" wide
		$s15 = "check_360" wide
		$s16 = "responsor.dat" wide ascii
		$s17 = "auto_start_after_install_check_anti" wide fullword
		$s18 = "auto_start_after_install" wide fullword
		$s19 = "extern_config.dat" wide fullword
		$s20 = "is_hhw" wide fullword
		$s21 = "SYSTEM\\Setup\\PrintResponsor" wide
		$event = "Global\\Event_{201a283f-e52b-450e-bf44-7dc436037e56}" wide ascii
		$s23 = "invalid encrypto hdr while decrypting"

	condition:
		uint16( 0 ) == 0x5a4d and ( $key or $event or 5 of ( $s* ) )
}

rule apt_Windows_TA410_FlowCloud_header_decryption
{
	meta:
		description = "Matches the function used to decrypt resources headers in TA410 FlowCloud"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"

	strings:
		$chunk_1 = {
            8B 1E
            8B CF
            D3 CB
            8D 0C 28
            83 C7 06
            30 18
            8B 1E
            D3 CB
            8D 0C 02
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            83 C0 06
            30 58 ??
            8B 1E
            D3 CB
            30 58 ??
            83 FF 10
            72 ??
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_dll_hijacking_strings
{
	meta:
		description = "Matches filenames inside TA410 FlowCloud malicious DLL."
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$dat1 = "emedres.dat" wide
		$dat2 = "vviewres.dat" wide
		$dat3 = "setlangloc.dat" wide
		$dll1 = "emedres.dll" wide
		$dll2 = "vviewres.dll" wide
		$dll3 = "setlangloc.dll" wide

	condition:
		uint16( 0 ) == 0x5a4d and ( all of ( $dat* ) or all of ( $dll* ) )
}

rule apt_Windows_TA410_FlowCloud_malicious_dll_antianalysis
{
	meta:
		description = "Matches anti-analysis techniques used in TA410 FlowCloud hijacking DLL."
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$chunk_1 = {
            33 C0
            E8 ?? ?? ?? ??
            83 C0 10
            3D 00 00 00 80
            7D 01
            EB FF
            E0 50
            C3
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

import "pe"

rule apt_Windows_TA410_FlowCloud_pdb
{
	meta:
		description = "Matches PDB paths found in TA410 FlowCloud."
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	condition:
		uint16( 0 ) == 0x5a4d and ( pe.pdb_path contains "\\FlowCloud\\trunk\\" or pe.pdb_path contains "\\flowcloud\\trunk\\" )
}

rule apt_Windows_TA410_FlowCloud_shellcode_decryption
{
	meta:
		description = "Matches the decryption function used in TA410 FlowCloud self-decrypting DLL"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$chunk_1 = {
            33 D2
            8B 45 ??
            BB 6B 04 00 00
            F7 F3
            81 C2 A8 01 00 00
            81 E2 FF 00 00 00
            8B 7D ??
            33 C9
            EB ??
            30 14 39
            00 14 39
            41
            3B 4D ??
            72 ??
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_fcClient_strings
{
	meta:
		description = "Strings found in fcClient/rescure.dat module."
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$s1 = "df257bdd-847c-490e-9ef9-1d7dc883d3c0"
		$s2 = "\\{2AFF264E-B722-4359-8E0F-947B85594A9A}"
		$s3 = "Global\\{26C96B51-2B5D-4D7B-BED1-3DCA4848EDD1}" wide
		$s4 = "{804423C2-F490-4ac3-BFA5-13DEDE63A71A}" wide
		$s5 = "{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}" wide
		$s6 = "XXXModule_func.dll"
		$driver1 = "\\drivers\\hidmouse.sys" wide fullword
		$driver2 = "\\drivers\\hidusb.sys" wide fullword

	condition:
		uint16( 0 ) == 0x5a4d and ( any of ( $s* ) or all of ( $driver* ) )
}

rule apt_Windows_TA410_FlowCloud_fcClientDll_strings
{
	meta:
		description = "Strings found in fcClientDll/responsor.dat module."
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$s1 = "http://%s/html/portlet/ext/draco/resources/draco_manager.swf/[[DYNAMIC]]/1"
		$s2 = "Cookie: COOKIE_SUPPORT=true; JSESSIONID=5C7E7A60D01D2891F40648DAB6CB3DF4.jvm1; COMPANY_ID=10301; ID=666e7375545678695645673d; PASSWORD=7a4b48574d746470447a303d; LOGIN=6863303130; SCREEN_NAME=4a2b455377766b657451493d; GUEST_LANGUAGE_ID=en-US"
		$fc_msg = ".fc_net.msg"
		$s4 = "\\pipe\\namedpipe_keymousespy_english" wide
		$s5 = "8932910381748^&*^$58876$%^ghjfgsa413901280dfjslajflsdka&*(^7867=89^&*F(^&*5678f5ds765f76%&*%&*5"
		$s6 = "cls_{CACB140B-0B82-4340-9B05-7983017BA3A4}" wide
		$s7 = "HTTP/1.1 200 OK\x0d\nServer: Apache-Coyote/1.1\x0d\nPragma: No-cache\x0d\nCache-Control: no-cache\x0d\nExpires: Thu, 01 Jan 1970 08:00:00 CST\x0d\nLast-Modified: Fri, 27 Apr 2012 08:11:04 GMT\x0d\nContent-Type: application/xml\x0d\nContent-Length: %d\x0d\nDate: %s GMT"
		$sql1 = "create table if not exists table_filed_space"
		$sql2 = "create table if not exists clipboard"
		$sql3 = "create trigger if not exists file_after_delete after delete on file"
		$sql4 = "create trigger if not exists file_data_after_insert after insert on file_data"
		$sql5 = "create trigger if not exists file_data_after_delete after delete on file_data"
		$sql6 = "create trigger if not exists file_data_after_update after update on file_data"
		$sql7 = "insert into file_data(file_id, ofs, data, status)"

	condition:
		uint16( 0 ) == 0x5a4d and ( any of ( $s* ) or #fc_msg >= 8 or 4 of ( $sql* ) )
}

rule apt_Windows_TA410_Rootkit_strings
{
	meta:
		description = "Strings found in TA410's Rootkit"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	strings:
		$driver1 = "\\Driver\\kbdclass" wide
		$driver2 = "\\Driver\\mouclass" wide
		$device1 = "\\Device\\KeyboardClass0" wide
		$device2 = "\\Device\\PointerClass0" wide
		$driver3 = "\\Driver\\tcpip" wide
		$device3 = "\\Device\\tcp" wide
		$driver4 = "\\Driver\\nsiproxy" wide
		$device4 = "\\Device\\Nsi" wide
		$reg1 = "\\Registry\\Machine\\SYSTEM\\Setup\\AllowStart\\ceipCommon" wide
		$reg2 = "RHH%d" wide
		$reg3 = "RHP%d" wide
		$s1 = "\\SystemRoot\\System32\\drivers\\hidmouse.sys" wide

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $s1 , $reg* ) and ( all of ( $driver* ) or all of ( $device* ) )
}

import "pe"

rule apt_Windows_TA410_FlowCloud_v5_resources
{
	meta:
		description = "Matches sequence of PE resource IDs found in TA410 FlowCloud version 5.0.2"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	condition:
		uint16( 0 ) == 0x5a4d and pe.number_of_resources >= 13 and for 12 resource in pe.resources : ( resource.type == 10 and resource.language == 1033 and ( resource.name_string == "1\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x000\x00" or resource.name_string == "1\x000\x000\x001\x00" or resource.name_string == "1\x000\x001\x00" or resource.name_string == "1\x000\x002\x00" or resource.name_string == "1\x000\x003\x00" or resource.name_string == "1\x000\x004\x00" or resource.name_string == "1\x000\x005\x00" or resource.name_string == "1\x000\x006\x00" or resource.name_string == "1\x000\x007\x00" or resource.name_string == "1\x000\x008\x00" or resource.name_string == "1\x000\x009\x00" or resource.name_string == "1\x001\x000\x00" or resource.name_string == "2\x000\x000\x000\x00" or resource.name_string == "2\x000\x000\x001\x00" ) )
}

import "pe"

rule apt_Windows_TA410_FlowCloud_v4_resources
{
	meta:
		description = "Matches sequence of PE resource IDs found in TA410 FlowCloud version 4.1.3"
		reference = "https://www.welivesecurity.com/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		author = "ESET Research"
		date = "2021-10-12"

	condition:
		uint16( 0 ) == 0x5a4d and pe.number_of_resources >= 6 and for 5 resource in pe.resources : ( resource.type == 10 and resource.language == 1033 and ( resource.name_string == "1\x000\x000\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x001\x00" or resource.name_string == "1\x000\x000\x000\x002\x00" or resource.name_string == "1\x000\x000\x000\x003\x00" or resource.name_string == "1\x000\x000\x000\x004\x00" or resource.name_string == "1\x000\x000\x000\x005\x00" or resource.name_string == "1\x000\x001\x000\x000\x00" ) )
}

rule generic_carbon
{
	meta:
		author = "ESET Research"
		date = "2017-03-30"
		description = "Turla Carbon malware"
		reference = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = "ModStart"
		$t1 = "STOP|OK"
		$t2 = "STOP|KILL"

	condition:
		( uint16( 0 ) == 0x5a4d ) and ( 1 of ( $s* ) ) and ( 1 of ( $t* ) )
}

import "pe"

rule carbon_metadata
{
	meta:
		author = "ESET Research"
		date = "2017-03-30"
		description = "Turla Carbon malware"
		reference = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	condition:
		(pe.version_info [ "InternalName" ] contains "SERVICE.EXE" or pe.version_info [ "InternalName" ] contains "MSIMGHLP.DLL" or pe.version_info [ "InternalName" ] contains "MSXIML.DLL" ) and pe.version_info [ "CompanyName" ] contains "Microsoft Corporation"
}

import "pe"

rule Gazer_certificate_subject
{
	meta:
		author = "ESET Research"
		date = "2017-08-30"
		description = "Turla Gazer malware"
		reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	condition:
		for any i in ( 0 .. pe.number_of_signatures - 1 ) : ( pe.signatures [ i ] . subject contains "Solid Loop" or pe.signatures [ i ] . subject contains "Ultimate Computer Support" )
}

rule Gazer_certificate
{
	meta:
		author = "ESET Research"
		date = "2017-08-30"
		description = "Turla Gazer malware"
		reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$certif1 = {52 76 a4 53 cd 70 9c 18 da 65 15 7e 5f 1f de 02}
		$certif2 = {12 90 f2 41 d9 b2 80 af 77 fc da 12 c6 b4 96 9c}

	condition:
		( uint16( 0 ) == 0x5a4d ) and 1 of them and filesize < 2MB
}

rule Gazer_logfile_name
{
	meta:
		author = "ESET Research"
		date = "2017-08-30"
		description = "Turla Gazer malware"
		reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = "CVRG72B5.tmp.cvr"
		$s2 = "CVRG1A6B.tmp.cvr"
		$s3 = "CVRG38D9.tmp.cvr"

	condition:
		( uint16( 0 ) == 0x5a4d ) and 1 of them
}

import "pe"

private rule not_ms
{
	condition:
		not for any i in ( 0 .. pe.number_of_signatures - 1 ) : ( pe.signatures [ i ] . issuer contains "Microsoft Corporation" )
}

rule turla_outlook_gen
{
	meta:
		author = "ESET Research"
		date = "05-09-2018"
		description = "Turla Outlook malware"
		version = 2
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = "Outlook Express" ascii wide
		$s2 = "Outlook watchdog" ascii wide
		$s3 = "Software\\RIT\\The Bat!" ascii wide
		$s4 = "Mail Event Window" ascii wide
		$s5 = "Software\\Mozilla\\Mozilla Thunderbird\\Profiles" ascii wide
		$s6 = "%%PDF-1.4\n%%%c%c\n" ascii wide
		$s7 = "%Y-%m-%dT%H:%M:%S+0000" ascii wide
		$s8 = "rctrl_renwnd32" ascii wide
		$s9 = "NetUIHWND" ascii wide
		$s10 = "homePostalAddress" ascii wide
		$s11 = "/EXPORT;OVERRIDE;START=-%d;END=-%d;FOLDER=%s;OUT=" ascii wide
		$s12 = "Re:|FWD:|AW:|FYI:|NT|QUE:" ascii wide
		$s13 = "IPM.Note" ascii wide
		$s14 = "MAPILogonEx" ascii wide
		$s15 = "pipe\\The Bat! %d CmdLine" ascii wide
		$s16 = "PowerShellRunner.dll" ascii wide
		$s17 = "cmd container" ascii wide
		$s18 = "mapid.tlb" ascii wide nocase
		$s19 = "Content-Type: F)*+" ascii wide fullword

	condition:
		not_ms and 5 of them
}

rule turla_outlook_filenames
{
	meta:
		author = "ESET Research"
		date = "22-08-2018"
		description = "Turla Outlook filenames"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = "mapid.tlb"
		$s2 = "msmime.dll"
		$s3 = "scawrdot.db"

	condition:
		any of them
}

rule turla_outlook_log
{
	meta:
		author = "ESET Research"
		date = "22-08-2018"
		description = "First bytes of the encrypted Turla Outlook logs"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = {01 87 C9 75 C8 69 98 AC E0 C9 7B [21] EB BB 60 BB 5A}

	condition:
		$s1 at 0
}

import "pe"

rule turla_outlook_exports
{
	meta:
		author = "ESET Research"
		date = "22-08-2018"
		description = "Export names of Turla Outlook Malware"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	condition:
		(pe.exports ( "install" ) or pe.exports ( "Install" ) ) and pe.exports ( "TBP_Initialize" ) and pe.exports ( "TBP_Finalize" ) and pe.exports ( "TBP_GetName" ) and pe.exports ( "DllRegisterServer" ) and pe.exports ( "DllGetClassObject" )
}

rule turla_outlook_pdf
{
	meta:
		author = "ESET Research"
		date = "22-08-2018"
		description = "Detect PDF documents generated by Turla Outlook malware"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = "Adobe PDF Library 9.0" ascii wide nocase
		$s2 = "Acrobat PDFMaker 9.0" ascii wide nocase
		$s3 = {FF D8 FF E0 00 10 4A 46 49 46}
		$s4 = {00 3F 00 FD FC A2 8A 28 03 FF D9}
		$s5 = "W5M0MpCehiHzreSzNTczkc9d" ascii wide nocase
		$s6 = "PDF-1.4" ascii wide nocase

	condition:
		5 of them
}

rule outlook_misty1
{
	meta:
		author = "ESET Research"
		date = "22-08-2018"
		description = "Detects the Turla MISTY1 implementation"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$o1 = {81 E7 FF 01 00 00}
		$s1 = {C1 E1 09}
		$s2 = {66 33 C6}
		$s3 = {C1 E8 07}
		$o2 = {8B 11 8D 04 1F 50 03 D3 8D 4D C4}

	condition:
		$o2 and for all i in ( 1 .. #o1 ) : ( for all of ( $s* ) : ( $ in ( @o1 [ i ] -500 .. @o1 [ i ] + 500 ) ) )
}

import "elf"

rule libkeyutils_with_ctor
{
	meta:
		description = "This rule detects if a libkeyutils.so shared library has a potentially malicious function to be called when loaded, either via a glibc constructor (DT_INIT + .ctors) or an initializer function in DT_INIT_ARRAY."
		author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
		copyright = "ESET, spol. s r.o."
		license = "BSD 2-Clause"
		date = "2024-02-01"
		reference = "https://www.welivesecurity.com"
		source = "https://github.com/eset/malware-ioc/"
		hash = "e7debd6e453192ad8376db5bab03ed0d87566591"
		version = 2
		last_modified = "2024-04-29"

	strings:
		$libname = "libkeyutils.so.1"

	condition:
		for any ptr_size in ( 4 , 8 ) : ( ( ( ptr_size == 4 and elf.machine == elf.EM_386 ) or ( ptr_size == 8 and elf.machine == elf.EM_X86_64 ) ) and for any d in elf.dynamic : ( d.type == elf.DT_SONAME and ( for any s in elf.sections : ( s.name == ".dynstr" and $libname at ( s.offset + d.val ) ) or for any s in elf.dynamic : ( s.type == elf.DT_STRTAB and $libname at ( s.val + d.val ) ) ) ) and ( for any s in elf.sections : ( s.name == ".ctors" and s.size > 2 * ptr_size ) or for any d in elf.dynamic : ( d.type == elf.DT_INIT_ARRAYSZ and d.val > ptr_size ) ) )
}

rule Ebury_v1_7_crypto
{
	meta:
		description = "This rule detects the strings decryption routine in Ebury v1.7 and v1.8"
		author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
		copyright = "ESET, spol. s r.o."
		license = "BSD 2-Clause"
		date = "2023-08-01"
		reference = "https://www.welivesecurity.com"
		source = "https://github.com/eset/malware-ioc/"
		hash = "e7debd6e453192ad8376db5bab03ed0d87566591"
		version = 1
		last_modified = "2024-04-29"

	strings:
		$64 = {
            48 69 ( 9C 24 ?? ?? ?? ?? | 5C 24 ?? | D2) 6D 4E C6 41 //  imul    rbx, [rsp+_buf], 41C64E6Dh
            8B (0C 16 | 34 07)                      //  mov     ecx, [rsi+rdx]
            48 81 C? 39 30 00 00                    //  add     rbx, 12345
            ( 31 D? |                               //  xor     ecx, ebx
              31 D? 48 89 9C 24 ?? ?? ?? ?? |       //  mov     [rsp+_buf], rbx
              31 D? 48 89 5C 24 ?? )                //  ^ optional
            89 (0C 10 | 34 01)                      //  mov     [rax+rdx], ecx
            48 83 C? 04                             //  add     rdx, 4
            48 (81 FA | 3D ) ?? ?? ?? ??            //  cmp     rdx, _size
            75 D?                                   //  jnz     short _begin
        }
		$32 = {
            69 C9 6D 4E C6 41      // imul    ecx, 41C64E6Dh
            8B B4 1A ?? ?? ?? ??   // mov     esi, [edx+ebx+_data]
            81 C1 39 30 00 00      // add     ecx, 12345
            31 CE                  // xor     esi, ecx
            89 34 10               // mov     [eax+edx], esi
            83 C2 04               // add     edx, 4
            81 FA ?? ?? ?? ??      // cmp     edx, _size
            75 DD                  // jnz     short loc_69A5
        }

	condition:
		any of them
}

import "elf"

private rule ApacheModule
{
	meta:
		description = "Apache 2.4 module ELF shared library"
		author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
		copyright = "ESET, spol. s r.o."
		license = "BSD 2-Clause"
		date = "2024-04-27"
		reference = "https://www.welivesecurity.com"
		source = "https://github.com/eset/malware-ioc/"
		hash = "e39667aa137e315bc26eaef791ccab52938fd809"
		version = 1
		last_modified = "2024-04-27"

	strings:
		$magic = "42PA"

	condition:
		for any s in elf.dynsym : ( s.type == elf.STT_OBJECT and for any seg in elf.segments : ( seg.type == elf.PT_LOAD and s.value >= seg.virtual_address and s.value < ( seg.virtual_address + seg.file_size ) and $magic at ( s.value - seg.virtual_address + seg.offset ) + 0x28 ) )
}

rule HelimodProxy
{
	meta:
		description = "HelimodProxy malicious Apache module"
		author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
		copyright = "ESET, spol. s r.o."
		license = "BSD 2-Clause"
		date = "2024-04-27"
		reference = "https://www.welivesecurity.com"
		source = "https://github.com/eset/malware-ioc/"
		hash = "e39667aa137e315bc26eaef791ccab52938fd809"
		version = 1
		last_modified = "2024-04-27"

	strings:
		$1 = "secret\x00%s:%u"
		$2 = "/%s/%s/%s%s"
		$3 = "ad\x00pmt"
		$4 = "mod_dir.c"
		$5 = "pmtad"

	condition:
		ApacheModule and ( $1 or ( $2 and $3 ) or ( $4 and $5 ) )
}

rule HelimodRedirect
{
	meta:
		description = "HelimodRedirect malicious Apache module"
		author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
		copyright = "ESET, spol. s r.o."
		license = "BSD 2-Clause"
		date = "2024-04-27"
		reference = "https://www.welivesecurity.com"
		source = "https://github.com/eset/malware-ioc/"
		hash = "e39667aa137e315bc26eaef791ccab52938fd809"
		version = 1
		last_modified = "2024-04-27"

	strings:
		$h1 = "secret\x00%s:%"
		$h2 = "$!%#!$"
		$h3 = "mod_security2.c"
		$r1 = "%s?DOM=%s&URI=%s"
		$r2 = "REDIRECT_URL"

	condition:
		ApacheModule and any of ( $h* ) and any of ( $r* )
}

rule HelimodSteal
{
	meta:
		description = "HelimodSteal malicious Apache module"
		author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
		copyright = "ESET, spol. s r.o."
		license = "BSD 2-Clause"
		date = "2024-04-27"
		reference = "https://www.welivesecurity.com"
		source = "https://github.com/eset/malware-ioc/"
		hash = "e39667aa137e315bc26eaef791ccab52938fd809"
		version = 2
		last_modified = "2024-04-27"

	strings:
		$h1 = "secret\x00%s:%"
		$h2 = "$!%#!$"
		$h3 = "mod_security2.c"
		$s1 = "p0sT5n1F3r"
		$s2 = "ENGINE_ON"
		$s3 = "POST /"

	condition:
		ApacheModule and any of ( $h* ) and any of ( $s* )
}

rule onimiki
{
	meta:
		description = "Linux/Onimiki malicious DNS server"
		malware = "Linux/Onimiki"
		operation = "Windigo"
		author = "Olivier Bilodeau <bilodeau@eset.com>"
		created = "2014-02-06"
		reference = "http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf"
		contact = "windigo@eset.sk"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"

	strings:
		$a1 = {43 0F B6 74 2A 0E 43 0F  B6 0C 2A 8D 7C 3D 00 8D}
		$a2 = {74 35 00 8D 4C 0D 00 89  F8 41 F7 E3 89 F8 29 D0}
		$a3 = {D1 E8 01 C2 89 F0 C1 EA  04 44 8D 0C 92 46 8D 0C}
		$a4 = {8A 41 F7 E3 89 F0 44 29  CF 29 D0 D1 E8 01 C2 89}
		$a5 = {C8 C1 EA 04 44 8D 04 92  46 8D 04 82 41 F7 E3 89}
		$a6 = {C8 44 29 C6 29 D0 D1 E8  01 C2 C1 EA 04 8D 04 92}
		$a7 = {8D 04 82 29 C1 42 0F B6  04 21 42 88 84 14 C0 01}
		$a8 = {00 00 42 0F B6 04 27 43  88 04 32 42 0F B6 04 26}
		$a9 = {42 88 84 14 A0 01 00 00  49 83 C2 01 49 83 FA 07}

	condition:
		all of them
}
