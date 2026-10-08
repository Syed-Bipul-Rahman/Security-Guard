/*
 * 91 rules selected from https://github.com/chronicle/GCTI
 * at commit 1c5fd42b1895098527fde00c2d9757edf6b303bb
 * License: Apache-2.0 (see LICENSES.txt next to this file)
 * Modified by Guard: rules were selected, deduplicated and reformatted
 * (data/yara/README.md says how); rule logic is unchanged.
 */

rule CobaltStrike_Resources_Artifact32_and_Resources_Dropper_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.exe,.dll,big.exe,big.dll} and resources/dropper.exe signature for versions 1.49 to 3.14"
		hash = "40fc605a8b95bbd79a3bd7d9af73fbeebe3fada577c99e7a111f6168f6a0d37a"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$payloadDecoder = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 18 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 03 [2] 0F B6 00 31 ?? 88 ?? 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 12 }

	condition:
		any of them
}

rule CobaltStrike_Resources_Artifact32_v3_1_and_v3_2
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,svc.exe,big.exe,big.dll,bigsvc.exe} and resources/artifact32uac(alt).dll signature for versions 3.1 and 3.2"
		hash = "4f14bcd7803a8e22e81e74d6061d0df9e8bac7f96f1213d062a29a8523ae4624"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 ?? 8A ?? 4? 88 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Artifact32_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,big.exe,big.dll,bigsvc.exe} signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x and resources/artifact32uac.dll for v3.14 and v4.0"
		hash = "888bae8d89c03c1d529b04f9e4a051140ce3d7b39bc9ea021ad9fc7c9f467719"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$pushFmtStr = {	C7 [3] 5C 00 00 00 C7 [3] 65 00 00 00 C7 [3] 70 00 00 00 C7 [3] 69 00 00 00 C7 [3] 70 00 00 00 F7 F1 C7 [3] 5C 00 00 00  C7 [3] 2E 00 00 00 C7 [3] 5C 00 00 00 }
		$fmtStr = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"

	condition:
		all of them
}

rule CobaltStrike_Resources_Artifact32svc_Exe_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe and resources/artifact32uac(alt).exe signature for versions v1.49 to v3.14"
		hash = "323ddf9623368b550def9e8980fde0557b6fe2dcd945fda97aa3b31c6c36d682"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$decoderFunc = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [5] 8B [2] 89 ?? C1 [2] C1 [2] 01 ?? 83 [2] 29 ?? 03 [5] 31 ?? 88 }

	condition:
		any of them
}

rule CobaltStrike_Resources_Artifact32svc_Exe_v3_1_v3_2_v3_14_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe signature for versions 3.1 and 3.2 (with overlap with v3.14 through v4.x)"
		hash = "871390255156ce35221478c7837c52d926dfd581173818620b738b4b029e6fd9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 }

	condition:
		$decoderFunc
}

rule CobaltStrike_Resources_Artifact64_v1_49_v2_x_v3_0_v3_3_thru_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.dll,.exe,big.exe,big.dll,bigsvc.exe,big.x64.dll} and resources/rtifactuac(alt)64.dll signature for versions v1.49, v2.x, v3.0, and v3.3 through v3.14"
		hash = "9ec57d306764517b5956b49d34a3a87d4a6b26a2bb3d0fdb993d055e0cc9920d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$a = { 8B [2] 48 98 48 [2] 48 [3] 8B [2] 48 98 48 [3] 44 [3] 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 48 98 48 [3] 0F B6 00 44 [2] 88 }

	condition:
		$a
}

rule CobaltStrike_Resources_Artifact64_v3_1_v3_2_v3_14_and_v4_0
{
	meta:
		description = "Cobalt Strike's resources/artifact64{svcbig.exe,.dll,big.dll,svc.exe} and resources/artifactuac(big)64.dll signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x"
		hash = "2e7a39bd6ac270f8f548855b97c4cef2c2ce7f54c54dd4d1aa0efabeecf3ba90"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$decoderFunction = { 31 ?? EB 0F 41 [2] 03 47 [3] 44 [3] 48 [2] 39 ?? 41 [2] 7C EA 4C [6] E9 }

	condition:
		$decoderFunction
}

rule CobaltStrike_Resources_Artifact64_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.exe,.dll,svc.exe,svcbig.exe,big.exe,big.dll,.x64.dll,big.x64.dll} and resource/artifactuac(alt)64.exe signature for versions v3.14 through v4.x"
		hash = "decfcca0018f2cec4a200ea057c804bb357300a67c6393b097d52881527b1c44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$fmtBuilder = {
			41 ?? 5C 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 65 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 69 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 2E 00 00 00
			89 [3]
			48 [6]
			E8
		}
		$fmtString = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_44
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.44"
		hash = "75102e8041c58768477f5f982500da7e03498643b6ece86194f4b3396215f9c2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 0F B7 D2 4A 53 8B D9 83 FA 04 77 36 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_45
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.45"
		hash = "1a92b2024320f581232f2ba1e9a11bef082d5e9723429b3e4febb149458d1bb1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 51 0F B7 D2 4A 53 56 83 FA 08 77 6B FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_46
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.46"
		hash = "44e34f4024878024d4804246f57a2b819020c88ba7de160415be38cd6b5e2f76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 8B F2 83 F9 0C 0F 87 8E 00 00 00 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_47
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.47"
		hash = "8ff6dc80581804391183303bb39fca2a5aba5fe13d81886ab21dbd183d536c8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 83 F8 12 77 10 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_48
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.48"
		hash = "dd4e445572cd5e32d7e9cc121e8de337e6f19ff07547e3f2c6b7fce7eafd15e4"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F1 8B DA 83 F8 17 77 12 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_49
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.49"
		hash = "52b4bd87e21ee0cbaaa0fc007fd3f894c5fc2c4bae5cbc2a37188de3c2c465fe"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 56 83 F8 1E 0F 87 23 01 00 00 FF 24 }
		$decoder = { B1 ?? 90 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_0_49
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 2.0.49"
		hash = "ed08c1a21906e313f619adaa0a6e5eb8120cddd17d0084a30ada306f2aca3a4e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 83 F8 22 0F 87 96 01 00 00 FF 24 }
		$decoder = { B1 ?? EB 03 8D 49 00 30 88 [4] 40 3D 30 05 00 00 72 F2  }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_1_and_v2_2
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.1 and 2.2"
		hash = "ae7a1d12e98b8c9090abe19bcaddbde8db7b119c73f7b40e76cdebb2610afdc2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 49 56 57 83 F9 24 0F 87 8A 01 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_3
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.3"
		hash = "00dd982cb9b37f6effb1a5a057b6571e533aac5e9e9ee39a399bb3637775ff83"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 49 56 57 83 F9 26 0F 87 A9 01 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_4
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.4"
		hash = "78c6f3f2b80e6140c4038e9c2bcd523a1b205d27187e37dc039ede4cf560beed"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 4A 56 57 83 FA 2F 0F 87 F9 01 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_5
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.5"
		hash = "d99693e3e521f42d19824955bef0cefb79b3a9dbf30f0d832180577674ee2b58"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 3A 0F 87 6E 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_0
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.0"
		hash = "30251f22df7f1be8bc75390a2f208b7514647835f07593f25e470342fd2e3f52"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 3C 0F 87 89 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_1
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.1"
		hash = "4de723e784ef4e1633bbbd65e7665adcfb03dd75505b2f17d358d5a40b7f35cf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_2
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.2"
		hash = "b490eeb95d150530b8e155da5d7ef778543836a03cb5c27767f1ae4265449a8d"
		rs2 = "a93647c373f16d61c38ba6382901f468247f12ba8cbe56663abb2a11ff2a5144"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 3D 0F 87 83 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
		$version3_1_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

	condition:
		$version_sig and $decoder and not $version3_1_sig
}

rule CobaltStrike_Resources_Beacon_Dll_v3_3
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.3"
		hash = "158dba14099f847816e2fc22f254c60e09ac999b6c6e2ba6f90c6dd6d937bc42"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F1 83 F8 41 0F 87 F0 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_4
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.4"
		hash = "5c40bfa04a957d68a095dd33431df883e3a075f5b7dea3e0be9834ce6d92daa3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F1 83 F8 42 0F 87 F0 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_5_hf1_and_3_5_1
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.5-hf1 and 3.5.1 (3.5.x)"
		hash = "c78e70cd74f4acda7d1d0bd85854ccacec79983565425e98c16a9871f1950525"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F1 83 F8 43 0F 87 07 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_6
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.6"
		hash = "495a744d0a0b5f08479c53739d08bfbd1f3b9818d8a9cbc75e71fcda6c30207d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F9 83 F8 47 0F 87 2F 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_7
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.7"
		hash = "f18029e6b12158fb3993f4951dab2dc6e645bb805ae515d205a53a1ef41ca9b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F9 83 F8 49 0F 87 47 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_8
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.8"
		hash = "67b6557f614af118a4c409c992c0d9a0cc800025f77861ecf1f3bbc7c293d603"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F9 83 F8 4B 0F 87 5D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
		$xmrig_srcpath = "C:/Users/SKOL-NOTE/Desktop/Loader/script.go"
		$c2_1 = "ns7.softline.top" xor
		$c2_2 = "ns8.softline.top" xor
		$c2_3 = "ns9.softline.top" xor

	condition:
		$version_sig and $decoder and not ( 2 of ( $c2_* ) or $xmrig_srcpath )
}

rule CobaltStrike_Resources_Beacon_Dll_v3_11
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.11"
		hash = "2428b93464585229fd234677627431cae09cfaeb1362fe4f648b8bee59d68f29"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B FA 83 F8 50 0F 87 11 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_11_bugfix_and_v3_12
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.11-bugfix and 3.12"
		hash = "5912c96fffeabb2c5c5cdd4387cfbfafad5f2e995f310ace76ca3643b866e3aa"
		rs2 = "4476a93abe48b7481c7b13dc912090b9476a2cdf46a1c4287b253098e3523192"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B FA 83 F8 50 0F 87 0D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_13
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.13"
		hash = "362119e3bce42e91cba662ea80f1a7957a5c2b1e92075a28352542f31ac46a0c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 4A 56 57 83 FA 5A 0F 87 2D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_14
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.14"
		hash = "254c68a92a7108e8c411c7b5b87a2f14654cd9f1324b344f036f6d3b6c7accda"
		rs2 = "87b3eb55a346b52fb42b140c03ac93fc82f5a7f80697801d3f05aea1ad236730"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 83 FA 5B 77 15 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_0_suspected
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.0 (suspected, not confirmed)"
		hash = "e2b2b72454776531bbc6a4a5dd579404250901557f887a6bccaee287ac71b248"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 51 4A 56 57 83 FA 62 0F 87 8F 03 00 00 FF 24 95 56 7B 00 10 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_1_and_v4_2
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.1 and 4.2"
		hash = "daa42f4380cccf8729129768f3588bb98e4833b0c40ad0620bb575b5674d5fc3"
		rs2 = "9de55f27224a4ddb6b2643224a5da9478999c7b2dea3a3d6b3e1808148012bcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 63 0F 87 3C 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.3 and 4.4"
		hash = "51490c01c72c821f476727c26fbbc85bdbc41464f95b28cdc577e5701790845f"
		rs2 = "78a6fbefa677eeee29d1af4a294ee57319221b329a2fe254442f5708858b37dc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 65 0F 87 47 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_7_suspected
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.7 (suspected, not confirmed)"
		hash = "da9e91b3d8df3d53425dd298778782be3bdcda40037bd5c92928395153160549"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_2
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.2"
		hash = "5993a027f301f37f3236551e6ded520e96872723a91042bfc54775dcb34c94a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 4C 8D 05 9F F8 FF FF 8B D3 48 8B CF E8 05 1A 00 00
                     EB 0A 8B D3 48 8B CF E8 41 21 00 00 48 8B 5C 24 30
                     48 83 C4 20 }
		$decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_3
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.3"
		hash = "7b00721efeff6ed94ab108477d57b03022692e288cc5814feb5e9d83e3788580"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 89 66 00 00 E9 23 FB FF FF 
                     41 B8 01 00 00 00 E9 F3 FD FF FF 48 8D 0D 2A F8 FF FF
                     E8 8D 2B 00 00 48 8B 5C 24 30 48 83 C4 20 }
		$decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_4
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.4"
		hash = "5a4d48c2eda8cda79dc130f8306699c8203e026533ce5691bf90363473733bf0"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 56 6F 00 00 E9 17 FB FF FF
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 41 4D 00 00
                     48 8B 5C 24 30 48 83 C4 20 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_5_hf1_and_v3_5_1
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.5-hf1 and 3.5.1"
		hash = "934134ab0ee65ec76ae98a9bb9ad0e9571d80f4bf1eb3491d58bacf06d42dc8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 38 70 00 00 E9 FD FA FF FF 
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 3F 4D 00 00 
                     48 8B 5C 24 30 48 83 C4 20 5F }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_6
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.6"
		hash = "92b0a4aec6a493bcb1b72ce04dd477fd1af5effa0b88a9d8283f26266bb019a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 27
                     0F 87 47 03 00 00 0F 84 30 03 00 00 83 F9 14
                     0F 87 A4 01 00 00 0F 84 7A 01 00 00 83 F9 0C
                     0F 87 C8 00 00 00 0F 84 B3 00 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_7
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.7"
		hash = "81296a65a24c0f6f22208b0d29e7bb803569746ce562e2fa0d623183a8bcca60"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 28
                     0F 87 7F 03 00 00 0F 84 67 03 00 00 83 F9 15
                     0F 87 DB 01 00 00 0F 84 BF 01 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_8
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.8"
		hash = "547d44669dba97a32cb9e95cfb8d3cd278e00599e6a11080df1a9d09226f33ae"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 7A 52 00 00 EB 0D 45 33 C0 8B D3 48 8B CF
                     E8 8F 55 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_11
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.11 (two subversions)"
		hash = "64007e104dddb6b5d5153399d850f1e1f1720d222bed19a26d0b1c500a675b1a"
		rs2 = "815f313e0835e7fdf4a6d93f2774cf642012fd21ce870c48ff489555012e0047"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 83 EC 20 41 8B D8 48 8B FA 83 F9 2D 0F 87 B2 03 00 00
                     0F 84 90 03 00 00 83 F9 17 0F 87 F8 01 00 00
                     0F 84 DC 01 00 00 83 F9 0E 0F 87 F9 00 00 00
                     0F 84 DD 00 00 00 FF C9 0F 84 C0 00 00 00 83 E9 02
                     0F 84 A6 00 00 00 FF C9 }
		$decoder = {
      80 34 28 ?? 
      48 FF C0
      48 3D 00 10 00 00
      7C F1
    }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_12
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.12"
		hash = "8a28b7a7e32ace2c52c582d0076939d4f10f41f4e5fa82551e7cc8bdbcd77ebc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 F8 2E 00 00 EB 16 8B D3 48 8B CF
                     E8 00 5C 00 00 EB 0A 8B D3 48 8B CF E8 64 4F 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_13
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.13"
		hash = "945e10dcd57ba23763481981c6035e0d0427f1d3ba71e75decd94b93f050538e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 48 8D 0D 01 5B FF FF 48 83 C4 28 E9 A8 54 FF FF 8B D0
                     49 8B CA E8 22 55 FF FF }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_14
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.14"
		hash = "297a8658aaa4a76599a7b79cb0da5b8aa573dd26c9e2c8f071e591200cf30c93"
		rs2 = "39b9040e3dcd1421a36e02df78fe031cbdd2fb1a9083260b8aedea7c2bc406bf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 B1 1F 00 00 8B D0 49 8B CA
                     48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_x86_v4_0_suspected
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.0 (suspected, not confirmed)"
		hash = "55aa2b534fcedc92bb3da54827d0daaa23ece0f02a10eb08f5b5247caaa63a73"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 D1 B3 FF FF
                     8B D0 49 8B CA 48 83 C4 28 E9 AF F5 FF FF 45 33 C0
                     4C 8D 0D 8D 70 FF FF 8B D0 49 8B CA E8 9B B0 FF FF }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_1_and_v_4_2
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.1 and 4.2"
		hash = "29ec171300e8d2dad2e1ca2b77912caf0d5f9d1b633a81bb6534acb20a1574b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 83 F9 34 0F 87 8E 03 00 00 0F 84 7A 03 00 00 83 F9 1C 0F 87 E6 01 00 00
                     0F 84 D7 01 00 00 83 F9 0E 0F 87 E9 00 00 00 0F 84 CE 00 00 00 FF C9
                     0F 84 B8 00 00 00 83 E9 02 0F 84 9F 00 00 00 FF C9 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_3
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Version 4.3"
		hash = "3ac9c3525caa29981775bddec43d686c0e855271f23731c376ba48761c27fa3d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 D3 88 FF FF
                     4C 8D 05 84 6E FF FF 8B D0 49 8B CA 48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_4_v_4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.4 through at least 4.6"
		hash = "3280fec57b7ca94fd2bdb5a4ea1c7e648f565ac077152c5a81469030ccf6ab44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 83 88 FF FF
                     4C 8D 05 A4 6D FF FF 8B D0 49 8B CA 48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_5_variant
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.5 (variant)"
		hash = "8f0da7a45945b630cd0dfb5661036e365dcdccd085bc6cff2abeec6f4c9f1035"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 E8 AB FF FF
                     8B D0 49 8B CA E8 1A EB FF FF 48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Bind64_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bind64.bin signature for versions v2.5 to v4.x"
		hash = "5dd136f5674f66363ea6463fd315e06690d6cb10e3cc516f2d378df63382955d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}
		$calls = {
			41 BA C2 DB 37 67
			FF D5
			48 [2]
			48 [2]
			41 BA B7 E9 38 FF
			FF D5
			4D [2]
			48 [2]
			48 [2]
			41 BA 74 EC 3B E1
			FF D5
			48 [2]
			48 [2]
			41 BA 75 6E 4D 61
		}

	condition:
		$apiLocator and $calls
}

rule CobaltStrike_Resources_Bind_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bind.bin signature for versions 2.5 to 4.x"
		hash = "3727542c0e3c2bf35cacc9e023d1b2d4a1e9e86ee5c62ee5b66184f46ca126d1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}
		$listenaccept = {
			5? 
			5? 
			68 B7 E9 38 FF
			FF ?? 
			5? 
			5? 
			5? 
			68 74 EC 3B E1
		}

	condition:
		$apiLocator and $ws2_32 and $listenaccept
}

rule CobaltStrike__Resources_Browserpivot_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.bin from v1.48 to v3.14 and sleeve/browserpivot.dll from v4.0 to at least v4.4"
		hash = "12af9f5a7e9bfc49c82a33d38437e2f3f601639afbcdc9be264d3a8d84fd5539"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$socket_recv = {
			FF [1-5]
			83 ?? FF 
			74 ?? 
			85 C0
			(74 | 76) ?? 
			03 ?? 
			83 ?? 02 
			72 ?? 
			80 ?? 3E FF 0A 
			75 ?? 
			80 ?? 3E FE 0D 
		}
		$fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"

	condition:
		all of them
}

rule CobaltStrike_Resources_Browserpivot_x64_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_x64_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.x64.bin from v1.48 to v3.14 and sleeve/browserpivot.x64.dll from v4.0 to at least v4.4"
		hash = "0ad32bc4fbf3189e897805cec0acd68326d9c6f714c543bafb9bc40f7ac63f55"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$socket_recv = {
			FF 15 [4]
			83 ?? FF
			74 ??
			85 ??
			74 ??
			03 ??
			83 ?? 02
			72 ??
			8D ?? FF
			80 [2] 0A
			75 ??
			8D ?? FE
			80 [2] 0D
		}
		$fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"

	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuac_Dll_v1_49_to_v3_14_and_Sleeve_Bypassuac_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac(-x86).dll from v1.49 to v3.14 (32-bit version) and sleeve/bypassuac.dll from v4.0 to at least v4.4"
		hash = "91d12e1d09a642feedee5da966e1c15a2c5aea90c79ac796e267053e466df365"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$deleteFileCOM = {
			A1 [4]
			6A 00
			8B ?? 
			5? 
			5? 
			FF ?? 48 
			85 ?? 
			75 ?? 
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}
		$copyFileCOM = {
			A1 [4]
			6A 00
			FF [2]
			8B ?? 
			FF [5]
			FF [5]
			5? 
			FF ?? 40 
			85 ?? 
			[2 - 6]
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}

	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuac_x64_Dll_v3_3_to_v3_14_and_Sleeve_Bypassuac_x64_Dll_v4_0_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac-x64.dll from v3.3 to v3.14 (64-bit version) and sleeve/bypassuac.x64.dll from v4.0 to at least v4.4"
		hash = "9ecf56e9099811c461d592c325c65c4f9f27d947cbdf3b8ef8a98a43e583aecb"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$deleteFileCOM = {
			48 8B [5]
			45 33 ??
			48 8B ??
			FF 90 90 00 00 00
			85 C0
			75 ??
			48 8B [5]
			48 8B ??
			FF 92 A8 00 00 00
			85 C0
		}
		$copyFileCOM = {
			48 8B [5]
			4C 8B [5]
			48 8B [5]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 90 80 00 00 00
			85 C0
			0F 85 [4]
			48 8B [5]
			48 8B 11
			FF 92 A8 00 00 00
		}

	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuactoken_Dll_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.dll from v3.11 to v3.14 (32-bit version)"
		hash = "df1c7256dfd78506e38c64c54c0645b6a56fc56b2ffad8c553b0f770c5683070"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$isHighIntegrityProcess = {
			5? 
			5? 
			5? 
			8B ?? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			75 ?? 
			FF 15 [4]
			83 ?? 7A 
			75 ?? 
			FF [2]
			5? 
			FF 15 [4]
			8B ?? 
			8D [2]
			5? 
			FF [2]
			5? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			74 ?? 
			FF ?? 
			FF 15 [4]
			8A ?? 
			FE C8
			0F B6 C0
			5? 
			FF ?? 
			FF 15 [4]
			B? 01 00 00 00 
			5? 
			81 ?? 00 30 00 00 
		}
		$executeTaskmgr = {
			6A 3C
			8D ?? C4 
			8B ?? 
			6A 00
			5? 
			8B ?? 
			E8 [4]
			83 C4 0C
			C7 [2] 3C 00 00 00 
			8D [2]
			C7 [2] 40 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			5? 
			C7 [2] 00 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			FF 15 [4]
			FF 75 FC
		}

	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuactoken_x64_Dll_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.x64.dll from v3.11 to v3.14 (64-bit version)"
		hash = "853068822bbc6b1305b2a9780cf1034f5d9d7127001351a6917f9dbb42f30d67"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$isHighIntegrityProcess = {
			83 ?? 7A
			75 ??
			8B [3]
			33 ??
			FF 15 [4]
			44 [4]
			8D [2]
			48 8B ??
			48 8D [3]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 15 [4]
			85 C0
			74 ??
			48 8B ??
			FF 15 [4]
			8D [2]
			8A ??
			40 [2]
			0F B6 D1
			48 8B 0F
			FF 15 [4]
			81 ?? 00 30 00 00
		}
		$executeTaskmgr = {
			44 8D ?? 70
			48 8D [3]
			E8 [4]
			83 [3] 00
			48 8D [5]
			0F 57 ??
			66 0F 7F [3]
			48 89 [3]
			48 8D [5]
			48 8D [3]
			C7 [3] 70 00 00 00
			C7 [3] 40 00 00 00
			48 89 [3]
			FF 15 
		}

	condition:
		all of them
}

rule CobaltStrike_Resources_Command_Ps1_v2_5_to_v3_7_and_Resources_Compress_Ps1_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/command.ps1 for versions 2.5 to v3.7 and resources/compress.ps1 from v3.8 to v4.x"
		hash = "932dec24b3863584b43caf9bb5d0cfbd7ed1969767d3061a7abdc05d3239ed62"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$ps1 = "$s=New-Object \x49O.MemoryStream(,[Convert]::\x46romBase64String(" nocase
		$ps2 = "));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();" nocase

	condition:
		all of them
}

rule CobaltStrike_Resources_Covertvpn_Dll_v2_1_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/covertvpn.dll signature for version v2.2 to v4.4"
		hash = "0a452a94d53e54b1df6ba02bc2f02e06d57153aad111171a94ec65c910d22dcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$dropComponentsAndActivateDriver_prologue = {
			5? 
			68 [4]
			68 [4]
			C7 [3-5] 00 00 00 00 
			FF 15 [4]
			50
			FF 15 [4]
			8B ?? 
			85 ?? 
			74 ??
			8D [3-5]
			5? 
			FF 15 [4]
			50
		}
		$dropFile = {
			6A 00
			5? 
			E8 [4]
			83 C4 08
			83 F8 FF
			74 ?? 
			5? 
			[0-5]
			E8 [4]
			83 C4 ??
			[0-2]
			6A 00
			68 80 01 00 00
			6A 02
			6A 00
			6A 05
			68 00 00 00 40
			5? 
			FF 15 [4]
			8B ?? 
			83 ?? FF 
			75 ?? 
			FF 15 [4]
			5? 
		}
		$nfp = "npf.sys" nocase
		$wpcap = "wpcap.dll" nocase

	condition:
		all of them
}

rule CobaltStrike_Resources_Covertvpn_injector_Exe_v1_44_to_v2_0_49
{
	meta:
		description = "Cobalt Strike's resources/covertvpn-injector.exe signature for version v1.44 to v2.0.49"
		hash = "d741751520f46602f5a57d1ed49feaa5789115aeeba7fa4fc7cbb534ee335462"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$dropComponentsAndActivateDriver_prologue = {
			C7 04 24 [4]
			E8 [4]
			83 EC 04
			C7 44 24 04 [4]
			89 04 24
			E8 59 14 00 00
			83 EC 08
			89 45 ?? 
			83 7D ?? 00 
			74 ?? 
			E8 [4]
			8D [2]
			89 [3]
			89 04 24
		}
		$dropFile = {
			C7 44 24 04 00 00 00 00
			8B [2]
			89 ?? 24 
			E8 [4]
			83 F8 FF
			74 ?? 
			8B [2]
			89 ?? 24 04 
			C7 04 24 [4]
			E8 [4]
			E9 [4]
			C7 44 24 18 00 00 00 00
			C7 44 24 14 80 01 00 00
			C7 44 24 10 02 00 00 00
			C7 44 24 0C 00 00 00 00
			C7 44 24 08 05 00 00 00
			C7 44 24 04 00 00 00 40
			8B [2]
			89 04 24
			E8 [4]
			83 EC 1C
			89 45 ?? 
		}
		$nfp = "npf.sys" nocase
		$wpcap = "wpcap.dll" nocase

	condition:
		all of them
}

rule CobaltStrike_Resources_Dnsstager_Bin_v1_47_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/dnsstager.bin signature for versions 1.47 to 4.x"
		hash = "10f946b88486b690305b87c14c244d7bc741015c3fef1c4625fa7f64917897f1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$dnsapi = { 68 64 6E 73 61 }

	condition:
		$apiLocator and $dnsapi
}

rule CobaltStrike_Resources_Elevate_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.dll signature for v3.0 to v3.14 and sleeve/elevate.dll for v4.x"
		hash = "6deeb2cafe9eeefe5fc5077e63cc08310f895e9d5d492c88c4e567323077aa2f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$wnd_proc = {
			6A 00
			6A 28
			68 00 01 00 00
			5? 
			C7 [5] 01 00 00 00 
			FF ?? 
			6A 00
			6A 27
			68 00 01 00 00
			5? 
			FF ?? 
			6A 00
			6A 00
			68 01 02 00 00
			5? 
			FF ?? 
		}

	condition:
		$wnd_proc
}

rule CobaltStrike_Resources_Elevate_X64_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_X64_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.x64.dll signature for v3.0 to v3.14 and sleeve/elevate.x64.dll for v4.x"
		hash = "c3ee8a9181fed39cec3bd645b32b611ce98d2e84c5a9eff31a8acfd9c26410ec"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$wnd_proc = {
			81 ?? 21 01 00 00
			75 ??
			83 [5] 00
			75 ??
			45 33 ??
			8D [2]
			C7 [5] 01 00 00 00
			45 [2] 28
			FF 15 [4]
			45 33 ??
			8D [2]
			45 [2] 27
			48 [2]
			FF 15 [4]
			45 33 ??
			45 33 ??
			BA 01 02 00 00
			48 
		}

	condition:
		$wnd_proc
}

rule CobaltStrike_Resources_Httpsstager64_Bin_v3_2_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpsstager64.bin signature for versions v3.2 to v4.x"
		hash = "109b8c55816ddc0defff360c93e8a07019ac812dd1a42209ea7e95ba79b5a573"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}
		$InternetSetOptionA = {
			BA 1F 00 00 00
			6A 00
			68 80 33 00 00
			49 [2]
			41 ?? 04 00 00 00
			41 ?? 75 46 9E 86
		}

	condition:
		$apiLocator and $InternetSetOptionA
}

rule CobaltStrike_Resources_Httpsstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpsstager.bin signature for versions 2.5 to 4.x"
		hash = "5ebe813a4c899b037ac0ee0962a439833964a7459b7a70f275ac73ea475705b3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$InternetSetOptionA = {
			6A 04
			5? 
			6A 1F
			5? 
			68 75 46 9E 86
			FF  
		}

	condition:
		$apiLocator and $InternetSetOptionA
}

rule CobaltStrike_Resources_Httpstager64_Bin_v3_2_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpstager64.bin signature for versions v3.2 to v4.x"
		hash = "ad93d1ee561bc25be4a96652942f698eac9b133d8b35ab7e7d3489a25f1d1e76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}
		$postInternetOpenJmp = {
			41 ?? 3A 56 79 A7
			FF ??
			EB 
		}

	condition:
		$apiLocator and $postInternetOpenJmp
}

rule CobaltStrike_Resources_Httpstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpstager.bin signature for versions 2.5 to 4.x"
		hash = "a47569af239af092880751d5e7b68d0d8636d9f678f749056e702c9b063df256"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$downloaderLoop = {
			B? 00 2F 00 00 
			39 ?? 
			74 ?? 
			31 ?? 
			( E9 | EB )
		}

	condition:
		$apiLocator and $downloaderLoop
}

rule CobaltStrike_Resources_Reverse64_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/reverse64.bin signature for versions v2.5 to v4.x"
		hash = "d2958138c1b7ef681a63865ec4a57b0c75cc76896bf87b21c415b7ec860397e8"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}
		$calls = {
			48 89 C1
			41 BA EA 0F DF E0
			FF D5
			48 [2]
			6A ??
			41 ??
			4C [2]
			48 [2]
			41 BA 99 A5 74 61
			FF D5
		}

	condition:
		$apiLocator and $calls
}

rule CobaltStrike_Resources_Reverse_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/reverse.bin signature for versions 2.5 to 4.x"
		hash = "887f666d6473058e1641c3ce1dd96e47189a59c3b0b85c8b8fccdd41b84000c7"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}
		$connect = {
			6A 10
			5? 
			5? 
			68 99 A5 74 61
		}

	condition:
		$apiLocator and $ws2_32 and $connect
}

rule CobaltStrike_Resources_Smbstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/smbstager.bin signature for versions 2.5 to 4.x"
		hash = "946af5a23e5403ea1caccb2e0988ec1526b375a3e919189f16491eeabc3e7d8c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$smb = { 68 C6 96 87 52 }
		$smbstart = {
			6A 40
			68 00 10 00 00
			68 FF FF 07 00
			6A 00
			68 58 A4 53 E5
		}

	condition:
		$apiLocator and $smb and $smbstart
}

rule CobaltStrike_Resources_Template_Py_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.py signature for versions v3.3 to v4.x"
		hash = "d5cb406bee013f51d876da44378c0a89b7b3b800d018527334ea0c5793ea4006"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$arch = "platform.architecture()"
		$nope = "WindowsPE"
		$alloc = "ctypes.windll.kernel32.VirtualAlloc"
		$movemem = "ctypes.windll.kernel32.RtlMoveMemory"
		$thread = "ctypes.windll.kernel32.CreateThread"
		$wait = "ctypes.windll.kernel32.WaitForSingleObject"

	condition:
		all of them
}

rule CobaltStrike_Resources_Template_Sct_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.sct signature for versions v3.3 to v4.x"
		hash = "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$scriptletstart = "<scriptlet>" nocase
		$registration = "<registration progid=" nocase
		$classid = "classid=" nocase
		$scriptlang = "<script language=\"vbscript\">" nocase
		$cdata = "<![CDATA["
		$scriptend = "</script>" nocase
		$antiregistration = "</registration>" nocase
		$scriptletend = "</scriptlet>"

	condition:
		all of them and @scriptletstart [ 1 ] < @registration [ 1 ] and @registration [ 1 ] < @classid [ 1 ] and @classid [ 1 ] < @scriptlang [ 1 ] and @scriptlang [ 1 ] < @cdata [ 1 ]
}

rule CobaltStrike_Resources__Template_Vbs_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/btemplate.vbs signature for versions v3.3 to v4.x"
		hash = "e0683f953062e63b2aabad7bc6d76a78748504b114329ef8e2ece808b3294135"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$ea = "Excel.Application" nocase
		$vis = "Visible = False" nocase
		$wsc = "Wscript.Shell" nocase
		$regkey1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" nocase
		$regkey2 = "\\Excel\\Security\\AccessVBOM" nocase
		$regwrite = ".RegWrite" nocase
		$dw = "REG_DWORD"
		$code = ".CodeModule.AddFromString"
		$ao = { 41 75 74 6f 5f 4f 70 65 6e }
		$da = ".DisplayAlerts"

	condition:
		all of them
}

rule CobaltStrike_Resources_Template__x32_x64_Ps1_v1_45_to_v2_5_and_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.x32 from v3.11 to v3.14 and resources/template.ps1 from v1.45 to v2.5 "
		hash = "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$importVA = "[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc" nocase
		$importCT = "[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread" nocase
		$importWFSO = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject" nocase
		$compiler = "New-Object Microsoft.CSharp.CSharpCodeProvider" nocase
		$params = "New-Object System.CodeDom.Compiler.CompilerParameters" nocase
		$paramsSys32 = ".ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" nocase
		$paramsGIM = ".GenerateInMemory = $True" nocase
		$result = "$compiler.CompileAssemblyFromSource($params, $assembly)" nocase

	condition:
		all of them
}

rule CobaltStrike_Resources_Template_x64_Ps1_v3_0_to_v4_x_excluding_3_12_3_13
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.hint.x64.ps1 and resources/template.hint.x32.ps1 from v3.0 to v4.x except 3.12 and 3.13"
		hash = "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$dda = "[AppDomain]::CurrentDomain.DefineDynamicAssembly" nocase
		$imm = "InMemoryModule" nocase
		$mdt = "MyDelegateType" nocase
		$rd = "New-Object System.Reflection.AssemblyName('ReflectedDelegate')" nocase
		$data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase
		$64bitSpecific = "[IntPtr]::size -eq 8"
		$mandatory = "Mandatory = $True"

	condition:
		all of them
}

rule CobaltStrike_Resources_Template_x86_Vba_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.x86.vba signature for versions v3.8 to v4.x"
		hash = "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$createstuff = "Function CreateStuff Lib \"kernel32\" Alias \"CreateRemoteThread\"" nocase
		$allocstuff = "Function AllocStuff Lib \"kernel32\" Alias \"VirtualAllocEx\"" nocase
		$writestuff = "Function WriteStuff Lib \"kernel32\" Alias \"WriteProcessMemory\"" nocase
		$runstuff = "Function RunStuff Lib \"kernel32\" Alias \"CreateProcessA\"" nocase
		$vars = "Dim rwxpage As Long" nocase
		$res = "RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)"
		$rwxpage = "AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)"

	condition:
		all of them and @vars [ 1 ] < @res [ 1 ] and @allocstuff [ 1 ] < @rwxpage [ 1 ]
}

rule CobaltStrike_Resources_Xor_Bin_v2_x_to_v4_x
{
	meta:
		description = "Cobalt Strike's resource/xor.bin signature for version 2.x through 4.x"
		hash = "211ccc5d28b480760ec997ed88ab2fbc5c19420a3d34c1df7991e65642638a6f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$stub52 = {fc e8 ?? ?? ?? ?? [1-32] eb 27 5? 8b ??    83 c? ?4 8b ??    31 ?? 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb ea 5? ff e? e8 d4 ff ff ff}
		$stub56 = {fc e8 ?? ?? ?? ?? [1-32] eb 2b 5d 8b ?? ?? 83 c5 ?4 8b ?? ?? 31 ?? 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e8 5? ff e? e8 d? ff ff ff}

	condition:
		any of them
}

rule CobaltStrike_Resources_Xor_Bin__64bit_v3_12_to_v4_x
{
	meta:
		description = "Cobalt Strike's resource/xor64.bin signature for version 3.12 through 4.x"
		hash = "01dba8783768093b9a34a1ea2a20f72f29fd9f43183f3719873df5827a04b744"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$stub58 = {fc e8 ?? ?? ?? ?? [1-32] eb 33 5? 8b ?? 00 4? 83 ?? ?4 8b ?? 00 31 ?? 4? 83 ?? ?4 5? 8b ?? 00 31 ?? 89 ?? 00 31 ?? 4? 83 ?? ?4 83 ?? ?4 31 ?? 39 ?? 74 ?2 eb e7 5? fc 4? 83 ?? f0 ff}
		$stub59 = {fc e8 ?? ?? ?? ?? [1-32] eb 2e 5? 8b ??    48 83 c? ?4 8b ??    31 ?? 48 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 48 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e9 5?    48 83 ec ?8 ff e? e8 cd ff ff ff}
		$stub63 = {fc e8 ?? ?? ?? ?? [1-32] eb 32 5d 8b ?? ?? 48 83 c5 ?4 8b ?? ?? 31 ?? 48 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 48 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e7 5?    48 83 ec ?8 ff e? e8 c9 ff ff ff}

	condition:
		any of them
}

rule CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.HA.x86.o (HeapAlloc) Versions 4.3 through at least 4.6"
		hash = "8e4a1862aa3693f0e9011ade23ad3ba036c76ae8ccfb6585dc19ceb101507dcd"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$core_sig = {
      C6 45 F0 48
      C6 45 F1 65
      C6 45 F2 61
      C6 45 F3 70
      C6 45 F4 41
      C6 45 F5 6C
      C6 45 F6 6C
      C6 45 F7 6F
      C6 45 F8 63
      C6 45 F9 00
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_MVF_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x86.o (MapViewOfFile) Versions 4.3 through at least 4.6"
		hash = "cded3791caffbb921e2afa2de4c04546067c3148c187780066e8757e67841b44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$core_sig = {
      C6 45 EC 4D
      C6 45 ED 61
      C6 45 EE 70
      C6 45 EF 56
      C6 45 F0 69
      C6 45 F1 65
      C6 45 F2 77
      C6 45 F3 4F
      C6 45 F4 66
      C6 45 F5 46
      C6 45 F6 69
      C6 45 F7 6C
      C6 45 F8 65
      C6 45 F9 00
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_VA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.VA.x86.o (VirtualAlloc) Versions 4.3 through at least 4.6"
		hash = "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }
		$deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.x86.o Versions 4.3 through at least 4.6"
		hash = "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }
		$deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }

	condition:
		$core_sig and not $deobfuscator
}

rule CobaltStrike_Sleeve_BeaconLoader_HA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.HA.x64.o (HeapAlloc) Versions 4.3 through at least 4.6"
		hash = "d64f10d5a486f0f2215774e8ab56087f32bef19ac666e96c5627c70d345a354d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$core_sig = {
      C6 44 24 38 48
      C6 44 24 39 65
      C6 44 24 3A 61
      C6 44 24 3B 70
      C6 44 24 3C 41
      C6 44 24 3D 6C
      C6 44 24 3E 6C
      C6 44 24 3F 6F
      C6 44 24 40 63
      C6 44 24 41 00
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_MVF_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x64.o (MapViewOfFile) Versions 4.3 through at least 4.6"
		hash = "9d5b6ccd0d468da389657309b2dc325851720390f9a5f3d3187aff7d2cd36594"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$core_sig = {
      C6 44 24 58 4D
      C6 44 24 59 61
      C6 44 24 5A 70
      C6 44 24 5B 56
      C6 44 24 5C 69
      C6 44 24 5D 65
      C6 44 24 5E 77
      C6 44 24 5F 4F
      C6 44 24 60 66
      C6 44 24 61 46
      C6 44 24 62 69
      C6 44 24 63 6C
      C6 44 24 64 65
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.VA.x64.o (VirtualAlloc) Versions 4.3 through at least 4.6"
		hash = "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$core_sig = {
      C6 44 24 48 56
      C6 44 24 49 69
      C6 44 24 4A 72
      C6 44 24 4B 74
      C6 44 24 4C 75
      C6 44 24 4D 61
      C6 44 24 4E 6C
      C6 44 24 4F 41
      C6 44 24 50 6C
      C6 44 24 51 6C
      C6 44 24 52 6F
      C6 44 24 53 63
      C6 44 24 54 00
    }
		$deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.x64.o (Base) Versions 4.3 through at least 4.6"
		hash = "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
		$core_sig = {
      33 C0
      83 F8 01
      74 63
      48 8B 44 24 20
      0F B7 00
      3D 4D 5A 00 00
      75 45
      48 8B 44 24 20
      48 63 40 3C
      48 89 44 24 28
      48 83 7C 24 28 40
      72 2F
      48 81 7C 24 28 00 04 00 00
      73 24
      48 8B 44 24 20
      48 8B 4C 24 28
      48 03 C8
      48 8B C1
      48 89 44 24 28
      48 8B 44 24 28
      81 38 50 45 00 00
      75 02
    }
		$deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

	condition:
		$core_sig and not $deobfuscator
}

rule Sliver_Implant_32bit
{
	meta:
		description = "Sliver 32-bit implant (with and without --debug flag at compile)"
		hash = "911f4106350871ddb1396410d36f2d2eadac1166397e28a553b28678543a9357"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		modified = "2022-11-19"

	strings:
		$s_tcppivot = { 81 ?? 74 63 70 70 [2-20] 81 ?? 04 69 76 6F 74  }
		$s_wg = { 66 81 ?? 77 67 }
		$s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }
		$s_http = { 81 ?? 68 74 74 70 }
		$s_https = { 81 ?? 68 74 74 70 [2-20] 80 ?? 04 73 }
		$s_mtls = { 81 ?? 6D 74 6C 73 }
		$fp1 = "cloudfoundry" ascii fullword

	condition:
		4 of ( $s* ) and not 1 of ( $fp* )
}

rule Sliver_Implant_64bit
{
	meta:
		description = "Sliver 64-bit implant (with and without --debug flag at compile)"
		hash = "2d1c9de42942a16c88a042f307f0ace215cdc67241432e1152080870fe95ea87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		modified = "2022-11-19"

	strings:
		$s_tcppivot = { 48 ?? 74 63 70 70 69 76 6F 74 }
		$s_namedpipe = { 48 ?? 6E 61 6D 65 64 70 69 70 [2-32] 80 ?? 08 65 }
		$s_https = { 81 ?? 68 74 74 70 [2-32] 80 ?? 04 73 }
		$s_wg = {66 81 ?? 77 67}
		$s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }
		$s_mtls = {  81 ?? 6D 74 6C 73  }
		$fp1 = "cloudfoundry" ascii fullword

	condition:
		5 of ( $s* ) and not 1 of ( $fp* )
}
