/*
 * 79 rules selected from https://github.com/airbnb/binaryalert
 * at commit a9c0f06affc35e1f8e45bb77f835b92350c68a0b
 * License: Apache-2.0 (see LICENSES.txt next to this file)
 * Modified by Guard: rules were selected, deduplicated and reformatted
 * (data/yara/README.md says how); rule logic is unchanged.
 */

import "math"
import "pe"
rule eicar_av_test
{
	meta:
		description = "This is a standard AV test, intended to verify that BinaryAlert is working correctly."
		author = "Austin Byers | Airbnb CSIRT"
		reference = "http://www.eicar.org/86-0-Intended-use.html"

	strings:
		$eicar_regex = /^X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*\s*$/

	condition:
		all of them
}

rule eicar_substring_test
{
	meta:
		description = "Standard AV test, checking for an EICAR substring"
		author = "Austin Byers | Airbnb CSIRT"

	strings:
		$eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

	condition:
		all of them
}

rule hacktool_macos_exploit_cve_5889
{
	meta:
		description = "http://www.cvedetails.com/cve/cve-2015-5889"
		reference = "https://www.exploit-db.com/exploits/38371/"
		author = "@mimeframe"

	strings:
		$a1 = "/etc/sudoers" fullword wide ascii
		$a2 = "/etc/crontab" fullword wide ascii
		$a3 = "* * * * * root echo" wide ascii
		$a4 = "ALL ALL=(ALL) NOPASSWD: ALL" wide ascii
		$a5 = "/usr/bin/rsh" fullword wide ascii
		$a6 = "localhost" fullword wide ascii

	condition:
		all of ( $a* )
}

rule hacktool_macos_exploit_tpwn
{
	meta:
		description = "tpwn exploits a null pointer dereference in XNU to escalate privileges to root."
		reference = "https://www.rapid7.com/db/modules/exploit/osx/local/tpwn"
		author = "@mimeframe"

	strings:
		$a1 = "[-] Couldn't find a ROP gadget, aborting." wide ascii
		$a2 = "leaked kaslr slide," wide ascii
		$a3 = "didn't get root, but this system is vulnerable." wide ascii
		$a4 = "Escalating privileges! -qwertyoruiop" wide ascii

	condition:
		2 of ( $a* )
}

rule hacktool_macos_juuso_keychaindump
{
	meta:
		description = "For reading OS X keychain passwords as root."
		reference = "https://github.com/juuso/keychaindump"
		author = "@mimeframe"

	strings:
		$a1 = "[-] Too many candidate keys to fit in memory" wide ascii
		$a2 = "[-] Could not allocate memory for key search" wide ascii
		$a3 = "[-] Too many credentials to fit in memory" wide ascii
		$a4 = "[-] The target file is not a keychain file" wide ascii
		$a5 = "[-] Could not find the securityd process" wide ascii
		$a6 = "[-] No root privileges, please run with sudo" wide ascii

	condition:
		4 of ( $a* )
}

rule hacktool_macos_keylogger_b4rsby_swiftlog
{
	meta:
		description = "Dirty user level command line keylogger hacked together in Swift."
		reference = "https://github.com/b4rsby/SwiftLog"
		author = "@mimeframe"

	strings:
		$a1 = "You need to enable the keylogger in the System Prefrences" wide ascii

	condition:
		all of ( $a* )
}

rule hacktool_macos_keylogger_caseyscarborough
{
	meta:
		description = "A simple and easy to use keylogger for macOS."
		reference = "https://github.com/caseyscarborough/keylogger"
		author = "@mimeframe"

	strings:
		$a1 = "/var/log/keystroke.log" wide ascii
		$a2 = "ERROR: Unable to create event tap." wide ascii
		$a3 = "Keylogging has begun." wide ascii
		$a4 = "ERROR: Unable to open log file. Ensure that you have the proper permissions." wide ascii

	condition:
		2 of ( $a* )
}

rule hacktool_macos_keylogger_dannvix
{
	meta:
		description = "A simple keylogger for macOS."
		reference = "https://github.com/dannvix/keylogger-osx"
		author = "@mimeframe"

	strings:
		$a1 = "/var/log/keystroke.log" wide ascii
		$a2 = "<forward-delete>" wide ascii
		$a3 = "<unknown>" wide ascii

	condition:
		all of ( $a* )
}

rule hacktool_macos_keylogger_eldeveloper_keystats
{
	meta:
		description = "A simple keylogger for macOS."
		reference = "https://github.com/ElDeveloper/keystats"
		author = "@mimeframe"

	strings:
		$a1 = "YVBKeyLoggerPerishedNotification" wide ascii
		$a2 = "YVBKeyLoggerPerishedByLackOfResponseNotification" wide ascii
		$a3 = "YVBKeyLoggerPerishedByUserChangeNotification" wide ascii

	condition:
		2 of ( $a* )
}

rule hacktool_macos_keylogger_giacomolaw
{
	meta:
		description = "A simple keylogger for macOS."
		reference = "https://github.com/GiacomoLaw/Keylogger"
		author = "@mimeframe"

	strings:
		$a1 = "ERROR: Unable to access keystroke log file. Please make sure you have the correct permissions." wide ascii
		$a2 = "ERROR: Unable to create event tap." wide ascii
		$a3 = "Keystrokes are now being recorded" wide ascii

	condition:
		2 of ( $a* )
}

rule hacktool_macos_keylogger_logkext
{
	meta:
		description = "LogKext is an open source keylogger for Mac OS X, a product of FSB software."
		reference = "https://github.com/SlEePlEs5/logKext"
		author = "@mimeframe"

	strings:
		$a1 = "logKextPassKey" wide ascii
		$a2 = "Couldn't get system keychain:" wide ascii
		$a3 = "Error finding secret in keychain" wide ascii
		$a4 = "com_fsb_iokit_logKext" wide ascii
		$b1 = "logKext Password:" wide ascii
		$b2 = "Logging controls whether the daemon is logging keystrokes (default is on)." wide ascii
		$c1 = "logKextPassKey" wide ascii
		$c2 = "Error: couldn't create secAccess" wide ascii
		$d1 = "IOHIKeyboard" wide ascii
		$d2 = "Clear keyboards called with kextkeys" wide ascii
		$d3 = "Added notification for keyboard" wide ascii

	condition:
		3 of ( $a* ) or all of ( $b* ) or all of ( $c* ) or all of ( $d* )
}

rule hacktool_macos_keylogger_roxlu_ofxkeylogger
{
	meta:
		description = "ofxKeylogger keylogger."
		reference = "https://github.com/roxlu/ofxKeylogger"
		author = "@mimeframe"

	strings:
		$a1 = "keylogger_init" wide ascii
		$a2 = "install_keylogger_hook function not found in dll." wide ascii
		$a3 = "keylogger_set_callback" wide ascii

	condition:
		all of ( $a* )
}

rule hacktool_macos_keylogger_skreweverything_swift
{
	meta:
		description = "It is a simple and easy to use keylogger for macOS written in Swift."
		reference = "https://github.com/SkrewEverything/Swift-Keylogger"
		author = "@mimeframe"

	strings:
		$a1 = "Can't create directories!" wide ascii
		$a2 = "Can't create manager" wide ascii
		$a3 = "Can't open HID!" wide ascii
		$a4 = "PRINTSCREEN" wide ascii
		$a5 = "LEFTARROW" wide ascii

	condition:
		4 of ( $a* )
}

private rule MachO
{
	meta:
		description = "Mach-O binaries"

	condition:
		uint32( 0 ) == 0xfeedface or uint32( 0 ) == 0xcefaedfe or uint32( 0 ) == 0xfeedfacf or uint32( 0 ) == 0xcffaedfe or uint32( 0 ) == 0xcafebabe or uint32( 0 ) == 0xbebafeca
}

rule hacktool_macos_macpmem
{
	meta:
		description = "MacPmem enables read/write access to physical memory on macOS. Can be used by CSIRT teams and attackers."
		reference = "https://github.com/google/rekall/tree/master/tools/osx/MacPmem"
		author = "@mimeframe"

	strings:
		$a1 = "%s/MacPmem.kext" wide ascii
		$a2 = "The Pmem physical memory imager." wide ascii
		$a3 = "The OSXPmem memory imager." wide ascii
		$a4 = "These AFF4 Volumes will be loaded and their metadata will be parsed before the program runs." wide ascii
		$a5 = "Pmem driver version incompatible. Reported" wide ascii
		$a6 = "Memory access driver left loaded since you specified the -l flag." wide ascii
		$b1 = "Unloading MacPmem" wide ascii
		$b2 = "MacPmem load tag is" wide ascii

	condition:
		MachO and 2 of ( $a* ) or all of ( $b* )
}

rule hacktool_macos_manwhoami_icloudcontacts
{
	meta:
		description = "Pulls iCloud Contacts for an account. No dependencies. No user notification."
		reference = "https://github.com/manwhoami/iCloudContacts"
		author = "@mimeframe"

	strings:
		$a1 = "https://setup.icloud.com/setup/authenticate/" wide ascii
		$a2 = "https://p04-contacts.icloud.com/" wide ascii
		$a3 = "HTTP Error 401: Unauthorized. Are you sure the credentials are correct?" wide ascii
		$a4 = "HTTP Error 404: URL not found. Did you enter a username?" wide ascii

	condition:
		3 of ( $a* )
}

rule hacktool_macos_manwhoami_mmetokendecrypt
{
	meta:
		description = "This program decrypts / extracts all authorization tokens on macOS / OS X / OSX."
		reference = "https://github.com/manwhoami/MMeTokenDecrypt"
		author = "@mimeframe"

	strings:
		$a1 = "security find-generic-password -ws 'iCloud'" wide ascii
		$a2 = "ERROR getting iCloud Decryption Key" wide ascii
		$a3 = "Could not find MMeTokenFile. You can specify the file manually." wide ascii
		$a4 = "Decrypting token plist ->" wide ascii
		$a5 = "Successfully decrypted token plist!" wide ascii

	condition:
		3 of ( $a* )
}

rule hacktool_macos_manwhoami_osxchromedecrypt
{
	meta:
		description = "Decrypt Google Chrome / Chromium passwords and credit cards on macOS / OS X."
		reference = "https://github.com/manwhoami/OSXChromeDecrypt"
		author = "@mimeframe"

	strings:
		$a1 = "Credit Cards for Chrome Profile" wide ascii
		$a2 = "Passwords for Chrome Profile" wide ascii
		$a3 = "Unknown Card Issuer" wide ascii
		$a4 = "ERROR getting Chrome Safe Storage Key" wide ascii
		$b1 = "select name_on_card, card_number_encrypted, expiration_month, expiration_year from credit_cards" wide ascii
		$b2 = "select username_value, password_value, origin_url, submit_element from logins" wide ascii

	condition:
		3 of ( $a* ) or all of ( $b* )
}

rule hacktool_macos_n0fate_chainbreaker
{
	meta:
		description = "chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner."
		reference = "https://github.com/n0fate/chainbreaker"
		author = "@mimeframe"

	strings:
		$a1 = "[!] Private Key Table is not available" wide ascii
		$a2 = "[!] Public Key Table is not available" wide ascii
		$a3 = "[-] Decrypted Private Key" wide ascii

	condition:
		all of ( $a* )
}

rule hacktool_macos_ptoomey3_keychain_dumper
{
	meta:
		description = "Keychain dumping utility."
		reference = "https://github.com/ptoomey3/Keychain-Dumper"
		author = "@mimeframe"

	strings:
		$a1 = "keychain_dumper" wide ascii
		$a2 = "/var/Keychains/keychain-2.db" wide ascii
		$a3 = "<key>keychain-access-groups</key>" wide ascii
		$a4 = "SELECT DISTINCT agrp FROM genp UNION SELECT DISTINCT agrp FROM inet" wide ascii
		$a5 = "dumpEntitlements" wide ascii

	condition:
		all of ( $a* )
}

rule hacktool_multi_bloodhound_owned
{
	meta:
		description = "Bloodhound: Custom queries to document a compromise, find collateral spread of owned nodes, and visualize deltas in privilege gains"
		reference = "https://github.com/porterhau5/BloodHound-Owned/"
		author = "@fusionrace"

	strings:
		$s1 = "Find all owned Domain Admins" fullword ascii wide
		$s2 = "Find Shortest Path from owned node to Domain Admins" fullword ascii wide
		$s3 = "List all directly owned nodes" fullword ascii wide
		$s4 = "Set owned and wave properties for a node" fullword ascii wide
		$s5 = "Find spread of compromise for owned nodes in wave" fullword ascii wide
		$s6 = "Show clusters of password reuse" fullword ascii wide
		$s7 = "Something went wrong when creating SharesPasswordWith relationship" fullword ascii wide
		$s8 = "reference doc of custom Cypher queries for BloodHound" fullword ascii wide
		$s9 = "Created SharesPasswordWith relationship between" fullword ascii wide
		$s10 = "Skipping finding spread of compromise due to" fullword ascii wide

	condition:
		any of them
}

rule hacktool_multi_jtesta_ssh_mitm
{
	meta:
		description = "intercepts ssh connections to capture credentials"
		reference = "https://github.com/jtesta/ssh-mitm"
		author = "@fusionrace"

	strings:
		$a1 = "INTERCEPTED PASSWORD:" wide ascii
		$a2 = "more sshbuf problems." wide ascii

	condition:
		all of ( $a* )
}

rule hacktool_multi_masscan
{
	meta:
		description = "masscan is a performant port scanner, it produces results similar to nmap"
		reference = "https://github.com/robertdavidgraham/masscan"
		author = "@mimeframe"

	strings:
		$a1 = "EHLO masscan" fullword wide ascii
		$a2 = "User-Agent: masscan/" wide ascii
		$a3 = "/etc/masscan/masscan.conf" fullword wide ascii
		$b1 = "nmap(%s): unsupported. This code will never do DNS lookups." wide ascii
		$b2 = "nmap(%s): unsupported, we do timing WAY different than nmap" wide ascii
		$b3 = "[hint] I've got some local priv escalation 0days that might work" wide ascii
		$b4 = "[hint] VMware on Macintosh doesn't support masscan" wide ascii

	condition:
		all of ( $a* ) or any of ( $b* )
}

rule hacktool_multi_ncc_ABPTTS
{
	meta:
		description = "Allows for TCP tunneling over HTTP"
		reference = "https://github.com/nccgroup/ABPTTS"
		author = "@mimeframe"

	strings:
		$s1 = "---===[[[ A Black Path Toward The Sun ]]]===---" ascii wide
		$s2 = "https://vulnerableserver/EStatus/" ascii wide
		$s3 = "Error: no ABPTTS forwarding URL was specified. This utility will now exit." ascii wide
		$s4 = "tQgGur6TFdW9YMbiyuaj9g6yBJb2tCbcgrEq" fullword ascii wide
		$s5 = "63688c4f211155c76f2948ba21ebaf83" fullword ascii wide
		$s6 = "ABPTTSClient-log.txt" fullword ascii wide

	condition:
		any of them
}

rule hacktool_multi_ntlmrelayx
{
	meta:
		description = "https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/"
		reference = "https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py"
		author = "@mimeframe"

	strings:
		$a1 = "Started interactive SMB client shell via TCP" wide ascii
		$a2 = "Service Installed.. CONNECT!" wide ascii
		$a3 = "Done dumping SAM hashes for host:" wide ascii
		$a4 = "DA already added. Refusing to add another" wide ascii
		$a5 = "Domain info dumped into lootdir!" wide ascii

	condition:
		any of ( $a* )
}

rule hacktool_multi_pyrasite_py
{
	meta:
		description = "A tool for injecting arbitrary code into running Python processes."
		reference = "https://github.com/lmacken/pyrasite"
		author = "@fusionrace"

	strings:
		$s1 = "WARNING: ptrace is disabled. Injection will not work." fullword ascii wide
		$s2 = "A payload that connects to a given host:port and receives commands" fullword ascii wide
		$s3 = "A reverse Python connection payload." fullword ascii wide
		$s4 = "pyrasite - inject code into a running python process" fullword ascii wide
		$s5 = "The ID of the process to inject code into" fullword ascii wide
		$s6 = "This file is part of pyrasite." fullword ascii wide
		$s7 = "https://github.com/lmacken/pyrasite" fullword ascii wide
		$s8 = "Setup a communication socket with the process by injecting" fullword ascii wide
		$s9 = "a reverse subshell and having it connect back to us." fullword ascii wide
		$s10 = "Write out a reverse python connection payload with a custom port" fullword ascii wide
		$s11 = "Wait for the injected payload to connect back to us" fullword ascii wide
		$s12 = "PyrasiteIPC" fullword ascii wide
		$s13 = "A reverse Python shell that behaves like Python interactive interpreter." fullword ascii wide
		$s14 = "pyrasite cannot establish reverse" fullword ascii wide

	condition:
		any of them
}

rule hacktool_multi_responder_py
{
	meta:
		description = "Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server"
		reference = "http://www.c0d3xpl0it.com/2017/02/compromising-domain-admin-in-internal-pentest.html"
		author = "@fusionrace"

	strings:
		$s1 = "Poison all requests with another IP address than Responder's one." fullword ascii wide
		$s2 = "Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned." fullword ascii wide
		$s3 = "Enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network." fullword ascii wide
		$s4 = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query." fullword ascii wide
		$s5 = "Upstream HTTP proxy used by the rogue WPAD Proxy for outgoing requests (format: host:port)" fullword ascii wide
		$s6 = "31mOSX detected, -i mandatory option is missing" fullword ascii wide
		$s7 = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query." fullword ascii wide

	condition:
		any of them
}

private rule cobaltstrike_template_exe
{
	meta:
		description = "Template to provide executable detection Cobalt Strike payloads"
		reference = "https://www.cobaltstrike.com"
		author = "@javutin, @joseselvi"

	strings:
		$compiler = "mingw-w64 runtime failure" nocase
		$f1 = "VirtualQuery" fullword
		$f2 = "VirtualProtect" fullword
		$f3 = "vfprintf" fullword
		$f4 = "Sleep" fullword
		$f5 = "GetTickCount" fullword
		$c1 = { // Compare case insensitive with "msvcrt", char by char
                0f b6 50 01 80 fa 53 74 05 80 fa 73 75 42 0f b6
                50 02 80 fa 56 74 05 80 fa 76 75 34 0f b6 50 03
                80 fa 43 74 05 80 fa 63 75 26 0f b6 50 04 80 fa
                52 74 05 80 fa 72 75 18 0f b6 50 05 80 fa 54 74
        }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and $compiler and all of ( $f* ) and all of ( $c* )
}

import "pe"
import "math"

rule hacktool_windows_cobaltstrike_artifact_exe
{
	meta:
		description = "Detection of the Artifact payload from Cobalt Strike"
		reference = "https://www.cobaltstrike.com/help-artifact-kit"
		author = "@javutin, @joseselvi"

	condition:
		cobaltstrike_template_exe and filesize < 100KB and pe.sections [ pe.section_index ( ".data" ) ] . raw_data_size > 512 and math.entropy ( pe.sections [ pe.section_index ( ".data" ) ] . raw_data_offset , 512 ) >= 7
}

rule hacktool_windows_cobaltstrike_postexploitation
{
	meta:
		description = "Detection of strings in the post-exploitation modules of Cobalt Strike"
		reference = "https://www.cobaltstrike.com/support"
		author = "@javutin, @mimeframe"

	strings:
		$s1 = "\\devcenter\\aggressor\\external\\"

	condition:
		filesize > 10KB and filesize < 1000KB and all of ( $s* )
}

rule hacktool_windows_cobaltstrike_powershell
{
	meta:
		description = "Detection of the PowerShell payloads from Cobalt Strike"
		reference = "https://www.cobaltstrike.com/help-payload-generator"
		author = "@javutin, @joseselvi"

	strings:
		$ps1 = "Set-StrictMode -Version 2"
		$ps2 = "func_get_proc_address"
		$ps3 = "func_get_delegate_type"
		$ps4 = "FromBase64String"
		$ps5 = "VirtualAlloc"
		$ps6 = "var_code"
		$ps7 = "var_buffer"
		$ps8 = "var_hthread"

	condition:
		$ps1 at 0 and filesize < 1000KB and all of ( $ps* )
}

rule hacktool_windows_hot_potato
{
	meta:
		description = "https://foxglovesecurity.com/2016/01/16/hot-potato/"
		reference = "https://github.com/foxglovesec/Potato"
		author = "@mimeframe"

	strings:
		$a1 = "Parsing initial NTLM auth..." wide ascii
		$a2 = "Got PROPFIND for /test..." wide ascii
		$a3 = "Starting NBNS spoofer..." wide ascii
		$a4 = "Exhausting UDP source ports so DNS lookups will fail..." wide ascii
		$a5 = "Usage: potato.exe -ip" wide ascii

	condition:
		any of ( $a* )
}

rule hacktool_windows_mimikatz_copywrite
{
	meta:
		description = "Mimikatz credential dump tool: Author copywrite"
		reference = "https://github.com/gentilkiwi/mimikatz"
		author = "@fusionrace"
		md5_1 = "0c87c0ca04f0ab626b5137409dded15ac66c058be6df09e22a636cc2bcb021b8"
		md5_2 = "0c91f4ca25aedf306d68edaea63b84efec0385321eacf25419a3050f2394ee3b"
		md5_3 = "0fee62bae204cf89d954d2cbf82a76b771744b981aef4c651caab43436b5a143"
		md5_4 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
		md5_5 = "09c542ff784bf98b2c4899900d4e699c5b2e2619a4c5eff68f6add14c74444ca"
		md5_6 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"

	strings:
		$s1 = "Kiwi en C" fullword ascii wide
		$s2 = "Benjamin DELPY `gentilkiwi`" fullword ascii wide
		$s3 = "http://blog.gentilkiwi.com/mimikatz" fullword ascii wide
		$s4 = "Build with love for POC only" fullword ascii wide
		$s5 = "gentilkiwi (Benjamin DELPY)" fullword wide
		$s6 = "KiwiSSP" fullword wide
		$s7 = "Kiwi Security Support Provider" fullword wide
		$s8 = "kiwi flavor !" fullword wide

	condition:
		any of them
}

rule hacktool_windows_mimikatz_errors
{
	meta:
		description = "Mimikatz credential dump tool: Error messages"
		reference = "https://github.com/gentilkiwi/mimikatz"
		author = "@fusionrace"
		md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
		md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"

	strings:
		$s1 = "[ERROR] [LSA] Symbols" fullword ascii wide
		$s2 = "[ERROR] [CRYPTO] Acquire keys" fullword ascii wide
		$s3 = "[ERROR] [CRYPTO] Symbols" fullword ascii wide
		$s4 = "[ERROR] [CRYPTO] Init" fullword ascii wide

	condition:
		all of them
}

rule hacktool_windows_mimikatz_files
{
	meta:
		description = "Mimikatz credential dump tool: Files"
		reference = "https://github.com/gentilkiwi/mimikatz"
		author = "@fusionrace"
		md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
		md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"

	strings:
		$s1 = "kiwifilter.log" fullword wide
		$s2 = "kiwissp.log" fullword wide
		$s3 = "mimilib.dll" fullword ascii wide

	condition:
		any of them
}

rule hacktool_windows_mimikatz_modules
{
	meta:
		description = "Mimikatz credential dump tool: Modules"
		reference = "https://github.com/gentilkiwi/mimikatz"
		author = "@fusionrace"
		md5_1 = "0c87c0ca04f0ab626b5137409dded15ac66c058be6df09e22a636cc2bcb021b8"
		md5_2 = "0c91f4ca25aedf306d68edaea63b84efec0385321eacf25419a3050f2394ee3b"
		md5_3 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
		md5_4 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
		md5_5 = "0fee62bae204cf89d954d2cbf82a76b771744b981aef4c651caab43436b5a143"

	strings:
		$s1 = "mimilib" fullword ascii wide
		$s2 = "mimidrv" fullword ascii wide
		$s3 = "mimilove" fullword ascii wide

	condition:
		any of them
}

rule hacktool_windows_mimikatz_sekurlsa
{
	meta:
		description = "Mimikatz credential dump tool"
		reference = "https://github.com/gentilkiwi/mimikatz"
		author = "@fusionrace"
		SHA256_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
		SHA256_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"

	strings:
		$s1 = "dpapisrv!g_MasterKeyCacheList" fullword ascii wide
		$s2 = "lsasrv!g_MasterKeyCacheList" fullword ascii wide
		$s3 = "!SspCredentialList" ascii wide
		$s4 = "livessp!LiveGlobalLogonSessionList" fullword ascii wide
		$s5 = "wdigest!l_LogSessList" fullword ascii wide
		$s6 = "tspkg!TSGlobalCredTable" fullword ascii wide

	condition:
		all of them
}

rule hacktool_windows_moyix_creddump
{
	meta:
		description = "creddump is a python tool to extract credentials and secrets from Windows registry hives."
		reference = "https://github.com/moyix/creddump"
		author = "@mimeframe"

	strings:
		$a1 = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%" wide ascii
		$a2 = "0123456789012345678901234567890123456789" wide ascii
		$a3 = "NTPASSWORD" wide ascii
		$a4 = "LMPASSWORD" wide ascii
		$a5 = "aad3b435b51404eeaad3b435b51404ee" wide ascii
		$a6 = "31d6cfe0d16ae931b73c59d7e0c089c0" wide ascii

	condition:
		all of ( $a* )
}

rule hacktool_windows_ncc_wmicmd
{
	meta:
		description = "Command shell wrapper for WMI"
		reference = "https://github.com/nccgroup/WMIcmd"
		author = "@mimeframe"

	strings:
		$a1 = "Need to specify a username, domain and password for non local connections" wide ascii
		$a2 = "WS-Management is running on the remote host" wide ascii
		$a3 = "firewall (if enabled) allows connections" wide ascii
		$a4 = "WARNING: Didn't see stdout output finished marker - output may be truncated" wide ascii
		$a5 = "Command sleep in milliseconds - increase if getting truncated output" wide ascii
		$b1 = "0x800706BA" wide ascii
		$b2 = "NTLMDOMAIN:" wide ascii
		$b3 = "cimv2" wide ascii

	condition:
		any of ( $a* ) or all of ( $b* )
}

rule hacktool_windows_rdp_cmd_delivery
{
	meta:
		description = "Delivers a text payload via RDP (rubber ducky)"
		reference = "https://github.com/nopernik/mytools/blob/master/rdp-cmd-delivery.sh"
		author = "@fusionrace"

	strings:
		$s1 = "Usage: rdp-cmd-delivery.sh OPTIONS" ascii wide
		$s2 = "[--tofile 'c:\\test.txt' local.ps1 #will copy contents of local.ps1 to c:\\test.txt" ascii wide
		$s3 = "-cmdfile local.bat                #will execute everything from local.bat" ascii wide
		$s4 = "To deliver powershell payload, use '--cmdfile script.ps1' but inside powershell console" ascii wide

	condition:
		any of them
}

rule hacktool_windows_wmi_implant
{
	meta:
		description = "A PowerShell based tool that is designed to act like a RAT"
		reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
		author = "@fusionrace"

	strings:
		$s1 = "This really isn't applicable unless you are using WMImplant interactively." fullword ascii wide
		$s2 = "What command do you want to run on the remote system? >" fullword ascii wide
		$s3 = "Do you want to [create] or [delete] a string registry value? >" fullword ascii wide
		$s4 = "Do you want to run a WMImplant against a list of computers from a file? [yes] or [no] >" fullword ascii wide
		$s5 = "What is the name of the service you are targeting? >" fullword ascii wide
		$s6 = "This function enables the user to upload or download files to/from the attacking machine to/from the targeted machine" fullword ascii wide
		$s7 = "gen_cli - Generate the CLI command to execute a command via WMImplant" fullword ascii wide
		$s8 = "exit - Exit WMImplant" fullword ascii wide
		$s9 = "Lateral Movement Facilitation" fullword ascii wide
		$s10 = "vacant_system - Determine if a user is away from the system." fullword ascii wide
		$s11 = "Please provide the ProcessID or ProcessName flag to specify the process to kill!" fullword ascii wide

	condition:
		any of them
}

rule malware_macos_apt_sofacy_xagent
{
	meta:
		description = "sofacy xagent for macOS"
		reference_1 = "http://researchcenter.paloaltonetworks.com/2017/02/unit42-xagentosx-sofacys-xagent-macos-tool/"
		reference_2 = "https://blog.malwarebytes.com/cybercrime/2017/03/two-new-mac-backdoors-discovered/"
		author = "@mimeframe"
		md5 = "4fe4b9560e99e33dabca553e2eeee510"

	strings:
		$a1 = "remoteShell" ascii wide
		$a2 = "getInfoOSX" ascii wide
		$a3 = "ftpUpload" ascii wide
		$a4 = "startUploading" ascii wide
		$a5 = "deleteFile:" ascii wide
		$a6 = "executeShellCommand" ascii wide
		$a7 = "getFirefoxPassword" ascii wide
		$a8 = "generateRandomPathAndName" ascii wide
		$a9 = "createCryptPacket" ascii wide
		$a10 = "CameraShot" ascii wide
		$a11 = "7Cryptor" ascii wide
		$a12 = "8ICryptor" ascii wide
		$a13 = "Keylogger" ascii wide
		$a14 = "BootXLoader" ascii wide
		$a15 = "InjectApp" ascii wide
		$b1 = "/Project/XAgentOSX/" ascii wide
		$b2 = "XLoader_OSX" fullword ascii wide
		$b3 = "<span class='keylog_user_keys'>" ascii wide
		$b4 = "<span class='keylog_process'>" ascii wide
		$b5 = "<span class='keylog_spec_key'>" ascii wide
		$b6 = "<font size=4 color=red><pre>Stop take screenshot</pre></font>" ascii wide
		$c1 = "http://23.227.196.215/" ascii wide
		$c2 = "http://apple-iclods.org/" ascii wide
		$c3 = "http://apple-checker.org/" ascii wide
		$c4 = "http://apple-uptoday.org/" ascii wide
		$c5 = "http://apple-search.info" ascii wide
		$d1 = "watch/?" fullword ascii wide
		$d2 = "search/?" fullword ascii wide
		$d3 = "find/?" fullword ascii wide
		$d4 = "results/?" fullword ascii wide
		$d5 = "open/?" fullword ascii wide
		$d6 = "search/?" fullword ascii wide
		$d7 = "close/?" fullword ascii wide
		$e1 = "itwm=" fullword ascii wide
		$e2 = "text=" fullword ascii wide
		$e3 = "from=" fullword ascii wide
		$e4 = "itwm=" fullword ascii wide
		$e5 = "ags=" fullword ascii wide
		$e6 = "btnG=" fullword ascii wide
		$e7 = "oprnd=" fullword ascii wide
		$e8 = "itwm=" fullword ascii wide
		$e9 = "utm=" fullword ascii wide
		$e10 = "channel=" fullword ascii wide

	condition:
		MachO and ( 5 of ( $a* ) or any of ( $b* ) or any of ( $c* ) or 4 of ( $d* ) or 5 of ( $e* ) )
}

rule malware_macos_bella
{
	meta:
		description = "Bella is a pure python post-exploitation data mining tool & remote administration tool for macOS."
		reference = "https://github.com/Trietptm-on-Security/Bella"
		author = "@mimeframe"

	strings:
		$a1 = "Verified! [2FV Enabled] Account ->" wide ascii
		$a2 = "There is no root shell to perform this command. See [rooter] manual entry." wide ascii
		$a3 = "Attempt to escalate Bella to root through a variety of attack vectors." wide ascii
		$a4 = "BELLA IS NOW RUNNING. CONNECT TO BELLA FROM THE CONTROL CENTER." wide ascii
		$b1 = "user_pass_phish" fullword wide ascii
		$b2 = "bella_info" fullword wide ascii
		$b3 = "get_root" fullword wide ascii
		$c1 = "Please specify a bella server." wide ascii
		$c2 = "What port should Bella connect on [Default is 4545]:" wide ascii

	condition:
		any of ( $a* ) or all of ( $b* ) or all of ( $c* )
}

rule malware_macos_macspy
{
	meta:
		description = "macSpy is a malware-as-a-service (MaaS) product advertised as the most sophisticated Mac spyware ever"
		reference = "https://www.alienvault.com/blogs/labs-research/macspy-os-x-rat-as-a-service"
		author = "AlienVault Labs"
		md5 = "6c03e4a9bcb9afaedb7451a33c214ae4"

	strings:
		$header0 = {cf fa ed fe}
		$header1 = {ce fa ed fe}
		$header2 = {ca fe ba be}
		$c1 = { 76 31 09 00 76 32 09 00 76 33 09 00 69 31 09 00 69 32 09 00 69 33 09 00 69 34 09 00 66 31 09 00 66 32 09 00 66 33 09 00 66 34 09 00 74 63 3A 00 }

	condition:
		($header0 at 0 or $header1 at 0 or $header2 at 0 ) and $c1
}

rule malware_macos_marten4n6_evilosx
{
	meta:
		description = "EvilOSX is a pure python, post-exploitation, RAT (Remote Administration Tool) for macOS / OSX."
		reference = "https://github.com/Marten4n6/EvilOSX"
		author = "@mimeframe"

	strings:
		$a1 = "icloud_phish_stop" fullword wide ascii
		$a2 = "icloud_contacts" fullword wide ascii
		$a3 = "itunes_backups" fullword wide ascii
		$a4 = "chrome_passwords" fullword wide ascii
		$a5 = "Starting EvilOSX..." wide ascii

	condition:
		4 of ( $a* )
}

rule malware_macos_neoneggplant_eggshell
{
	meta:
		description = "EggShell is an iOS and macOS post exploitation surveillance pentest tool written in Python."
		reference = "https://github.com/neoneggplant/EggShell"
		author = "@mimeframe"

	strings:
		$a1 = "Created By Lucas Jackson (@neoneggplant)" wide ascii
		$a2 = "SET LHOST (Leave blank for" wide ascii
		$a3 = "SET LPORT (Leave blank for" wide ascii
		$b1 = "/tmp/.esplog" wide ascii
		$b2 = "spGHbigdxMBJpbOCAr3rnS3inCdYQyZV" wide ascii
		$b3 = "keylogclear" wide ascii
		$b4 = "getpasscode" wide ascii
		$c1 = "spGHbigdxMBJpbOCAr3rnS3inCdYQyZV" wide ascii
		$c2 = "getfacebook" wide ascii
		$c3 = "type is eggsu" wide ascii
		$c4 = "rmpersistence" wide ascii

	condition:
		all of ( $a* ) or 3 of ( $b* ) or 3 of ( $c* )
}

rule malware_macos_proton_rat_generic
{
	meta:
		description = "https://www.hackread.com/hackers-selling-undetectable-proton-mac-malware/"
		reference = "https://objective-see.com/blog/blog_0x1D.html"
		author = "@mimeframe"
		md5 = "6a2d0c8b20efc3fa283176a4bc76d6fd"

	strings:
		$a1 = "SRWebSocket" nocase wide ascii
		$a2 = "SocketRocket" nocase wide ascii
		$b1 = "SSH tunnel not launched" nocase wide ascii
		$b2 = "SSH tunnel still running" nocase wide ascii
		$b3 = "SSH tunnel already launched" nocase wide ascii
		$b4 = "Entering interactive session." nocase wide ascii

	condition:
		MachO and any of ( $a* ) and any of ( $b* )
}

rule malware_multi_pupy_rat
{
	meta:
		description = "pupy - opensource cross platform rat and post-exploitation tool"
		reference = "https://github.com/n1nj4sec/pupy"
		author = "@mimeframe"

	strings:
		$a1 = "dumping lsa secrets" nocase wide ascii
		$a2 = "dumping cached domain passwords" nocase wide ascii
		$a3 = "the keylogger is already started" nocase wide ascii
		$a4 = "pupyutils.dns" wide ascii
		$a5 = "pupwinutils.security" wide ascii
		$a6 = "-PUPY_CONFIG_COMES_HERE-" wide ascii

	condition:
		3 of ( $a* )
}

rule malware_multi_vesche_basicrat
{
	meta:
		description = "cross-platform Python 2.x Remote Access Trojan (RAT)"
		reference = "https://github.com/vesche/basicRAT"
		author = "@mimeframe"

	strings:
		$a1 = "HKCU Run registry key applied" wide ascii
		$a2 = "HKCU Run registry key failed" wide ascii
		$a3 = "Error, platform unsupported." wide ascii
		$a4 = "Persistence successful," wide ascii
		$a5 = "Persistence unsuccessful," wide ascii

	condition:
		all of ( $a* )
}

rule malware_windows_apt_red_leaves_generic
{
	meta:
		description = "Red Leaves malware, related to APT10"
		reference = "https://github.com/nccgroup/Cyber-Defence/blob/master/Technical%20Notes/Red%20Leaves/Source/Red%20Leaves%20technical%20note%20v1.0.md"
		author = "David Cannings"
		md5 = "81df89d6fa0b26cadd4e50ef5350f341"

	strings:
		$a1 = "Feb 04 2015"
		$a2 = "I can not start %s"
		$a3 = "dwConnectPort" fullword
		$a4 = "dwRemoteLanPort" fullword
		$a5 = "strRemoteLanAddress" fullword
		$a6 = "strLocalConnectIp" fullword
		$a7 = "\\\\.\\pipe\\NamePipe_MoreWindows" wide
		$a8 = "RedLeavesCMDSimulatorMutex" wide
		$a9 = "(NT %d.%d Build %d)" wide
		$a10 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)" wide
		$a11 = "red_autumnal_leaves_dllmain.dll" wide ascii
		$a12 = "__data" wide
		$a13 = "__serial" wide
		$a14 = "__upt" wide
		$a15 = "__msgid" wide

	condition:
		7 of ( $a* )
}

rule malware_windows_apt_whitebear_binary_loader_1
{
	meta:
		description = "The WhiteBear loader contains a set of messaging and injection components that support continued presence on victim hosts"
		reference = "https://securelist.com/introducing-whitebear/81638/"
		author = "@fusionrace"
		md5 = "b099b82acb860d9a9a571515024b35f0"

	strings:
		$a1 = "### PE STORAGE ###" wide ascii
		$a2 = "### CRYPTO 0 ###" wide ascii
		$a3 = "### EXTERNAL STORAGE ###" wide ascii
		$a4 = "### CRYPTO 1 ###" wide ascii
		$a5 = "### QUEUES ###" wide ascii
		$a6 = "### TRANSPORT ###" wide ascii
		$a7 = "### EXECUTION SUBSYSTEM ###" wide ascii
		$a8 = "### AUTORUN MANAGER ###" wide ascii
		$a9 = "### INJECT MANAGER ###" wide ascii
		$a10 = "### LOCAL TRANSPORT MANAGER ###" wide ascii

	condition:
		6 of ( $a* )
}

rule malware_windows_apt_whitebear_binary_loader_2
{
	meta:
		description = "The WhiteBear loader contains a set of messaging and injection components that support continued presence on victim hosts"
		reference = "https://securelist.com/introducing-whitebear/81638/"
		author = "@fusionrace"
		md5 = "06bd89448a10aa5c2f4ca46b4709a879"

	strings:
		$b1 = "i cunt waiting anymore #%d" wide ascii
		$b2 = "lights aint turnt off with #%d" wide ascii
		$b3 = "Not find process" wide ascii
		$b4 = "CMessageProcessingSystem::Receive_TAKE_NOP" wide ascii
		$b5 = "CMessageProcessingSystem::Receive_TAKE_CAN_NOT_WORK" wide ascii

	condition:
		3 of ( $b* )
}

rule malware_windows_apt_whitebear_binary_loader_3
{
	meta:
		description = "The WhiteBear loader contains a set of messaging and injection components that support continued presence on victim hosts"
		reference = "https://securelist.com/introducing-whitebear/81638/"
		author = "@fusionrace"
		md5 = "b099b82acb860d9a9a571515024b35f0"

	strings:
		$c1 = "{531511FA-190D-5D85-8A4A-279F2F592CC7}" wide ascii
		$c2 = "IsLoaderAlreadyWork" wide ascii
		$c3 = "\\\\.\\pipe\\Winsock2\\CatalogChangeListener-%03x%01x-%01x" wide ascii
		$c4 = "\\\\.\\pipe\\Winsock2\\CatalogChangeListener-%02x%02x-%01x" wide ascii

	condition:
		all of ( $c* )
}

rule ccleaner_backdoor
{
	meta:
		description = "Ccleaner 5.33 backdoor with a possible APT17/Group72 connection."
		reference = "http://blog.talosintelligence.com/2017/09/ccleaner-c2-concern.html"
		author = "@fusionrace"
		md5_1 = "d488e4b61c233293bec2ee09553d3a2f"
		md5_2 = "b95911a69e49544f9ecc427478eb952f"
		md5_3 = "063b58879c8197b06d619c3be90506ec"
		md5_4 = "7690e414e130acf7c962774c05283142"

	strings:
		$s1 = "s:\\workspace\\ccleaner\\branches\\v5.33" fullword ascii wide

	condition:
		$s1
}

rule malware_windows_moonlightmaze_IRIX_exploit_GEN
{
	meta:
		description = "Rule to detect Irix exploits from David Hedley used by Moonlight Maze hackers"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		reference2 = "https://www.exploit-db.com/exploits/19274/"
		author = "Kaspersky Lab"
		md5_1 = "008ea82f31f585622353bd47fa1d84be"
		md5_2 = "a26bad2b79075f454c83203fa00ed50c"
		md5_3 = "f67fc6e90f05ba13f207c7fdaa8c2cab"
		md5_4 = "5937db3896cdd8b0beb3df44e509e136"
		md5_5 = "f4ed5170dcea7e5ba62537d84392b280"

	strings:
		$a1 = "stack = 0x%x, targ_addr = 0x%x"
		$a2 = "execl failed"

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( all of them )
}

rule malware_windows_moonlightmaze_cle_tool
{
	meta:
		description = "Rule to detect Moonlight Maze 'cle' log cleaning tool"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Kaspersky Lab"
		md5 = "647d7b711f7b4434145ea30d0ef207b0"

	strings:
		$a1 = "./a filename template_file" ascii wide
		$a2 = "May be %s is empty?" ascii wide
		$a3 = "template string = |%s|" ascii wide
		$a4 = "No blocks !!!"
		$a5 = "No data in this block !!!!!!" ascii wide
		$a6 = "No good line"

	condition:
		3 of ( $a* )
}

rule malware_windows_moonlightmaze_custom_sniffer
{
	meta:
		description = "Rule to detect Moonlight Maze sniffer tools"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Kaspersky Lab"
		md5_1 = "7b86f40e861705d59f5206c482e1f2a5"
		md5_2 = "927426b558888ad680829bd34b0ad0e7"

	strings:
		$a1 = "/var/tmp/gogo" fullword
		$a2 = "myfilename= |%s|" fullword
		$a3 = "mypid,mygid=" fullword
		$a4 = "mypid=|%d| mygid=|%d|" fullword
		$a5 = "/var/tmp/task" fullword
		$a6 = "mydevname= |%s|" fullword

	condition:
		any of ( $a* )
}

rule malware_windows_moonlightmaze_de_tool
{
	meta:
		description = "Rule to detect Moonlight Maze 'de' and 'deg' tunnel tool"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Kaspersky Lab"
		md5_1 = "4bc7ed168fb78f0dc688ee2be20c9703"
		md5_2 = "8b56e8552a74133da4bc5939b5f74243"

	strings:
		$a1 = "Vnuk: %d" ascii fullword
		$a2 = "Syn: %d" ascii fullword
		$a3 = {25 73 0A 25 73 0A 25 73 0A 25 73 0A}

	condition:
		2 of ( $a* )
}

rule malware_windows_moonlightmaze_encrypted_keyloger
{
	meta:
		description = "Rule to detect Moonlight Maze encrypted keylogger logs"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Kaspersky Lab"

	strings:
		$a1 = {47 01 22 2A 6D 3E 39 2C}

	condition:
		($a1 at 0 )
}

rule malware_windows_moonlightmaze_loki
{
	meta:
		description = "Rule to detect Moonlight Maze Loki samples by custom attacker-authored strings"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Kaspersky Lab"
		md5_1 = "14cce7e641d308c3a177a8abb5457019"
		md5_2 = "a3164d2bbc45fb1eef5fde7eb8b245ea"
		md5_3 = "dabee9a7ea0ddaf900ef1e3e166ffe8a"
		md5_4 = "1980958afffb6a9d5a6c73fc1e2795c2"
		md5_5 = "e59f92aadb6505f29a9f368ab803082e"

	strings:
		$a1 = "Write file Ok..." ascii wide
		$a2 = "ERROR: Can not open socket...." ascii wide
		$a3 = "Error in parametrs:" ascii wide
		$a4 = "Usage: @<get/put> <IP> <PORT> <file>" ascii wide
		$a5 = "ERROR: Not connect..." ascii wide
		$a6 = "Connect successful...." ascii wide
		$a7 = "clnt <%d> rqstd n ll kll" ascii wide
		$a8 = "clnt <%d> rqstd swap" ascii wide
		$a9 = "cld nt sgnl prcs grp" ascii wide
		$a10 = "cld nt sgnl prnt" ascii wide
		$a11 = "ork error" ascii fullword

	condition:
		2 of ( $a* )
}

rule malware_windows_moonlightmaze_loki2crypto
{
	meta:
		description = "Rule to detect hardcoded DH modulus used in 1996/1997 Loki2 sourcecode; #ifdef STRONG_CRYPTO /* 384-bit strong prime */"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Costin Raiu, Kaspersky Lab"
		md5_1 = "19fbd8cbfb12482e8020a887d6427315"
		md5_2 = "ea06b213d5924de65407e8931b1e4326"
		md5_3 = "14ecd5e6fc8e501037b54ca263896a11"
		md5_4 = "e079ec947d3d4dacb21e993b760a65dc"
		md5_5 = "edf900cebb70c6d1fcab0234062bfc28"

	strings:
		$modulus = {DA E1 01 CD D8 C9 70 AF C2 E4 F2 7A 41 8B 43 39 52 9B 4B 4D E5 85 F8 49}

	condition:
		$modulus
}

rule malware_windows_moonlightmaze_u_logcleaner
{
	meta:
		description = "Rule to detect log cleaners based on utclean.c"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		reference2 = "http://cd.textfiles.com/cuteskunk/Unix-Hacking-Exploits/utclean.c"
		author = "Kaspersky Lab"
		md5_1 = "d98796dcda1443a37b124dbdc041fe3b"
		md5_2 = "73a518f0a73ab77033121d4191172820"

	strings:
		$a1 = "Hiding complit...n"
		$a2 = "usage: %s <username> <fixthings> [hostname]"
		$a3 = "ls -la %s* ; /bin/cp  ./wtmp.tmp %s; rm  ./wtmp.tmp"

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( any of them )
}

rule malware_windows_moonlightmaze_wipe
{
	meta:
		description = "Rule to detect log cleaner based on wipe.c"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		reference2 = "http://www.afn.org/~afn28925/wipe.c"
		author = "Kaspersky Lab"
		md5 = "e69efc504934551c6a77b525d5343241"

	strings:
		$a1 = "ERROR: Unlinking tmp WTMP file."
		$a2 = "USAGE: wipe [ u|w|l|a ] ...options..."
		$a3 = "Erase acct entries on tty :   wipe a [username] [tty]"
		$a4 = "Alter lastlog entry       :   wipe l [username] [tty] [time] [host]"

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( 2 of them )
}

rule malware_windows_moonlightmaze_xk_keylogger
{
	meta:
		description = "Rule to detect Moonlight Maze 'xk' keylogger"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Kaspersky Lab"

	strings:
		$a1 = "Log ended at => %s"
		$a2 = "Log started at => %s [pid %d]"
		$a3 = "/var/tmp/task" fullword
		$a4 = "/var/tmp/taskhost" fullword
		$a5 = "my hostname: %s"
		$a6 = "/var/tmp/tasklog"
		$a7 = "/var/tmp/.Xtmp01" fullword
		$a8 = "myfilename=-%s-"
		$a9 = "/var/tmp/taskpid"
		$a10 = "mypid=-%d-" fullword
		$a11 = "/var/tmp/taskgid" fullword
		$a12 = "mygid=-%d-" fullword

	condition:
		3 of ( $a* )
}

rule malware_windows_pony_stealer
{
	meta:
		description = "Pony stealer malware"
		reference = "https://www.knowbe4.com/pony-stealer"
		author = "@mimeframe"
		md5 = "5e52ce394c3be2a685dbb8f435e2f64f"

	strings:
		$a1 = "signons.sqlite" nocase wide ascii
		$a2 = "signons.txt" nocase wide ascii
		$a3 = "signons2.txt" nocase wide ascii
		$a4 = "signons3.txt" nocase wide ascii
		$a5 = "WininetCacheCredentials" nocase wide ascii
		$a6 = "moz_logins" nocase wide ascii
		$a7 = "encryptedPassword" nocase wide ascii
		$a8 = "FlashFXP" nocase wide ascii
		$a9 = "BulletProof" nocase wide ascii
		$a10 = "CuteFTP" nocase wide ascii

	condition:
		all of ( $a* )
}

rule malware_windows_remcos_rat
{
	meta:
		description = "https://blog.fortinet.com/2017/02/14/remcos-a-new-rat-in-the-wild-2"
		reference = "https://breaking-security.net/remcos/remcos-changelog/"
		author = "@mimeframe"
		md5 = "c8dafe143fe1d81ae6a3c0cd4724b272"

	strings:
		$a1 = "[Following text has been pasted from clipboard:]" wide ascii
		$a2 = "[Chrome StoredLogins found, cleared!]" wide ascii
		$a3 = "[Firefox StoredLogins cleared!]" wide ascii
		$b1 = "getclipboard" wide ascii
		$b2 = "stopmiccapture" wide ascii
		$b3 = "downloadfromurltofile" wide ascii
		$b4 = "getcamsingleframe" wide ascii
		$c1 = "Breaking-Security.Net" wide ascii
		$c2 = "REMCOS v" wide ascii

	condition:
		any of ( $a* ) or 3 of ( $b* ) or all of ( $c* )
}

rule malware_windows_t3ntman_crunchrat
{
	meta:
		description = "HTTPS-based Remote Administration Tool (RAT)"
		reference = "https://github.com/t3ntman/CrunchRAT"
		author = "@mimeframe"

	strings:
		$a1 = "<action>command<action>" wide ascii
		$a2 = "<action>upload<action>" wide ascii
		$a3 = "<action>download<action>" wide ascii
		$a4 = "cmd.exe" wide ascii
		$a5 = "application/x-www-form-urlencoded" wide ascii
		$a6 = "&action=" wide ascii
		$a7 = "&secondary=" wide ascii
		$a8 = "<secondary>" wide ascii
		$a9 = "<action>" wide ascii

	condition:
		all of ( $a* )
}

rule malware_windows_winnti_loadperf_dll_loader
{
	meta:
		description = "Winnti APT group; gzwrite64 imported from loadoerf.ini"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/winnti-abuses-github/"
		author = "@mimeframe"
		md5 = "879ce99e253e598a3c156258a9e81457"

	strings:
		$s1 = "loadoerf.ini" fullword ascii wide
		$s2 = "gzwrite64" fullword ascii wide

	condition:
		all of ( $s* )
}

rule malware_windows_xrat_quasarrat
{
	meta:
		description = "xRAT is a derivative of QuasarRAT; this catches both RATs."
		reference = "https://github.com/quasar/QuasarRAT"
		author = "@mimeframe"

	strings:
		$a1 = ">> New Session created" wide ascii
		$a2 = ">> Session unexpectedly closed" wide ascii
		$a3 = ">> Session closed" wide ascii
		$a4 = "session unexpectedly closed" wide ascii
		$a5 = "cmd" fullword wide ascii
		$a6 = "/K" fullword wide ascii
		$b1 = "echo DONT CLOSE THIS WINDOW!" wide ascii
		$b2 = "ping -n 20 localhost > nul" wide ascii
		$b3 = "Downloading file..." wide ascii
		$b4 = "Visited Website" wide ascii
		$b5 = "Adding Autostart Item failed!" wide ascii
		$b6 = ":Zone.Identifier" wide ascii
		$c1 = "GetDrives I/O error" wide ascii
		$c2 = "/r /t 0" wide ascii
		$c3 = "desktop.ini" wide ascii
		$c4 = "WAN IP Address" wide ascii
		$c5 = "User refused the elevation request." wide ascii
		$c6 = "Process already elevated." wide ascii

	condition:
		5 of ( $a* ) or 5 of ( $b* ) or 5 of ( $c* )
}

rule ransomware_windows_HDDCryptorA
{
	meta:
		description = "The HDDCryptor ransomware encrypts local harddisks as well as resources in network shares via Server Message Block (SMB)"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/bksod-by-ransomware-hddcryptor-uses-commercial-tools-to-encrypt-network-shares-and-lock-hdds/"
		author = "@fusionrace"
		md5 = "498bdcfb93d13fecaf92e96f77063abf"

	strings:
		$u1 = "You are Hacked" fullword ascii wide
		$u2 = "Your H.D.D Encrypted , Contact Us For Decryption Key" nocase ascii wide
		$u3 = "start hard drive encryption..." ascii wide
		$u4 = "Your hard drive is securely encrypted" ascii wide
		$g1 = "Wipe All Passwords?" ascii wide
		$g2 = "SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config" ascii wide
		$g3 = "DiskCryptor" ascii wide
		$g4 = "dcinst.exe" fullword ascii wide
		$g5 = "dcrypt.exe" fullword ascii wide
		$g6 = "you can only use AES to encrypt the boot partition!" ascii wide

	condition:
		2 of ( $u* ) or 4 of ( $g* )
}

rule ransomware_windows_cerber_evasion
{
	meta:
		description = "Cerber Ransomware: Evades detection by machine learning applications"
		reference_1 = "http://blog.trendmicro.com/trendlabs-security-intelligence/cerber-starts-evading-machine-learning/"
		reference_2 = "http://www.darkreading.com/vulnerabilities---threats/cerber-ransomware-now-evades-machine-learning/d/d-id/1328506"
		author = "@fusionrace"
		md5 = "bc62b557d48f3501c383f25d014f22df"

	strings:
		$s1 = "38oDr5.vbs" fullword ascii wide
		$s2 = "8ivq.dll" fullword ascii wide
		$s3 = "jmsctls_progress32" fullword ascii wide

	condition:
		all of them
}

rule ransomware_windows_cryptolocker
{
	meta:
		description = "The CryptoLocker malware propagated via infected email attachments, and via an existing botnet; when activated, the malware encrypts files stored on local and mounted network drives"
		reference = "https://www.secureworks.com/research/cryptolocker-ransomware"
		author = "@fusionrace"
		md5 = "012d9088558072bc3103ab5da39ddd54"

	strings:
		$u0 = "Paysafecard is an electronic payment method for predominantly online shopping" fullword ascii wide
		$u1 = "bb to select the method of payment and the currency." fullword ascii wide
		$u2 = "Where can I purchase a MoneyPak?" fullword ascii wide
		$u3 = "Ukash is electronic cash and e-commerce brand." fullword ascii wide
		$u4 = "You have to send below specified amount to Bitcoin address" fullword ascii wide
		$u5 = "cashU is a prepaid online" fullword ascii wide
		$u6 = "Your important files \\b encryption" fullword ascii wide
		$u7 = "Encryption was produced using a \\b unique\\b0  public key" fullword ascii wide
		$u8 = "then be used to pay online, or loaded on to a prepaid card or eWallet." fullword ascii wide
		$u9 = "Arabic online gamers and e-commerce buyers." fullword ascii wide

	condition:
		2 of them
}

rule ransomware_windows_hydracrypt
{
	meta:
		description = "HydraCrypt encrypts a victim’s files and appends the filenames with the extension “hydracrypt_ID_*"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/hydracrypt-variant-of-ransomware-distributed-by-angler-exploit-kit/"
		author = "@fusionrace"
		md5 = "08b304d01220f9de63244b4666621bba"

	strings:
		$u0 = "oTraining" fullword ascii wide
		$u1 = "Stop Training" fullword ascii wide
		$u2 = "Play \"sound.wav\"" fullword ascii wide
		$u3 = "&Start Recording" fullword ascii wide
		$u4 = "7About record" fullword ascii wide

	condition:
		all of them
}

rule ransomware_windows_lazarus_wannacry
{
	meta:
		description = "Rule based on shared code between Feb 2017 Wannacry sample and Lazarus backdoor from Feb 2015 discovered by Neel Mehta"
		reference = "https://twitter.com/neelmehta/status/864164081116225536"
		author = "Costin G. Raiu, Kaspersky Lab"
		md5_1 = "9c7c7149387a1c79679a87dd1ba755bc"
		md5_2 = "ac21c8ad899727137c4b94458d7aa8d8"

	strings:
		$a1 = {
        51 53 55 8B 6C 24 10 56 57 6A 20 8B 45 00 8D 75
        04 24 01 0C 01 46 89 45 00 C6 46 FF 03 C6 06 01
        46 56 E8
        }
		$a2 = {
        03 00 04 00 05 00 06 00 08 00 09 00 0A 00 0D 00
        10 00 11 00 12 00 13 00 14 00 15 00 16 00 2F 00
        30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00
        38 00 39 00 3C 00 3D 00 3E 00 3F 00 40 00 41 00
        44 00 45 00 46 00 62 00 63 00 64 00 66 00 67 00
        68 00 69 00 6A 00 6B 00 84 00 87 00 88 00 96 00
        FF 00 01 C0 02 C0 03 C0 04 C0 05 C0 06 C0 07 C0
        08 C0 09 C0 0A C0 0B C0 0C C0 0D C0 0E C0 0F C0
        10 C0 11 C0 12 C0 13 C0 14 C0 23 C0 24 C0 27 C0
        2B C0 2C C0 FF FE
        }

	condition:
		(( uint16( 0 ) == 0x5A4D ) ) and all of them
}

rule ransomware_windows_petya_variant_1
{
	meta:
		description = "Petya Ransomware new variant June 2017 using ETERNALBLUE"
		reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
		author = "@fusionrace"
		md5 = "71b6a493388e7d0b40c83ce903bc6b04"

	strings:
		$s1 = "Ooops, your important files are encrypted." fullword ascii wide
		$s2 = "Send your Bitcoin wallet ID and personal installation key to e-mail" fullword ascii wide
		$s3 = "wowsmith123456@posteo.net. Your personal installation key:" fullword ascii wide
		$s4 = "Send $300 worth of Bitcoin to following address:" fullword ascii wide
		$s5 = "have been encrypted.  Perhaps you are busy looking for a way to recover your" fullword ascii wide
		$s6 = "need to do is submit the payment and purchase the decryption key." fullword ascii wide

	condition:
		any of them
}

rule ransomware_windows_petya_variant_2
{
	meta:
		description = "Petya Ransomware new variant June 2017 using ETERNALBLUE"
		reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
		author = "@fusionrace"
		md5 = "71b6a493388e7d0b40c83ce903bc6b04"

	strings:
		$s1 = "dllhost.dat" fullword wide
		$s2 = "\\\\%ws\\admin$\\%ws" fullword wide
		$s3 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\"" fullword wide
		$s4 = "\\\\.\\PhysicalDrive" fullword wide
		$s5 = ".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls.xlsx.xvd.zip." fullword wide

	condition:
		3 of them
}

rule ransomware_windows_petya_variant_3
{
	meta:
		description = "Petya Ransomware new variant June 2017 using ETERNALBLUE"
		reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
		author = "@fusionrace"
		md5 = "71b6a493388e7d0b40c83ce903bc6b04"

	strings:
		$s1 = "wevtutil cl Setup & wevtutil cl System" fullword wide
		$s2 = "fsutil usn deletejournal /D %c:" fullword wide

	condition:
		any of them
}

rule ransomware_windows_petya_variant_bitcoin
{
	meta:
		description = "Petya Ransomware new variant June 2017 using ETERNALBLUE: Bitcoin"
		reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
		author = "@fusionrace"
		md5 = "71b6a493388e7d0b40c83ce903bc6b04"

	strings:
		$s1 = "MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB" fullword wide

	condition:
		$s1
}

rule ransomware_windows_powerware_locky
{
	meta:
		description = "PowerWare Ransomware"
		reference = "https://researchcenter.paloaltonetworks.com/2016/07/unit42-powerware-ransomware-spoofing-locky-malware-family/"
		author = "@fusionrace"
		md5 = "3433a4da9d8794709630eb06afd2b8c1"

	strings:
		$s0 = "ScriptRunner.dll" fullword ascii wide
		$s1 = "ScriptRunner.pdb" fullword ascii wide
		$s2 = "fixed.ps1" fullword ascii wide

	condition:
		all of them
}

rule ransomware_windows_wannacry
{
	meta:
		description = "wannacry ransomware for windows"
		reference = "https://securelist.com/blog/incidents/78351/wannacry-ransomware-used-in-widespread-attacks-all-over-the-world/"
		author = "@fusionrace"
		md5 = "4fef5e34143e646dbf9907c4374276f5"

	strings:
		$a1 = "msg/m_chinese" wide ascii
		$a2 = ".wnry" wide ascii
		$a3 = "attrib +h" wide ascii
		$b1 = "WNcry@2ol7" wide ascii
		$b2 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" wide ascii
		$b3 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" wide ascii
		$b4 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" wide ascii
		$b5 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" wide ascii

	condition:
		all of ( $a* ) or any of ( $b* )
}

rule ransomware_windows_zcrypt
{
	meta:
		description = "Zcrypt will encrypt data and append the .zcrypt extension to the filenames"
		reference = "https://blog.malwarebytes.com/threat-analysis/2016/06/zcrypt-ransomware/"
		author = "@fusionrace"
		md5 = "d1e75b274211a78d9c5d38c8ff2e1778"

	strings:
		$u1 = "How to Buy Bitcoins" ascii wide
		$u2 = "ALL YOUR PERSONAL FILES ARE ENCRYPTED" ascii wide
		$u3 = "Click Here to Show Bitcoin Address" ascii wide
		$u4 = "MyEncrypter2.pdb" fullword ascii wide
		$g1 = ".p7b" fullword ascii wide
		$g2 = ".p7c" fullword ascii wide
		$g3 = ".pdd" fullword ascii wide
		$g4 = ".pef" fullword ascii wide
		$g5 = ".pem" fullword ascii wide
		$g6 = "How to decrypt files.html" fullword ascii wide

	condition:
		any of ( $u* ) or all of ( $g* )
}
