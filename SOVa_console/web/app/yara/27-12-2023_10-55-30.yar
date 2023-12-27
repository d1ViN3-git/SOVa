rule MSIETabularActivex
{
        meta:
                ref = "CVE-2010-0805"
                impact = 7
                hide = true
                author = "@d3t0n4t0r"
        strings:
                $cve20100805_1 = "333C7BC4-460F-11D0-BC04-0080C7055A83" nocase fullword
                $cve20100805_2 = "DataURL" nocase fullword
                $cve20100805_3 = "true"
        condition:
                ($cve20100805_1 and $cve20100805_3) or (all of them)
}
rule JavaDeploymentToolkit
{
   meta:
      ref = "CVE-2010-0887"
      impact = 7
      author = "@d3t0n4t0r"
   strings:
      $cve20100887_1 = "CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" nocase fullword
      $cve20100887_2 = "document.createElement(\"OBJECT\")" nocase fullword
      $cve20100887_3 = "application/npruntime-scriptable-plugin;deploymenttoolkit" nocase fullword
      $cve20100887_4 = "application/java-deployment-toolkit" nocase fullword
      $cve20100887_5 = "document.body.appendChild(" nocase fullword
      $cve20100887_6 = "launch("
      $cve20100887_7 = "-J-jar -J" nocase fullword
   condition:
      3 of them
}
rule FlashNewfunction: decodedPDF
{
   meta:  
      ref = "CVE-2010-1297"
      hide = true
      impact = 5 
      ref = "http://blog.xanda.org/tag/jsunpack/"
   strings:
      $unescape = "unescape" fullword nocase
      $shellcode = /%u[A-Fa-f0-9]{4}/
      $shellcode5 = /(%u[A-Fa-f0-9]{4}){5}/
      $cve20101297 = /\/Subtype ?\/Flash/
   condition:
      ($unescape and $shellcode and $cve20101297) or ($shellcode5 and $cve20101297)
}
rule CVE_2012_0158_KeyBoy {
  meta:
      author = "Etienne Maynier <etienne@citizenlab.ca>"
      description = "CVE-2012-0158 variant"
      file = "8307e444cad98b1b59568ad2eba5f201"

  strings:
      $a = "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001" nocase // OLE header
      $b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" nocase // junk data
      $c = /5(\{\\b0\}|)[ ]*2006F00(\{\\b0\}|)[ ]*6F007(\{\\b0\}|)[ ]*400200045(\{\\b0\}|)[ ]*006(\{\\b0\}|)[ ]*E007(\{\\b0\}|)[ ]*400720079/ nocase
      $d = "MSComctlLib.ListViewCtrl.2"
      $e = "ac38c874503c307405347aaaebf2ac2c31ebf6e8e3" nocase //decoding shellcode


  condition:
      all of them
}
rule CVE_2013_0422
{
        meta:
                description = "Java Applet JMX Remote Code Execution"
                cve = "CVE-2013-0422"
                ref = "http://pastebin.com/JVedyrCe"
                author = "adnan.shukor@gmail.com"
                date = "12-Jan-2013"
                version = "1"
                impact = 4
                hide = false
        strings:
                $0422_1 = "com/sun/jmx/mbeanserver/JmxMBeanServer" fullword
                $0422_2 = "com/sun/jmx/mbeanserver/JmxMBeanServerBuilder" fullword
                $0422_3 = "com/sun/jmx/mbeanserver/MBeanInstantiator" fullword
                $0422_4 = "findClass" fullword
                $0422_5 = "publicLookup" fullword
                $class = /sun\.org\.mozilla\.javascript\.internal\.(Context|GeneratedClassLoader)/ fullword 
        condition:
                (all of ($0422_*)) or (all of them)
}
rule Exploit_MS15_077_078: Exploit {
	meta:
		description = "MS15-078 / MS15-077 exploit - generic signature"
		author = "Florian Roth"
		reference = "https://code.google.com/p/google-security-research/issues/detail?id=473&can=1&start=200"
		date = "2015-07-21"
		hash1 = "18e3e840a5e5b75747d6b961fca66a670e3faef252aaa416a88488967b47ac1c"
		hash2 = "0b5dc030e73074b18b1959d1cf7177ff510dbc2a0ec2b8bb927936f59eb3d14d"
		hash3 = "fc609adef44b5c64de029b2b2cff22a6f36b6bdf9463c1bd320a522ed39de5d9"
		hash4 = "ad6bb982a1ecfe080baf0a2b27950f989c107949b1cf02b6e0907f1a568ece15"
	strings:
		$s1 = "GDI32.DLL" fullword ascii
		$s2 = "atmfd.dll" fullword wide
		$s3 = "AddFontMemResourceEx" fullword ascii
		$s4 = "NamedEscape" fullword ascii
		$s5 = "CreateBitmap" fullword ascii
		$s6 = "DeleteObject" fullword ascii

		$op0 = { 83 45 e8 01 eb 07 c7 45 e8 } /* Opcode */
		$op1 = { 8d 85 24 42 fb ff 89 04 24 e8 80 22 00 00 c7 45 } /* Opcode */
		$op2 = { eb 54 8b 15 6c 00 4c 00 8d 85 24 42 fb ff 89 44 } /* Opcode */
		$op3 = { 64 00 88 ff 84 03 70 03 }
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of ($s*) or all of ($op*)
}

rule Exploit_MS15_077_078_HackingTeam: Exploit {
	meta:
		description = "MS15-078 / MS15-077 exploit - Hacking Team code"
		author = "Florian Roth"
		date = "2015-07-21"
		super_rule = 1
		hash1 = "ad6bb982a1ecfe080baf0a2b27950f989c107949b1cf02b6e0907f1a568ece15"
		hash2 = "fc609adef44b5c64de029b2b2cff22a6f36b6bdf9463c1bd320a522ed39de5d9"
	strings:
		$s1 = "\\SystemRoot\\system32\\CI.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "\\sysnative\\CI.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "CRTDLL.DLL" fullword ascii
		$s5 = "\\sysnative" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "InternetOpenA coolio, trying open %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and all of them
}
rule Mal_Dropper_httpEXE_from_CAB : Dropper {
	meta:
		description = "Detects a dropper from a CAB file mentioned in the article"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 60
		hash1 = "9e7e5f70c4b32a4d5e8c798c26671843e76bb4bd5967056a822e982ed36e047b"
	strings:
		$s1 = "029.Hdl" fullword ascii
		$s2 = "http.exe" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of ($s*) ) )
}
rule Mal_http_EXE : Trojan {
	meta:
		description = "Detects trojan from APT report named http.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 80
		hash1 = "ad191d1d18841f0c5e48a5a1c9072709e2dd6359a6f6d427e0de59cfcd1d9666"
	strings:
		$x1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"%s\"" fullword ascii
		$x2 = "%ALLUSERSPROFILE%\\Accessories\\wordpade.exe" fullword ascii
		$x3 = "\\dumps.dat" fullword ascii
		$x4 = "\\wordpade.exe" fullword ascii
		$x5 = "\\%s|%s|4|%d|%4d-%02d-%02d %02d:%02d:%02d|" fullword ascii
		$x6 = "\\%s|%s|5|%d|%4d-%02d-%02d %02d:%02d:%02d|" fullword ascii
		$x7 = "cKaNBh9fnmXgJcSBxx5nFS+8s7abcQ==" fullword ascii
		$x8 = "cKaNBhFLn1nXMcCR0RlbMQ==" fullword ascii /* base64: pKY1[1 */

		$s1 = "SELECT * FROM moz_logins;" fullword ascii
		$s2 = "makescr.dat" fullword ascii
		$s3 = "%s\\Mozilla\\Firefox\\profiles.ini" fullword ascii
		$s4 = "?moz-proxy://" fullword ascii
		$s5 = "[%s-%s] Title: %s" fullword ascii
		$s6 = "Cforeign key mismatch - \"%w\" referencing \"%w\"" fullword ascii
		$s7 = "Windows 95 SR2" fullword ascii
		$s8 = "\\|%s|0|0|" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 2 of ($s*) ) ) or ( 3 of ($x*) )
}

rule Mal_PotPlayer_DLL : dll {
	meta:
		description = "Detects a malicious PotPlayer.dll"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 70
		hash1 = "705409bc11fb45fa3c4e2fa9dd35af7d4613e52a713d9c6ea6bc4baff49aa74a"
	strings:
		$x1 = "C:\\Users\\john\\Desktop\\PotPlayer\\Release\\PotPlayer.pdb" fullword ascii

		$s3 = "PotPlayer.dll" fullword ascii
		$s4 = "\\update.dat" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and $x1 or all of ($s*)
}
rule Flash_CVE_2015_5119_APT3 : Exploit {
    meta:
        description = "Exploit Sample CVE-2015-5119"
        author = "Florian Roth"
        score = 70
        date = "2015-08-01"
    strings:
        $s0 = "HT_exploit" fullword ascii
        $s1 = "HT_Exploit" fullword ascii
        $s2 = "flash_exploit_" ascii
        $s3 = "exp1_fla/MainTimeline" ascii fullword
        $s4 = "exp2_fla/MainTimeline" ascii fullword
        $s5 = "_shellcode_32" fullword ascii
        $s6 = "todo: unknown 32-bit target" fullword ascii 
    condition:
        uint16(0) == 0x5746 and 1 of them
}
rule Linux_DirtyCow_Exploit {
   meta:
      description = "Detects Linux Dirty Cow Exploit - CVE-2012-0056 and CVE-2016-5195"
      author = "Florian Roth"
      reference = "http://dirtycow.ninja/"
      date = "2016-10-21"
   strings:
      $a1 = { 48 89 D6 41 B9 00 00 00 00 41 89 C0 B9 02 00 00 00 BA 01 00 00 00 BF 00 00 00 00 }

      $b1 = { E8 ?? FC FF FF 48 8B 45 E8 BE 00 00 00 00 48 89 C7 E8 ?? FC FF FF 48 8B 45 F0 BE 00 00 00 00 48 89 }
      $b2 = { E8 ?? FC FF FF B8 00 00 00 00 }

      $source1 = "madvise(map,100,MADV_DONTNEED);"
      $source2 = "=open(\"/proc/self/mem\",O_RDWR);"
      $source3 = ",map,SEEK_SET);"

      $source_printf1 = "mmap %x"
      $source_printf2 = "procselfmem %d"
      $source_printf3 = "madvise %d"
      $source_printf4 = "[-] failed to patch payload"
      $source_printf5 = "[-] failed to win race condition..."
      $source_printf6 = "[*] waiting for reverse connect shell..."

      $s1 = "/proc/self/mem"
      $s2 = "/proc/%d/mem"
      $s3 = "/proc/self/map"
      $s4 = "/proc/%d/map"

      $p1 = "pthread_create" fullword ascii
      $p2 = "pthread_join" fullword ascii
   condition:
      ( uint16(0) == 0x457f and $a1 ) or
      all of ($b*) or
      3 of ($source*) or
      ( uint16(0) == 0x457f and 1 of ($s*) and all of ($p*) and filesize < 20KB )
}
rule potential_CVE_2017_11882
{
    meta:
      author = "ReversingLabs"
      reference = "https://www.reversinglabs.com/newsroom/news/reversinglabs-yara-rule-detects-cobalt-strike-payload-exploiting-cve-2017-11882.html"
      
    strings:
        $docfilemagic = { D0 CF 11 E0 A1 B1 1A E1 }

        $equation1 = "Equation Native" wide ascii
        $equation2 = "Microsoft Equation 3.0" wide ascii

        $mshta = "mshta"
        $http  = "http://"
        $https = "https://"
        $cmd   = "cmd"
        $pwsh  = "powershell"
        $exe   = ".exe"

        $address = { 12 0C 43 00 }

    condition:
        $docfilemagic at 0 and any of ($mshta, $http, $https, $cmd, $pwsh, $exe) and any of ($equation1, $equation2) and $address
}

rule rtf_cve2017_11882_ole : malicious exploit cve_2017_11882 {
    meta:
        author = "John Davison"
        description = "Attempts to identify the exploit CVE 2017 11882"
        reference = "https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about"
        sample = "51cf2a6c0c1a29abca9fd13cb22421da"
        score = 60
        //file_name = "re:^stream_[0-9]+_[0-9]+.dat$"
    strings:
        $headers = { 1c 00 00 00 02 00 ?? ?? a9 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 01 01 03 ?? }
        $font = { 0a 01 08 5a 5a } // <-- I think that 5a 5a is the trigger for the buffer overflow
        //$code = /[\x01-\x7F]{44}/
        $winexec = { 12 0c 43 00 }
    condition:
        all of them and @font > @headers and @winexec == @font + 5 + 44
}

// same as above but for RTF documents
rule rtf_cve2017_11882 : malicious exploit cve_2017_1182 {
    meta:
        author = "John Davison"
        description = "Attempts to identify the exploit CVE 2017 11882"
        reference = "https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about"
        sample = "51cf2a6c0c1a29abca9fd13cb22421da"
        score = 60
        //file_ext = "rtf"
    strings:
        $headers = { 31 63 30 30 30 30 30 30  30 32 30 30 ?? ?? ?? ??
                     61 39 30 30 30 30 30 30  ?? ?? ?? ?? ?? ?? ?? ??
                     ?? ?? ?? ?? ?? ?? ?? ??  ?? ?? ?? ?? ?? ?? ?? ??
                     ?? ?? ?? ?? ?? ?? ?? ??  30 33 30 31 30 31 30 33
                     ?? ?? }
        $font = { 30 61 30 31 30 38 35 61  35 61 }
        $winexec = { 31 32 30 63 34 33 30 30 }
    condition:
        all of them and @font > @headers and @winexec == @font + ((5 + 44) * 2)
}
rule CVE_2018_20250 : AceArchive UNACEV2_DLL_EXP
{
    meta:
        description = "Generic rule for hostile ACE archive using CVE-2018-20250"
        author = "xylitol@temari.fr"
        date = "2019-03-17"
        reference = "https://research.checkpoint.com/extracting-code-execution-from-winrar/"
        // May only the challenge guide you
    strings:
        $string1 = "**ACE**" ascii wide
        $string2 = "*UNREGISTERED VERSION*" ascii wide
        // $hexstring1 = C:\C:\
        $hexstring1 = {?? 3A 5C ?? 3A 5C}
        // $hexstring2 = C:\C:C:..
        $hexstring2 = {?? 3A 5C ?? 3A ?? 3A 2E}
    condition:  
         $string1 at 7 and $string2 at 31 and 1 of ($hexstring*)
}
rule crime_ole_loadswf_cve_2018_4878
{
meta:
description = "Detects CVE-2018-4878"
vuln_type = "Remote Code Execution"
vuln_impact = "Use-after-free"
affected_versions = "Adobe Flash 28.0.0.137 and earlier versions"
mitigation0 = "Implement Protected View for Office documents"
mitigation1 = "Disable Adobe Flash"
weaponization = "Embedded in Microsoft Office first payloads"
actor = "Purported North Korean actors"
reference = "hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998"
report = "https://www.flashpoint-intel.com/blog/targeted-attacks-south-korean-entities/"
author = "Vitali Kremez, Flashpoint"
version = "1.1"

strings:
// EMBEDDED FLASH OBJECT BIN HEADER
$header = "rdf:RDF" wide ascii

// OBJECT APPLICATION TYPE TITLE
$title = "Adobe Flex" wide ascii

// PDB PATH 
$pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" wide ascii

// LOADER STRINGS
$s0 = "URLRequest" wide ascii
$s1 = "URLLoader" wide ascii
$s2 = "loadswf" wide ascii
$s3 = "myUrlReqest" wide ascii

condition:
all of ($header*) and all of ($title*) and 3 of ($s*) or all of ($pdb*) and all of ($header*) and 1 of ($s*)
}