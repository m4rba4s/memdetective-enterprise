/*
 * Memory Inspector CLI - Sample YARA Rules
 * 
 * Professional ruleset for detecting common threats and anomalies
 * Optimized for memory scanning scenarios
 */

rule Shellcode_Common_Patterns {
    meta:
        description = "Detects common shellcode patterns and techniques"
        author = "Memory Inspector Team"
        category = "shellcode"
        severity = "high"
    
    strings:
        // NOP sleds
        $nop_sled_x86 = { 90 90 90 90 90 90 90 90 }
        $nop_sled_alt = { 91 91 91 91 91 91 91 91 }  // Alternative NOP
        
        // Common x86 shellcode opcodes
        $call_pop = { E8 ?? ?? ?? ?? 5? }  // CALL/POP technique
        $jmp_call_pop = { EB ?? 5? E8 ?? ?? ?? ?? }
        
        // Stack pivot techniques
        $stack_pivot = { 54 5C }  // PUSH ESP; POP ESP equivalent
        
        // Egg hunters
        $egg_hunter = { 66 81 3F ?? ?? 75 ?? 66 81 7F ?? ?? ?? 75 ?? }
        
    condition:
        any of them
}

rule Metasploit_Payload_Signatures {
    meta:
        description = "Detects Metasploit framework payload signatures"
        author = "Memory Inspector Team"
        category = "exploit"
        severity = "critical"
    
    strings:
        // Meterpreter strings
        $meterpreter_1 = "meterpreter" nocase
        $meterpreter_2 = "METERPRETER_TRANSPORT_" nocase
        
        // Stage payload markers
        $stage_marker = { 4D 5A 78 00 01 00 00 00 04 00 00 00 }
        
        // Common Metasploit stub
        $msf_stub = { FC 48 83 E4 F0 E8 }
        
        // Reverse shell patterns
        $reverse_shell = "CreateProcess" nocase
        
    condition:
        any of them
}

rule Code_Injection_Techniques {
    meta:
        description = "Detects common code injection techniques"
        author = "Memory Inspector Team"
        category = "injection"
        severity = "high"
    
    strings:
        // DLL injection APIs
        $loadlibrary = "LoadLibrary" nocase
        $getprocaddr = "GetProcAddress" nocase
        $virtualalloc = "VirtualAlloc" nocase
        $writeprocessmemory = "WriteProcessMemory" nocase
        
        // Process hollowing
        $ntunmapview = "NtUnmapViewOfSection" nocase
        $zwunmapview = "ZwUnmapViewOfSection" nocase
        
        // Reflective DLL loading
        $reflective_dll = "ReflectiveLoader" nocase
        
        // Manual DLL loading
        $manual_map = { 4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45 }
        
    condition:
        any of them
}

rule Anti_Analysis_Techniques {
    meta:
        description = "Detects anti-analysis and evasion techniques"
        author = "Memory Inspector Team"
        category = "evasion"
        severity = "medium"
    
    strings:
        // Debugger detection
        $isdebuggerpresent = "IsDebuggerPresent" nocase
        $checkremotedebuggerpresent = "CheckRemoteDebuggerPresent" nocase
        $ntqueryinformationprocess = "NtQueryInformationProcess" nocase
        
        // VM detection
        $vmware_detection = "VMware" nocase
        $vbox_detection = "VirtualBox" nocase
        $qemu_detection = "QEMU" nocase
        
        // Time-based evasion
        $sleep_api = "Sleep" nocase
        $gettickcount = "GetTickCount" nocase
        
        // Anti-hooking
        $unhook_pattern = { 48 89 ?? 57 48 83 EC 20 65 48 8B 04 25 60 00 00 00 }
        
    condition:
        2 of them
}

rule Suspicious_Memory_Patterns {
    meta:
        description = "Detects suspicious memory allocation patterns"
        author = "Memory Inspector Team"
        category = "memory"
        severity = "medium"
    
    strings:
        // Executable memory allocation
        $virtualalloc_exec = { 68 40 00 00 00 }  // PAGE_EXECUTE_READWRITE
        $mprotect_exec = { C7 ?? ?? ?? ?? ?? 07 00 00 00 }  // PROT_READ|PROT_WRITE|PROT_EXEC
        
        // Large memory allocations
        $large_alloc = { 68 ?? ?? ?? 0? }  // > 16MB allocation
        
        // Memory scanning patterns
        $memory_scan = { 81 ?? ?? ?? ?? ?? 74 ?? 81 ?? ?? ?? ?? ?? 74 ?? }
        
    condition:
        any of them
}

rule Cryptographic_Operations {
    meta:
        description = "Detects cryptographic operations that might indicate payload decryption"
        author = "Memory Inspector Team"
        category = "crypto"
        severity = "low"
    
    strings:
        // RC4 key scheduling
        $rc4_ksa = { 8A 04 0E 32 04 0A 88 04 0E }
        
        // XOR loops
        $xor_loop = { 30 ?? ?? 40 3D ?? ?? ?? ?? 7C }
        
        // AES constants
        $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        
        // Base64 alphabet
        $base64_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        
    condition:
        any of them
}

rule Network_Communication {
    meta:
        description = "Detects network communication patterns"
        author = "Memory Inspector Team"
        category = "network"
        severity = "medium"
    
    strings:
        // HTTP user agents
        $useragent_mozilla = "Mozilla/" nocase
        $useragent_curl = "curl/" nocase
        
        // Network APIs
        $winsock_connect = "connect" nocase
        $winsock_send = "send" nocase
        $winsock_recv = "recv" nocase
        
        // C2 communication patterns
        $http_beacon = "GET /" nocase
        $post_data = "POST /" nocase
        
        // Common C2 protocols
        $https_pattern = "https://" nocase
        $tcp_pattern = { 00 50 }  // Port 80
        $ssl_pattern = { 01 BB }  // Port 443
        
    condition:
        2 of them
}

rule Privilege_Escalation {
    meta:
        description = "Detects privilege escalation techniques"
        author = "Memory Inspector Team"
        category = "privilege"
        severity = "high"
    
    strings:
        // Token manipulation
        $adjusttokenprivileges = "AdjustTokenPrivileges" nocase
        $impersonateloggedonuser = "ImpersonateLoggedOnUser" nocase
        
        // Service exploitation
        $createservice = "CreateService" nocase
        $openscmanager = "OpenSCManager" nocase
        
        // UAC bypass
        $uac_bypass = "shell32.dll" nocase
        $runas = "runas" nocase
        
        // Kernel exploitation
        $ntquerysysteminformation = "NtQuerySystemInformation" nocase
        $zwquerysysteminformation = "ZwQuerySystemInformation" nocase
        
    condition:
        any of them
}