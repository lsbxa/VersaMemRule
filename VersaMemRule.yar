rule VersaMem_Webshell_Indicators {
    meta:
        description = "Detects VersaMem Malware"
        author = "lsbxa"
        date = "2025-08-05"

    strings:
	// General strings
        $s1 = "org.apache.catalina.startup.Bootstrap" ascii
        $s2 = "com.versa.vnms.ui.TestMain" ascii
        $s3 = "/tmp/.java_pid" ascii
        $s4 = "CoreClassFileTransformer" ascii
        $s5 = "WriteTestTransformer" ascii
        $s6 = "CapturePassTransformer" ascii
        $s7 = "Versa-Auth" ascii
        $s8 = "captureLoginPasswordCode" ascii
        $s9 = "/tmp/.temp.data" ascii
        $s10 = "getInsertCode" ascii
		$s11 = "pgrep" ascii
		$s12 = "com/sun/tools/attach/VirtualMachine" ascii
		$s13 = "loadAgent" ascii
		$s14 = "Base64" ascii
		$s15 = "AES" ascii
		$s16 = "org.apache.catalina.core.ApplicationFilterChain" ascii

        // Malicious class files
        $webshell1 = "com/versa/vnms/ui/init/CapturePassTransformer.classPK" ascii
        $webshell2 = "com/versa/vnms/ui/init/WriteTestTransformer.classPK" ascii

        // Path indicator
        $maven1 = "META-INF/maven/org.example/Director_tomcat_memShell/PK" ascii
        $maven2 = "META-INF/maven/org.example/Director_tomcat_memShell/pom.propertiesPK" ascii
        $maven3 = "META-INF/maven/org.example/Director_tomcat_memShell/pom.xmlPK" ascii

    condition:
        4 of ($s*) or (any of ($maven*) and 1 of ($webshell*))

}

