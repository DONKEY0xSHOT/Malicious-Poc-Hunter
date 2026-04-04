rule PowerShell_Reverse_Shell
{
    meta:
        description = "Detects PowerShell reverse shell patterns using TCP sockets and stream I/O"
        category    = "Reverse Shell"
        severity    = "Critical"

    strings:
        // TCP client construction
        $net_tcp1 = "System.Net.Sockets.TcpClient"     nocase ascii wide
        $net_tcp2 = "Net.Sockets.TcpClient"            nocase ascii wide
        $net_tcp3 = "New-Object System.Net.Sockets"    nocase ascii wide

        // Stream reading/writing
        $stream1  = "GetStream()"                      nocase ascii wide
        $stream2  = "NetworkStream"                    nocase ascii wide
        $stream3  = "StreamReader"                     nocase ascii wide
        $stream4  = "StreamWriter"                     nocase ascii wide

        // Shell spawning
        $shell1   = "cmd.exe"                          nocase ascii wide
        $shell2   = "/bin/bash"                              ascii
        $shell3   = "/bin/sh"                                ascii
        $shell4   = "cmd /c"                           nocase ascii wide

        // Invoke / execute
        $invoke1  = "Invoke-Expression"                nocase ascii wide
        $invoke2  = "IEX("                             nocase ascii wide
        $invoke3  = "&([scriptblock]"                  nocase ascii wide

        // Socket connect
        $connect  = ".Connect("                        nocase ascii wide

    condition:
        any of ($net_tcp*) and
        any of ($stream*) and
        $connect and
        (any of ($shell*) or any of ($invoke*))
}


rule Python_Reverse_Shell
{
    meta:
        description = "Detects Python reverse shell patterns: socket + subprocess + dup2/pty"
        category    = "Reverse Shell"
        severity    = "Critical"

    strings:
        $sock_import = "import socket"       ascii
        $sock_create = "socket.socket"       ascii
        $sock_conn   = ".connect(("          ascii

        $sub_import  = "import subprocess"   ascii
        $os_import   = "import os"           ascii

        // Shell redirect primitives
        $dup2        = "os.dup2"             ascii
        $pty_spawn   = "pty.spawn"           ascii

        // Shell targets
        $sh1         = "/bin/sh"             ascii
        $sh2         = "/bin/bash"           ascii
        $sh3         = "cmd.exe"             ascii

        // Alternative: subprocess call with shell string
        $popen_sh1   = "subprocess.Popen([\"/bin"  ascii
        $popen_sh2   = "subprocess.call([\"/bin"   ascii

    condition:
        $sock_import and $sock_create and $sock_conn and
        ($sub_import or $os_import) and
        ($dup2 or $pty_spawn or $popen_sh1 or $popen_sh2) and
        any of ($sh*)
}


rule Bash_Reverse_Shell
{
    meta:
        description = "Detects bash/sh reverse shell one-liners embedded in scripts"
        category    = "Reverse Shell"
        severity    = "Critical"

    strings:
        $bash_tcp   = /bash\s+-i\s+>&\s*\/dev\/tcp\// ascii
        $bash_udp   = /bash\s+-i\s+>&\s*\/dev\/udp\// ascii
        $nc_e1      = /nc\s+(-e|--exec)\s/            ascii
        $nc_e2      = /ncat\s+-e\s/                    ascii
        $mkfifo     = "mkfifo"                         ascii
        $dev_tcp    = "/dev/tcp/"                      ascii
        $socat      = /socat\s+.*EXEC:/                ascii

    condition:
        any of ($bash_tcp, $bash_udp, $nc_e1, $nc_e2, $socat) or
        ($mkfifo and $dev_tcp)
}
