[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0)]
    [ValidateSet('download', 'seed', 'create', 'status', 'wait', 'provision', 'checkpoint', 'reset')]
    [string] $Action = 'status',

    [string] $VMName = 'socat-classic-ubuntu2604',
    [string] $SwitchName = 'Default Switch',
    [string] $LabRoot = (Join-Path $env:LOCALAPPDATA 'socat-hyperv'),
    [string] $CheckpointName = 'clean-provisioned',
    [ValidatePattern('^[a-z_][a-z0-9_-]*$')]
    [string] $GuestUser = 'socat-user',
    [int] $ProcessorCount = 6,
    [UInt64] $StartupMemoryBytes = 12GB,
    [UInt64] $DiskSizeBytes = 64GB
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$UbuntuImageName = 'ubuntu-26.04-server-cloudimg-amd64.img'
$UbuntuImageUrl = "https://cloud-images.ubuntu.com/releases/26.04/release/$UbuntuImageName"
$UbuntuImageSHA256 = '9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05'

$ScriptRoot = Split-Path -Parent $PSCommandPath
$ImageDirectory = Join-Path $LabRoot 'images'
$StateDirectory = Join-Path $LabRoot 'state'
$SeedDirectory = Join-Path $StateDirectory 'cidata'
$KeyDirectory = Join-Path $LabRoot 'ssh'
$DiskDirectory = Join-Path $LabRoot 'disks'
$UbuntuImagePath = Join-Path $ImageDirectory $UbuntuImageName
$VHDXPath = Join-Path $DiskDirectory "$VMName.vhdx"
$SeedISOPath = Join-Path $StateDirectory "$VMName-cidata.iso"
$SSHKeyPath = Join-Path $KeyDirectory 'socat_lab_ed25519'
$KnownHostsPath = Join-Path $KeyDirectory 'known_hosts'
$StatePath = Join-Path $StateDirectory "$VMName.json"
$GuestProvisionPath = Join-Path $ScriptRoot 'guest-provision.sh'

function Set-Utf8NoBom {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Value
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Value, $encoding)
}

function New-LabDirectories {
    foreach ($path in $ImageDirectory, $StateDirectory, $KeyDirectory, $DiskDirectory) {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
    }
}

function Get-QemuImg {
    $command = Get-Command qemu-img.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @(
        (Join-Path $env:ProgramFiles 'qemu\qemu-img.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\QEMU\qemu-img.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    throw @'
qemu-img.exe was not found. Install the verified winget package from an
elevated PowerShell once:

  winget install --exact --id SoftwareFreedomConservancy.QEMU
'@
}

function Invoke-Native {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(ValueFromRemainingArguments)] [string[]] $Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE"
    }
}

function Get-UbuntuImage {
    New-LabDirectories
    if (-not (Test-Path -LiteralPath $UbuntuImagePath -PathType Leaf)) {
        $partial = "$UbuntuImagePath.part"
        Invoke-Native curl.exe '--fail' '--location' '--retry' '5' '--continue-at' '-' '--output' $partial $UbuntuImageUrl
        Move-Item -LiteralPath $partial -Destination $UbuntuImagePath
    }

    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $UbuntuImagePath).Hash.ToLowerInvariant()
    if ($actual -ne $UbuntuImageSHA256) {
        throw "Ubuntu image checksum mismatch: got $actual, want $UbuntuImageSHA256"
    }
    Write-Host "verified $UbuntuImagePath"
}

function New-LabSSHKey {
    New-LabDirectories
    if (-not (Test-Path -LiteralPath $SSHKeyPath -PathType Leaf)) {
        Invoke-Native ssh-keygen.exe '-q' '-t' 'ed25519' '-N' '' '-C' 'socat-hyperv-lab' '-f' $SSHKeyPath
    }
    if (-not (Test-Path -LiteralPath "$SSHKeyPath.pub" -PathType Leaf)) {
        throw "SSH public key is missing: $SSHKeyPath.pub"
    }
    return (Get-Content -Raw -LiteralPath "$SSHKeyPath.pub").Trim()
}

function New-CidataISO {
    param(
        [Parameter(Mandatory)] [string] $SourceDirectory,
        [Parameter(Mandatory)] [string] $Path
    )

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path
    }

    if (-not ('SocatIsoStreamWriter' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class SocatIsoStreamWriter
{
    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    private static extern int SHCreateStreamOnFile(
        string path,
        uint mode,
        out IStream stream);

    public static void Write(object source, long length, string path)
    {
        var input = (IStream)source;
        IStream output;
        const uint STGM_WRITE_CREATE = 0x00001001;
        int result = SHCreateStreamOnFile(path, STGM_WRITE_CREATE, out output);
        if (result < 0)
        {
            Marshal.ThrowExceptionForHR(result);
        }

        try
        {
            input.CopyTo(output, length, IntPtr.Zero, IntPtr.Zero);
            output.Commit(0);
        }
        finally
        {
            if (output != null && Marshal.IsComObject(output))
            {
                Marshal.ReleaseComObject(output);
            }
        }
    }
}
'@
    }

    $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $image.ChooseImageDefaultsForMediaType(12) # IMAPI_MEDIA_TYPE_DISK
    $image.FileSystemsToCreate = 3 # ISO9660 | Joliet
    $image.VolumeName = 'CIDATA'
    $image.Root.AddTree($SourceDirectory, $false)
    $result = $image.CreateResultImage()
    $stream = $result.ImageStream
    $length = [long] $result.TotalBlocks * [long] $result.BlockSize
    try {
        [SocatIsoStreamWriter]::Write($stream, $length, $Path)
    }
    finally {
        [void] [System.Runtime.InteropServices.Marshal]::ReleaseComObject($stream)
        [void] [System.Runtime.InteropServices.Marshal]::ReleaseComObject($result)
        [void] [System.Runtime.InteropServices.Marshal]::ReleaseComObject($image)
    }
}

function New-CloudInitSeed {
    $publicKey = New-LabSSHKey
    if (Test-Path -LiteralPath $SeedDirectory) {
        Remove-Item -Recurse -LiteralPath $SeedDirectory
    }
    New-Item -ItemType Directory -Path $SeedDirectory | Out-Null

    $metadata = @"
instance-id: $VMName
local-hostname: socat-classic
"@
    Set-Utf8NoBom -Path (Join-Path $SeedDirectory 'meta-data') -Value $metadata

    $userData = @"
#cloud-config
hostname: socat-classic
manage_etc_hosts: true
ssh_pwauth: false
disable_root: true
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
users:
  - default
  - name: $GuestUser
    gecos: Socat test lab
    groups: [adm, sudo]
    shell: /bin/bash
    lock_passwd: true
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $publicKey
packages:
  - openssh-server
runcmd:
  - [systemctl, enable, --now, ssh.service]
  - [mkdir, -p, /var/lib/socat-lab]
  - [touch, /var/lib/socat-lab/cloud-init-ready]
final_message: Socat Hyper-V cloud-init complete
"@
    Set-Utf8NoBom -Path (Join-Path $SeedDirectory 'user-data') -Value $userData

    New-CidataISO -SourceDirectory $SeedDirectory -Path $SeedISOPath
    Write-Host "created $SeedISOPath"
}

function Get-LabIPv4Address {
    $vmAdapter = Get-VMNetworkAdapter -VMName $VMName -ErrorAction Stop | Select-Object -First 1
    $address = $vmAdapter.IPAddresses |
        Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notmatch '^(127|169\.254)\.' } |
        Select-Object -First 1
    if ($address) {
        return $address
    }

    # Minimal cloud images can obtain DHCP before Hyper-V's KVP daemon reports
    # guest addresses. Resolve the VM MAC in the internal switch's neighbor
    # table so first boot does not depend on that optional daemon.
    $hostAdapter = Get-NetAdapter -Name "vEthernet ($($vmAdapter.SwitchName))" -ErrorAction SilentlyContinue
    if (-not $hostAdapter) {
        return $null
    }
    $vmMac = ($vmAdapter.MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    return Get-NetNeighbor -InterfaceIndex $hostAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            (($_.LinkLayerAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq $vmMac) -and
            $_.IPAddress -notmatch '^(127|169\.254)\.'
        } |
        Select-Object -ExpandProperty IPAddress -First 1
}

function Save-LabState {
    param([string] $IPAddress)
    $state = [ordered]@{
        vm_name = $VMName
        ip_address = $IPAddress
        ssh_user = $GuestUser
        ssh_key = $SSHKeyPath
        known_hosts = $KnownHostsPath
        checkpoint = $CheckpointName
        updated_at = (Get-Date).ToString('o')
    } | ConvertTo-Json
    Set-Utf8NoBom -Path $StatePath -Value $state
}

function Get-SSHArguments {
    return @(
        '-i', $SSHKeyPath,
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=5',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', "UserKnownHostsFile=$KnownHostsPath"
    )
}

function Wait-LabSSH {
    param([int] $TimeoutSeconds = 600)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $address = Get-LabIPv4Address
        if ($address) {
            $arguments = @(Get-SSHArguments) + @("$GuestUser@$address", 'true')
            & ssh.exe @arguments 2>$null
            if ($LASTEXITCODE -eq 0) {
                Save-LabState -IPAddress $address
                Write-Host "SSH ready: $GuestUser@$address"
                return $address
            }
        }
        Start-Sleep -Seconds 5
    }
    throw "SSH did not become ready for $VMName within $TimeoutSeconds seconds"
}

function New-LabVM {
    Get-UbuntuImage
    New-CloudInitSeed
    $qemuImg = Get-QemuImg

    if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
        throw "VM already exists: $VMName"
    }
    if (Test-Path -LiteralPath $VHDXPath) {
        throw "refusing to overwrite existing disk: $VHDXPath"
    }
    if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
        throw "Hyper-V switch does not exist: $SwitchName"
    }

    $info = & $qemuImg info --output=json $UbuntuImagePath | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $info.format -ne 'qcow2') {
        throw "unexpected Ubuntu image format: $($info.format)"
    }

    Invoke-Native $qemuImg 'convert' '-p' '-S' '0' '-f' 'qcow2' '-O' 'vhdx' '-o' 'subformat=dynamic,block_size=1048576' $UbuntuImagePath $VHDXPath
    # qemu-img may mark a dynamic VHDX as an NTFS sparse host file. Hyper-V
    # supports dynamic VHDX allocation but rejects the outer SparseFile flag.
    $diskFile = Get-Item -LiteralPath $VHDXPath
    if (($diskFile.Attributes -band [System.IO.FileAttributes]::SparseFile) -ne 0) {
        Invoke-Native fsutil.exe 'sparse' 'setflag' $VHDXPath '0'
    }
    Resize-VHD -Path $VHDXPath -SizeBytes $DiskSizeBytes

    $vm = New-VM -Name $VMName -Generation 2 -MemoryStartupBytes $StartupMemoryBytes -VHDPath $VHDXPath -SwitchName $SwitchName
    Set-VMProcessor -VM $vm -Count $ProcessorCount
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
    Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -CheckpointType ProductionOnly -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Add-VMDvdDrive -VM $vm -Path $SeedISOPath | Out-Null
    $disk = Get-VMHardDiskDrive -VM $vm
    Set-VMFirmware -VM $vm -FirstBootDevice $disk

    Start-VM -VM $vm | Out-Null
    Wait-LabSSH -TimeoutSeconds 600 | Out-Null
}

function Invoke-LabProvision {
    if (-not (Test-Path -LiteralPath $GuestProvisionPath -PathType Leaf)) {
        throw "guest provisioning script is missing: $GuestProvisionPath"
    }
    $address = Wait-LabSSH
    $sshArguments = @(Get-SSHArguments)
    $scpArguments = @(
        '-i', $SSHKeyPath,
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', "UserKnownHostsFile=$KnownHostsPath",
        $GuestProvisionPath,
        "${GuestUser}@${address}:/tmp/guest-provision.sh"
    )
    Invoke-Native ssh.exe @sshArguments "$GuestUser@$address" 'sudo cloud-init status --wait'
    Invoke-Native scp.exe @scpArguments
    Invoke-Native ssh.exe @sshArguments "$GuestUser@$address" 'sudo bash /tmp/guest-provision.sh'
}

function New-CleanCheckpoint {
    $address = Wait-LabSSH
    $sshArguments = @(Get-SSHArguments)
    Invoke-Native ssh.exe @sshArguments "$GuestUser@$address" 'test -f /var/lib/socat-lab/provisioned'
    if (Get-VMCheckpoint -VMName $VMName -Name $CheckpointName -ErrorAction SilentlyContinue) {
        throw "checkpoint already exists: $CheckpointName"
    }

    Invoke-Native ssh.exe @sshArguments "$GuestUser@$address" 'sudo shutdown -h now'
    $vm = Get-VM -Name $VMName
    $deadline = (Get-Date).AddMinutes(5)
    while ($vm.State -ne 'Off' -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        $vm = Get-VM -Name $VMName
    }
    if ($vm.State -ne 'Off') {
        throw "VM did not shut down cleanly: $VMName"
    }

    Get-VMDvdDrive -VMName $VMName | Set-VMDvdDrive -Path $null
    Checkpoint-VM -VMName $VMName -SnapshotName $CheckpointName
    Write-Host "created checkpoint $CheckpointName"
}

function Reset-LabVM {
    $vm = Get-VM -Name $VMName -ErrorAction Stop
    $checkpoint = Get-VMCheckpoint -VMName $VMName -Name $CheckpointName -ErrorAction Stop
    if ($vm.State -ne 'Off') {
        Stop-VM -VM $vm -TurnOff -Force
    }
    Restore-VMCheckpoint -VMCheckpoint $checkpoint -Confirm:$false
    Start-VM -Name $VMName | Out-Null
    Wait-LabSSH | Out-Null
}

function Show-LabStatus {
    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if (-not $vm) {
        [pscustomobject]@{
            VMName = $VMName
            State = 'Absent'
            ImagePresent = (Test-Path -LiteralPath $UbuntuImagePath)
            QemuImg = try { Get-QemuImg } catch { $null }
        } | Format-List
        return
    }

    $checkpointNames = @(Get-VMCheckpoint -VMName $VMName -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name)
    [pscustomobject]@{
        VMName = $vm.Name
        State = $vm.State
        Generation = $vm.Generation
        ProcessorCount = $vm.ProcessorCount
        StartupMemoryGB = [math]::Round($vm.MemoryStartup / 1GB, 1)
        IPv4Address = Get-LabIPv4Address
        DiskPath = $VHDXPath
        Checkpoints = $checkpointNames -join ', '
    } | Format-List
}

New-LabDirectories
switch ($Action) {
    'download' { Get-UbuntuImage }
    'seed' { New-CloudInitSeed }
    'create' { New-LabVM }
    'status' { Show-LabStatus }
    'wait' { Wait-LabSSH | Out-Null }
    'provision' { Invoke-LabProvision }
    'checkpoint' { New-CleanCheckpoint }
    'reset' { Reset-LabVM }
}
