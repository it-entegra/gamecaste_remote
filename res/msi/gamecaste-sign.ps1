param(
    [Parameter(Mandatory = $true)][string]$Msi,
    [string]$Out
)

# Signs a package built by gc-build-windows.yml: the exe and dll files inside
# the MSI, then the MSI itself. CI cannot do it, the key of the "Gamecast LLC"
# certificate stays on the PC of whoever releases, so run it there:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File gamecaste-sign.ps1 -Msi <package.msi>
#
# The signed package goes to the "signed" folder beside the given one, under
# the same file name, unless -Out names another file. The certificate is found
# and used the way the GameCaste shell installer build does it.
#
# The MSI keeps its files in an embedded cabinet, so they are unpacked, signed
# and packed again, and the sizes and hashes the MSI records are brought up to
# date. Windows Installer then unpacks the result once more and the files are
# compared with the signed ones.
#
# The signed package keeps the ProductCode and the version of the unsigned one.
# Release only one of the two: Windows Installer takes them for one product.

$ErrorActionPreference = 'Stop'

$subject = 'Gamecast LLC'
$timestampUrl = 'http://timestamp.globalsign.com/tsa/r6advanced1'

function Find-SignTool {
    $candidates = @($env:SIGNTOOL, 'C:\Program Files (x86)\Microsoft SDKs\ClickOnce\SignTool\signtool.exe')
    foreach ($kits in 'C:\Program Files (x86)\Windows Kits\10\bin', 'D:\Program Files (x86)\Windows Kits\10\bin') {
        if (Test-Path -LiteralPath $kits) {
            $candidates += Get-ChildItem -LiteralPath $kits -Directory -Filter '10.*' |
                Sort-Object { [version]$_.Name } -Descending |
                ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' }
        }
    }
    $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}

function Find-CertificateStore {
    foreach ($location in 'CurrentUser', 'LocalMachine') {
        $certificates = Get-ChildItem "Cert:\$location\My" | Where-Object {
            $_.Subject -like "*CN=$subject*" -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date)
        }
        if ($certificates) { return $location }
    }
}

# All files go into one signtool call: a key on a token asks for its PIN per call.
function Invoke-SignTool([string[]]$files) {
    $arguments = @('sign')
    # signtool looks in the user's store unless told otherwise.
    if ($store -eq 'LocalMachine') { $arguments += '/sm' }
    $arguments += '/tr', $timestampUrl, '/td', 'SHA256', '/fd', 'SHA256', '/n', $subject
    for ($attempt = 1; ; $attempt++) {
        & $signTool @arguments @files | Out-Host
        if ($LASTEXITCODE -eq 0) { return }
        # The timestamp server does not always answer.
        if ($attempt -ge 3) { throw "signtool exited with $LASTEXITCODE." }
        Write-Host "signtool failed (attempt $attempt), trying again in 10 s"
        Start-Sleep -Seconds 10
    }
}

function Assert-Signed([string]$file) {
    $signature = Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notlike "*CN=$subject*") {
        throw "The signature of ${file} is not a valid ""$subject"" one: $($signature.Status). $($signature.StatusMessage)"
    }
}

# The Windows Installer objects carry no type information for PowerShell to bind to.
function Invoke-Com($object, [string]$name, [string]$kind, $arguments) {
    # PowerShell wraps what cmdlets return, and COM rejects a wrapped argument as a type mismatch.
    $plain = New-Object System.Collections.ArrayList
    foreach ($argument in $arguments) { [void]$plain.Add($argument.PSObject.BaseObject) }
    $result = $object.GetType().InvokeMember($name, $kind, $null, $object, $plain.ToArray())
    if ($null -ne $result -and [Runtime.InteropServices.Marshal]::IsComObject($result)) { [void]$comObjects.Add($result) }
    $result
}

# Windows Installer keeps the package open until every object made from it is released.
function Close-Com {
    foreach ($object in $comObjects) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object) }
    $comObjects.Clear()
}

function Get-Rows($database, [string]$sql) {
    $view = Invoke-Com $database 'OpenView' 'InvokeMethod' @($sql)
    Invoke-Com $view 'Execute' 'InvokeMethod' $null | Out-Null
    $rows = New-Object System.Collections.ArrayList
    while ($true) {
        $record = Invoke-Com $view 'Fetch' 'InvokeMethod' $null
        if ($null -eq $record) { break }
        $values = @()
        for ($field = 1; $field -le (Invoke-Com $record 'FieldCount' 'GetProperty' $null); $field++) {
            $values += [string](Invoke-Com $record 'StringData' 'GetProperty' @($field))
        }
        [void]$rows.Add($values)
    }
    Invoke-Com $view 'Close' 'InvokeMethod' $null | Out-Null
    , $rows
}

function Invoke-Sql($database, [string]$sql, $record) {
    $view = Invoke-Com $database 'OpenView' 'InvokeMethod' @($sql)
    Invoke-Com $view 'Execute' 'InvokeMethod' @($record) | Out-Null
    Invoke-Com $view 'Close' 'InvokeMethod' $null | Out-Null
}

function Save-Stream($database, [string]$name, [string]$file) {
    $view = Invoke-Com $database 'OpenView' 'InvokeMethod' @('SELECT `Data` FROM `_Streams` WHERE `Name` = ''{0}''' -f $name)
    Invoke-Com $view 'Execute' 'InvokeMethod' $null | Out-Null
    $record = Invoke-Com $view 'Fetch' 'InvokeMethod' $null
    if ($null -eq $record) { throw "The package has no $name stream." }
    $left = [int](Invoke-Com $record 'DataSize' 'GetProperty' @(1))
    # Read as bytes (1), the stream comes as a string of one character per byte.
    $bytes = [Text.Encoding]::GetEncoding(28591)
    $output = [IO.File]::Create($file)
    try {
        while ($left -gt 0) {
            $text = [string](Invoke-Com $record 'ReadStream' 'InvokeMethod' @(1, [Math]::Min($left, 1MB), 1))
            if ($text.Length -eq 0) { throw "Cannot read the $name stream." }
            $chunk = $bytes.GetBytes($text)
            $output.Write($chunk, 0, $chunk.Length)
            $left -= $chunk.Length
        }
    } finally {
        $output.Close()
    }
    Invoke-Com $view 'Close' 'InvokeMethod' $null | Out-Null
}

$Msi = (Resolve-Path -LiteralPath $Msi).Path
if (-not $Out) {
    $Out = Join-Path (Join-Path (Split-Path -Parent $Msi) 'signed') (Split-Path -Leaf $Msi)
}
$Out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Out)
if ($Out -eq $Msi) { throw 'The signed package cannot replace the unsigned one.' }
if ((Get-AuthenticodeSignature -LiteralPath $Msi).Status -eq 'Valid') { throw "$Msi is signed already." }

$signTool = Find-SignTool
if (-not $signTool) { throw 'signtool.exe was not found (SIGNTOOL variable, ClickOnce SignTool or Windows Kits 10).' }
$store = Find-CertificateStore
if (-not $store) {
    throw "There is no valid ""$subject"" certificate with a private key in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
}
Write-Host "Signing with $signTool, certificate ""$subject"" ($store)"

$work = Join-Path ([IO.Path]::GetTempPath()) ('gamecaste-sign-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
# expand and makecab get relative paths, whatever characters the temporary folder has.
Push-Location -LiteralPath $work
$comObjects = New-Object System.Collections.ArrayList
$installer = New-Object -ComObject WindowsInstaller.Installer
[void]$comObjects.Add($installer)
try {
    $package = Join-Path $work (Split-Path -Leaf $Msi)
    Copy-Item -LiteralPath $Msi -Destination $package
    $database = Invoke-Com $installer 'OpenDatabase' 'InvokeMethod' @($package, 1)

    $properties = New-Object System.Collections.Hashtable
    foreach ($row in (Get-Rows $database 'SELECT `Property`, `Value` FROM `Property`')) { $properties[$row[0]] = $row[1] }

    $media = Get-Rows $database 'SELECT `Cabinet` FROM `Media`'
    if ($media.Count -ne 1 -or -not $media[0][0].StartsWith('#')) {
        throw 'Only a package with a single embedded cabinet is supported.'
    }
    $cabinet = $media[0][0].Substring(1)

    $files = foreach ($row in (Get-Rows $database 'SELECT `File`, `FileName`, `FileSize`, `Sequence` FROM `File` ORDER BY `Sequence`')) {
        $name = ($row[1] -split '\|')[-1]
        [pscustomobject]@{
            Key    = $row[0]
            Name   = $name
            Size   = [long]$row[2]
            # The cabinet names the files by key and has to list them in this order.
            Source = "files\$($row[3])\$name"
            Path   = Join-Path $work "files\$($row[3])\$name"
        }
    }

    Save-Stream $database $cabinet (Join-Path $work 'source.cab')
    New-Item -ItemType Directory -Path 'raw' | Out-Null
    & expand.exe -F:* source.cab raw | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "expand exited with $LASTEXITCODE." }
    foreach ($file in $files) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $file.Path) | Out-Null
        Move-Item -LiteralPath (Join-Path 'raw' $file.Key) -Destination $file.Path
        if ((Get-Item -LiteralPath $file.Path).Length -ne $file.Size) {
            throw "$($file.Name) is not of the size the package records."
        }
    }
    if (Get-ChildItem -LiteralPath 'raw') { throw 'The cabinet holds files the package does not list.' }

    $toSign = @(foreach ($file in $files) {
            if ($file.Name -notmatch '\.(exe|dll)$') { continue }
            $signature = Get-AuthenticodeSignature -LiteralPath $file.Path
            if ($signature.Status -eq 'NotSigned') {
                $file
            } elseif ($signature.Status -eq 'Valid') {
                Write-Host "Left as is, signed by $($signature.SignerCertificate.Subject): $($file.Name)"
            } else {
                throw "$($file.Name) carries a signature that does not verify: $($signature.Status). $($signature.StatusMessage)"
            }
        })

    if ($toSign.Count -gt 0) {
        Invoke-SignTool ($toSign | ForEach-Object { $_.Path })

        $tables = (Get-Rows $database 'SELECT `Name` FROM `_Tables`') | ForEach-Object { $_[0] }
        $hashed = @()
        if ($tables -ccontains 'MsiFileHash') {
            $hashed = @((Get-Rows $database 'SELECT `File_` FROM `MsiFileHash`') | ForEach-Object { $_[0] })
        }
        foreach ($file in $toSign) {
            Assert-Signed $file.Path
            $record = Invoke-Com $installer 'CreateRecord' 'InvokeMethod' @(2)
            Invoke-Com $record 'IntegerData' 'SetProperty' @(1, [int](Get-Item -LiteralPath $file.Path).Length)
            Invoke-Com $record 'StringData' 'SetProperty' @(2, $file.Key)
            Invoke-Sql $database 'UPDATE `File` SET `FileSize` = ? WHERE `File` = ?' $record
            if ($hashed -ccontains $file.Key) {
                $hash = Invoke-Com $installer 'FileHash' 'InvokeMethod' @($file.Path, 0)
                $record = Invoke-Com $installer 'CreateRecord' 'InvokeMethod' @(5)
                foreach ($part in 1..4) {
                    Invoke-Com $record 'IntegerData' 'SetProperty' @($part, (Invoke-Com $hash 'IntegerData' 'GetProperty' @($part)))
                }
                Invoke-Com $record 'StringData' 'SetProperty' @(5, $file.Key)
                Invoke-Sql $database ('UPDATE `MsiFileHash` SET `HashPart1` = ?, `HashPart2` = ?, `HashPart3` = ?, `HashPart4` = ? ' +
                    'WHERE `File_` = ?') $record
            }
        }

        $directives = @(
            ".Set CabinetNameTemplate=$cabinet",
            '.Set DiskDirectoryTemplate=cabinet',
            '.Set MaxDiskSize=0',
            '.Set MaxCabinetSize=0',
            '.Set MaxDiskFileCount=0',
            '.Set CabinetFileCountThreshold=0',
            '.Set FolderFileCountThreshold=0',
            '.Set FolderSizeThreshold=0',
            '.Set Cabinet=on',
            '.Set Compress=on',
            '.Set CompressionType=LZX',
            '.Set CompressionMemory=21',
            '.Set InfFileName=NUL',
            '.Set RptFileName=NUL'
        )
        Set-Content -LiteralPath 'cabinet.ddf' -Encoding ASCII -Value ($directives + ($files | ForEach-Object { '"{0}" "{1}"' -f $_.Source, $_.Key }))
        & makecab.exe /F cabinet.ddf | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "makecab exited with $LASTEXITCODE." }

        $view = Invoke-Com $database 'OpenView' 'InvokeMethod' @('SELECT `Name`, `Data` FROM `_Streams`')
        Invoke-Com $view 'Execute' 'InvokeMethod' $null | Out-Null
        $record = Invoke-Com $installer 'CreateRecord' 'InvokeMethod' @(2)
        Invoke-Com $record 'StringData' 'SetProperty' @(1, $cabinet)
        Invoke-Com $record 'SetStream' 'InvokeMethod' @(2, (Join-Path $work "cabinet\$cabinet"))
        # 3 is msiViewModifyAssign: replaces the stream of that name.
        Invoke-Com $view 'Modify' 'InvokeMethod' @(3, $record) | Out-Null
        Invoke-Com $view 'Close' 'InvokeMethod' $null | Out-Null

        # Two packages that differ must not share a package code (summary property 9).
        $packageCode = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
        $summary = Invoke-Com $database 'SummaryInformation' 'GetProperty' @(1)
        Invoke-Com $summary 'Property' 'SetProperty' @(9, $packageCode)
        Invoke-Com $summary 'Persist' 'InvokeMethod' $null | Out-Null
        Invoke-Com $database 'Commit' 'InvokeMethod' $null | Out-Null
    }

    Close-Com
    Invoke-SignTool @($package)
    Assert-Signed $package

    if ($toSign.Count -gt 0) {
        # An administrative installation only unpacks the package into a folder.
        $image = Join-Path $work 'image'
        $process = Start-Process msiexec.exe -ArgumentList "/a `"$package`" /qn TARGETDIR=`"$image`"" -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw "msiexec /a exited with $($process.ExitCode)." }
        $signed = @($files | ForEach-Object { (Get-FileHash -LiteralPath $_.Path -Algorithm SHA256).Hash } | Sort-Object)
        $unpacked = @(Get-ChildItem -LiteralPath $image -Recurse -File |
                Where-Object { $_.FullName -ne (Join-Path $image (Split-Path -Leaf $package)) } |
                ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } | Sort-Object)
        if (Compare-Object $signed $unpacked) {
            throw 'Windows Installer unpacks the signed package into files that differ from the signed ones.'
        }
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
    Move-Item -LiteralPath $package -Destination $Out -Force
    Write-Host "Signed $($toSign.Count) files and the package: $Out"
    Write-Host "ProductVersion $($properties['ProductVersion']), ProductCode $($properties['ProductCode'])"
    Write-Host "size $((Get-Item -LiteralPath $Out).Length), sha256 $((Get-FileHash -LiteralPath $Out -Algorithm SHA256).Hash.ToLower())"
} finally {
    Close-Com
    Pop-Location
    Remove-Item -LiteralPath $work -Recurse -Force
}
