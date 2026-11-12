param(
    [Parameter(Mandatory = $true)] [string] $StockPath,
    [Parameter(Mandatory = $true)] [string] $OutputPath,
    [string] $MozillaPath = (Join-Path $PSScriptRoot '..\vendor\root-certificates\mozilla-cacert-2026-09-25.pem'),
    [string] $SectigoE46Path = (Join-Path $PSScriptRoot '..\vendor\root-certificates\sectigo-e46.pem')
)

$ErrorActionPreference = 'Stop'

$expectedStockSha = '3D7E053FB7B8AD425AB7C0AE4523B837163CA9D436F8BFE43C8FE730636D04E2'
$expectedMozillaSha = 'A41B5D356AEA97A529FE27E0F7316D2F9D946D75927476CF9CF1B90637D00505'
$expectedE46Sha = '808130157F570B7640069852C88E256738007811A64C3AA9A4C31038347DC19C'
$expectedOutputSha = '35BE1BEB9AC3B17F128C16792DAE3CE0FBE0230A7C8AA2D47E500084F4F7E7F0'

function Assert-Sha256([string] $Path, [string] $Expected, [string] $Label) {
    $actual = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Path))
    )
    if ($actual -ne $Expected) {
        throw "$Label SHA-256 mismatch: $actual (expected $Expected)"
    }
}

Assert-Sha256 $StockPath $expectedStockSha 'stock root bundle'
Assert-Sha256 $MozillaPath $expectedMozillaSha 'Mozilla root snapshot'
Assert-Sha256 $SectigoE46Path $expectedE46Sha 'Sectigo E46 root'

# Keep this list intentionally small. The New 3DS browser has a very limited
# resident heap and crashed while parsing the complete Mozilla CA bundle.
# Select only roots useful to current public-web chains; the E46 EC root is
# supplied separately below because it is not in this Mozilla snapshot.
$wantedSubjects = @(
    'Security Communication RootCA2',
    'COMODO RSA Certification Authority',
    'USERTrust RSA Certification Authority',
    'IdenTrust Commercial Root CA 1',
    'ISRG Root X1',
    'Amazon Root CA 1',
    'Amazon Root CA 2',
    'SSL.com Root Certification Authority RSA',
    'SSL.com EV Root Certification Authority RSA R2',
    'GlobalSign Root CA - R6',
    'Microsoft RSA Root Certificate Authority 2017',
    'NAVER Global Root Certification Authority',
    'GlobalSign Root R46',
    'HARICA TLS RSA Root CA 2021',
    'GTS Root R1',
    'DigiCert Global Root G3',
    'DigiCert TLS RSA4096 Root G5',
    'Sectigo Public Server Authentication Root R46',
    'SSL.com TLS RSA Root CA 2022',
    'Telekom Security TLS RSA Root 2023',
    'SecureSign Root CA14',
    'TrustAsia TLS RSA Root CA',
    'SwissSign RSA TLS Root CA 2022 - 1',
    'OISTE Server Root RSA G1',
    'Telia RSA TLS Root CA v3'
)

function Get-PemCertificates([string] $Path) {
    $text = [IO.File]::ReadAllText($Path)
    $pattern = '-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----'
    foreach ($match in [regex]::Matches($text, $pattern, [Text.RegularExpressions.RegexOptions]::Singleline)) {
        $base64 = $match.Groups[1].Value -replace '\s', ''
        $der = [Convert]::FromBase64String($base64)
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $fingerprint = [Convert]::ToHexString($sha256.ComputeHash($der))
        }
        finally {
            $sha256.Dispose()
        }
        [pscustomobject]@{
            Der = $der
            Certificate = $cert
            Subject = $cert.Subject
            Fingerprint = $fingerprint
        }
    }
}

function ConvertTo-Pem([byte[]] $Der) {
    $base64 = [Convert]::ToBase64String($Der)
    $lines = for ($offset = 0; $offset -lt $base64.Length; $offset += 64) {
        $length = [Math]::Min(64, $base64.Length - $offset)
        $base64.Substring($offset, $length)
    }
    "-----BEGIN CERTIFICATE-----`n$($lines -join "`n")`n-----END CERTIFICATE-----`n"
}

$stockText = [IO.File]::ReadAllText($StockPath).TrimEnd()
$stock = @(Get-PemCertificates $StockPath)
$mozilla = @(Get-PemCertificates $MozillaPath)
$stockFingerprints = [Collections.Generic.HashSet[string]]::new([string[]] $stock.Fingerprint)
$selected = [Collections.Generic.List[object]]::new()
$missing = [Collections.Generic.List[string]]::new()

foreach ($wanted in $wantedSubjects) {
    $matches = @($mozilla | Where-Object { $_.Subject -like "*$wanted*" })
    if ($matches.Count -ne 1) {
        $missing.Add("$wanted (matches=$($matches.Count))")
        continue
    }
    $entry = $matches[0]
    if (-not $stockFingerprints.Contains($entry.Fingerprint) -and
        -not ($selected.Fingerprint -contains $entry.Fingerprint)) {
        $selected.Add($entry)
    }
}

if ($missing.Count -gt 0) {
    throw "Mozilla selection mismatch: $($missing -join '; ')"
}

$builder = [Text.StringBuilder]::new()
[void] $builder.Append($stockText)
[void] $builder.Append("`n`n# Curated current Mozilla RSA roots for the New Nintendo 3DS browser.`n")
# Preserve the exact, hardware-tested bundle bytes. This historical comment
# describes the Mozilla subset; E46 is appended separately below.
[void] $builder.Append("# Exact duplicates of stock roots are omitted. ECC-only and distrusted roots are omitted.`n")
foreach ($entry in $selected) {
    [void] $builder.Append("`n# Added: $($entry.Subject)`n")
    [void] $builder.Append((ConvertTo-Pem $entry.Der))
}

[void] $builder.Append("`n# Additional root certificate source: http://crt.sectigo.com/SectigoPublicServerAuthenticationRootE46.crt`n")
[void] $builder.Append("`n# Added: sectigo-e46.pem`n")
[void] $builder.Append([IO.File]::ReadAllText($SectigoE46Path).Replace("`r`n", "`n"))

$outputDirectory = Split-Path -Parent $OutputPath
[IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
[IO.File]::WriteAllBytes($OutputPath, [Text.Encoding]::ASCII.GetBytes($builder.ToString()))

$resultBytes = [IO.File]::ReadAllBytes($OutputPath)
$resultSha = [Security.Cryptography.SHA256]::HashData($resultBytes)
$resultShaHex = [Convert]::ToHexString($resultSha)
if ($resultShaHex -ne $expectedOutputSha) {
    throw "root bundle SHA-256 mismatch: $resultShaHex (expected $expectedOutputSha)"
}
Write-Output "stock=$($stock.Count) selected=$($selected.Count + 1) total=$($stock.Count + $selected.Count + 1)"
Write-Output "size=$($resultBytes.Length) sha256=$resultShaHex"
$selected | ForEach-Object { Write-Output "ADD $($_.Subject) [$($_.Certificate.PublicKey.Oid.FriendlyName)]" }
