# Função para resolver o nome do dispositivo via IP
function Resolve-HostName {
    param (
        [string]$IPAddress
    )
    try {
        $hostEntry = [System.Net.Dns]::GetHostEntry($IPAddress)
        return $hostEntry.HostName
    } catch {
        try {
            Test-Connection -ComputerName $IPAddress -Count 1 -Quiet | Out-Null
            $hostEntry = [System.Net.Dns]::GetHostEntry($IPAddress)
            return $hostEntry.HostName
        } catch {
            try {
                $nbtResult = nbtstat -A $IPAddress | Select-String -Pattern "<20>\s+\S+" | ForEach-Object { $_ -replace '.*<20>\s+', '' }
                if ($nbtResult) {
                    return $nbtResult
                } else {
                    throw "NetBIOS não resolveu"
                }
            } catch {
                try {
                    $wmiQuery = Get-WmiObject -Class Win32_PingStatus -Filter "Address='$IPAddress'" | Select-Object -ExpandProperty ProtocolAddress
                    if ($wmiQuery) {
                        $wmiName = [System.Net.Dns]::GetHostEntry($wmiQuery)
                        return $wmiName.HostName
                    } else {
                        throw "WMI não resolveu"
                    }
                } catch {
                    return "Não Resolvido"
                }
            }
        }
    }
}

# Função para identificar o fabricante a partir do MAC Address
function Get-MACVendor {
    param (
        [string]$MACAddress
    )
    try {
        $vendorAPI = "https://api.macvendors.com/$MACAddress"
        $vendor = Invoke-RestMethod -Uri $vendorAPI -Method Get -ErrorAction Stop
        return $vendor
    } catch {
        return "Desconhecido"
    }
}

# Função para verificar dispositivos conhecidos
function Is-KnownDevice {
    param (
        [string]$MACAddress
    )
    $knownDevices = @(
        "00-14-22-01-23-45",
        "78-3E-A1-BD-FA-00"
    )
    return $knownDevices -contains $MACAddress
}

# Função de Bruteforce para portas padrão
function Bruteforce-Ports {
    param (
        [string]$IPAddress,
        [array]$Ports = @(21, 22, 23, 80, 443)
    )
    $results = @{}
    foreach ($port in $Ports) {
        $tcpTest = Test-NetConnection -ComputerName $IPAddress -Port $port -ErrorAction SilentlyContinue
        $results[$port] = if ($tcpTest) { "Aberto" } else { "Fechado" }
    }
    return $results
}

# Determina os intervalos de rede
try {
    $networkRanges = Get-NetworkRange
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit
}

# Executa uma varredura em todos os intervalos de rede
$deviceList = @()
foreach ($networkRange in $networkRanges) {
    $arpTable = arp -a | ForEach-Object {
        if ($_ -match '(?<IP>\d+\.\d+\.\d+\.\d+)\s+(?<MAC>([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})\s+(?<Type>\w+)') {
            [PSCustomObject]@{
                IPAddress = $matches.IP
                MACAddress = $matches.MAC
            }
        }
    }

    $arpTable = $arpTable | Where-Object { !($_.IPAddress -match '224\.\d+\.\d+\.\d+') }

    if (Check-Nmap) {
        Write-Host "Executando varredura com Nmap na faixa: $networkRange" -ForegroundColor Cyan
        $nmapScan = & nmap -sn $networkRange 2>$null | Select-String -Pattern "Nmap scan report for" | ForEach-Object { $_ -replace 'Nmap scan report for ', '' }
        foreach ($host in $nmapScan) {
            if (-not $arpTable.IPAddress.Contains($host)) {
                $arpTable += [PSCustomObject]@{
                    IPAddress = $host
                    MACAddress = "Desconhecido"
                }
            }
        }
    } else {
        Write-Host "Nmap não está disponível para a faixa: $networkRange. Continuando sem ele." -ForegroundColor Yellow
    }

    foreach ($entry in $arpTable) {
        $hostname = Resolve-HostName -IPAddress $entry.IPAddress
        $macVendor = Get-MACVendor -MACAddress $entry.MACAddress
        $isKnown = Is-KnownDevice -MACAddress $entry.MACAddress
        $bruteforceResults = Bruteforce-Ports -IPAddress $entry.IPAddress

        $deviceList += [PSCustomObject]@{
            HostName      = $hostname
            IPAddress     = $entry.IPAddress
            MACAddress    = $entry.MACAddress
            Vendor        = $macVendor
            Known         = if ($isKnown) { "Sim" } else { "Não" }
            PortStatuses  = $bruteforceResults.GetEnumerator() | ForEach-Object { "$($_.Key): $_.Value" }
        }
    }
}

# Exporta resultados para CSV e JSON
$deviceList | Export-Csv -Path "DispositivosRede.csv" -NoTypeInformation
$deviceList | Select-Object -Property * | ConvertTo-Json -Depth 3 | Set-Content -Path "DispositivosRede.json"

# Exibe os dispositivos encontrados em uma tabela e interface gráfica
Write-Output "Dispositivos na rede:" | Write-Host -ForegroundColor Green
$deviceList | Format-Table -AutoSize
$deviceList | Out-GridView -Title "Dispositivos na Rede"

# Notifica dispositivos desconhecidos
$unknownDevices = $deviceList | Where-Object { $_.Known -eq "Não" }
if ($unknownDevices.Count -gt 0) {
    Write-Host "Dispositivos desconhecidos detectados:" -ForegroundColor Red
    $unknownDevices | Format-Table -AutoSize
}
