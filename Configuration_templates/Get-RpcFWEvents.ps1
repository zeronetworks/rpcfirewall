# Function to parse RPCFW logs
function Parse-RPCFWLog {
    param ($Event)
    $action = if($Event.Keywords -band 0x10000000000000) {'Audit Failure'} elseif($Event.Keywords -band 0x20000000000000) {'Audit Success'} else {'Unknown'}
    return New-Object PSObject -Property @{
        'Log Source' = 'RPCFW'
        'TimeCreated' = $Event.TimeCreated
        'Endpoint' = [regex]::Match($Event.Message, 'Endpoint:\s*(.*?)($|\r\n)').Groups[1].Value
        'InterfaceUuid' = [regex]::Match($Event.Message, 'InterfaceUuid:\s*(.*?)($|\r\n)').Groups[1].Value
        'OpNum' = [regex]::Match($Event.Message, 'OpNum:\s*(.*?)($|\r\n)').Groups[1].Value
        'Security ID' = [regex]::Match($Event.Message, 'Security ID:\s*(.*?)($|\r\n)').Groups[1].Value
        'Client Network Address' = [regex]::Match($Event.Message, 'Client Network Address:\s*(.*?)($|\r\n)').Groups[1].Value
        'Client Port' = [regex]::Match($Event.Message, 'Client Port:\s*(.*?)($|\r\n)').Groups[1].Value
        'Protocol' = [regex]::Match($Event.Message, 'Protocol:\s*(.*?)($|\r\n)').Groups[1].Value
        'Action' = $action
    }
}

function Parse-RPCFWSecurityLog {
    param ($Event)
    $action = if($Event.Keywords -band 0x10000000000000) {'Audit Failure'} elseif($Event.Keywords -band 0x20000000000000) {'Audit Success'} else {'Unknown'}
    return New-Object PSObject -Property @{
        'Log Source' = 'Security'
        'TimeCreated' = $Event.TimeCreated
        'Endpoint' = ""
        'InterfaceUuid' = [regex]::Match($Event.Message, 'Interface UUID:\s*(.*?)($|\r\n)').Groups[1].Value
        'OpNum' = ""
        'Security ID' = [regex]::Match($Event.Message, 'SID:\s*(.*?)($|\r\n)').Groups[1].Value
        'Client Network Address' = [regex]::Match($Event.Message, 'Remote IP Address:\s*(.*?)($|\r\n)').Groups[1].Value
        'Client Port' = [regex]::Match($Event.Message, 'Remote Port:\s*(.*?)($|\r\n)').Groups[1].Value
        'Protocol' = [regex]::Match($Event.Message, 'Protocol Sequence:\s*(.*?)($|\r\n)').Groups[1].Value
        'Action' = $action
    }
}

# Retrieve and parse RPCFW events
$RPCFWEvents = Get-WinEvent -LogName RPCFW -ErrorAction SilentlyContinue | ForEach-Object { Parse-RPCFWLog $_ }

$RPCFWSecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=5712} -ErrorAction SilentlyContinue | ForEach-Object { Parse-RPCFWSecurityLog $_ }

$CombinedEvents = $RPCFWSecurityEvents + $RPCFWEvents

# Sort combined events by time
$SortedEvents = $CombinedEvents | Sort-Object -Property TimeCreated

# Export combined events to CSV
$SortedEvents | Export-Csv -Path "RPCFW.csv" -NoTypeInformation


# Retrieve and parse RPCFW events
$RPCFWEvents = Get-WinEvent -LogName RPCFW -ErrorAction SilentlyContinue | ForEach-Object { Parse-RPCFWLog $_ }

$RPCFWSecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=5712} -ErrorAction SilentlyContinue | ForEach-Object { Parse-RPCFWSecurityLog $_ }

$CombinedEvents = $RPCFWSecurityEvents + $RPCFWEvents

# Sort combined events by time
$SortedEvents = $CombinedEvents | Sort-Object -Property TimeCreated

# Export combined events to CSV
$SortedEvents | Export-Csv -Path "RPCFW.csv" -NoTypeInformation
