# flatten.ps1 — turn the file-exporter's OTLP JSON-lines into something readable.
#
# The file exporter writes one OTLP document per flush: spans are buried under
# resourceSpans[].scopeSpans[].spans[], and attributes are {key,value:{stringValue}}
# pairs rather than plain fields. Worse, the interesting content (prompts, model
# replies, tool results) is itself JSON *inside* those string attributes. This
# script unwraps both layers so you get plain prose per span.
#
# Usage:
#   .\flatten.ps1                                    # timeline of agent-traffic.json
#   .\flatten.ps1 -Path .\agent-traffic-soc.json     # the SOC-filtered feed
#   .\flatten.ps1 -Format excel                      # decoded .csv, opens cleanly in Excel
#   .\flatten.ps1 -Format ndjson -Out .\flat.json    # flat NDJSON for grep/jq
#   .\flatten.ps1 -Full                              # don't truncate long content
param(
    [string]$Path   = "./agent-traffic.json",
    [ValidateSet('timeline','excel','csv','ndjson')]
    [string]$Format = 'timeline',
    [string]$Out,
    [switch]$Full
)

# Excel's hard per-cell ceiling is 32,767 characters.
$CellMax = if ($Full) { 32000 } else { 1500 }

function Get-AttrValue($v) {
    if ($null -ne $v.stringValue) { return $v.stringValue }
    if ($null -ne $v.intValue)    { return $v.intValue }
    if ($null -ne $v.boolValue)   { return $v.boolValue }
    if ($null -ne $v.doubleValue) { return $v.doubleValue }
    return ($v | ConvertTo-Json -Compress -Depth 30)
}

function Clip($s, $n) {
    if ($null -eq $s) { return $null }
    $s = [string]$s
    if ($Full -or $s.Length -le $n) { return $s }
    # Plain ASCII marker: PowerShell 5.1's console encoding mangles non-ASCII here.
    "$($s.Substring(0,$n))...[+$($s.Length - $n) chars]"
}

# gen_ai.input.messages / output.messages hold a JSON array of
# {role, parts:[{type,content}]}. Flatten to "[role] text".
function ConvertFrom-Messages($json) {
    if ([string]::IsNullOrWhiteSpace($json)) { return $null }
    try { $msgs = $json | ConvertFrom-Json -ErrorAction Stop } catch { return $json }
    $out = @()
    foreach ($m in @($msgs)) {
        $parts = @()
        foreach ($p in @($m.parts)) {
            if     ($null -ne $p.content) { $parts += [string]$p.content }
            elseif ($null -ne $p.text)    { $parts += [string]$p.text }
        }
        if ($parts.Count) {
            $role = if ($m.role) { $m.role } else { 'msg' }
            $out += "[$role] " + ($parts -join ' ')
        }
        elseif ($null -ne $m.text) { $out += [string]$m.text }
    }
    if ($out.Count) { $out -join "`r`n" } else { $json }
}

# copilot_chat.user_request is plain text for most spans, but for agent-mode
# turns it is a JSON array of {type:"input_text", text:"..."} blocks.
function ConvertFrom-Loose($json) {
    if ([string]::IsNullOrWhiteSpace($json)) { return $null }
    $t = ([string]$json).TrimStart()
    if ($t[0] -ne '{' -and $t[0] -ne '[') { return $json }
    try { $obj = $json | ConvertFrom-Json -ErrorAction Stop } catch { return $json }
    $parts = @()
    foreach ($i in @($obj)) {
        if     ($null -ne $i.text)    { $parts += [string]$i.text }
        elseif ($null -ne $i.content) { $parts += [string]$i.content }
    }
    if ($parts.Count) { $parts -join "`r`n" } else { $json }
}

# Tool results are often a serialised VS Code render tree; the human-readable
# content lives in scattered "text" properties. Walk the object and collect them.
function Get-TextNodes($obj, [System.Collections.ArrayList]$acc, [int]$depth = 0) {
    if ($null -eq $obj -or $depth -gt 40) { return }
    if ($obj -is [string]) { return }
    if ($obj -is [System.Collections.IEnumerable]) {
        foreach ($i in $obj) { Get-TextNodes $i $acc ($depth + 1) }
        return
    }
    if ($obj -is [psobject]) {
        foreach ($prop in $obj.PSObject.Properties) {
            if ($prop.Name -eq 'text' -and $prop.Value -is [string] -and $prop.Value.Trim()) {
                [void]$acc.Add($prop.Value.Trim())
            } else {
                Get-TextNodes $prop.Value $acc ($depth + 1)
            }
        }
    }
}

function ConvertFrom-ToolPayload($json) {
    if ([string]::IsNullOrWhiteSpace($json)) { return $null }
    $t = ([string]$json).TrimStart()
    if ($t[0] -ne '{' -and $t[0] -ne '[') { return $json }   # already plain prose
    try { $obj = $json | ConvertFrom-Json -ErrorAction Stop } catch { return $json }
    $acc = New-Object System.Collections.ArrayList
    Get-TextNodes $obj $acc
    if ($acc.Count) { ($acc | Select-Object -Unique) -join ' ' } else { $json }
}

# Pull the one field that actually identifies what a tool call did.
function Get-ToolTarget($argsJson) {
    if ([string]::IsNullOrWhiteSpace($argsJson)) { return $null }
    try { $a = $argsJson | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    foreach ($k in 'command','filePath','resourcePath','path','query','operation') {
        if ($a.PSObject.Properties.Name -contains $k -and $a.$k) { return [string]$a.$k }
    }
    return $null
}

$records = New-Object System.Collections.ArrayList

foreach ($line in (Get-Content $Path)) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $doc = $line | ConvertFrom-Json

    foreach ($rs in $doc.resourceSpans) {
        $res = @{}
        foreach ($a in $rs.resource.attributes) { $res[$a.key] = Get-AttrValue $a.value }

        foreach ($ss in $rs.scopeSpans) {
            foreach ($sp in $ss.spans) {
                $at = @{}
                foreach ($a in $sp.attributes) { $at[$a.key] = Get-AttrValue $a.value }

                $startNs  = [int64]$sp.startTimeUnixNano
                $toolArgs = $at['gen_ai.tool.call.arguments']

                [void]$records.Add([pscustomobject]@{
                    Time        = [DateTimeOffset]::FromUnixTimeMilliseconds([math]::Floor($startNs / 1e6)).LocalDateTime
                    DurationSec = [math]::Round(([int64]$sp.endTimeUnixNano - $startNs) / 1e9, 1)
                    Operation   = $at['gen_ai.operation.name']
                    Agent       = $at['gen_ai.agent.name']
                    Tool        = $at['gen_ai.tool.name']
                    ToolTarget  = Clip (Get-ToolTarget $toolArgs) $CellMax
                    Model       = $at['gen_ai.request.model']
                    UserRequest = Clip (ConvertFrom-Loose $at['copilot_chat.user_request']) $CellMax
                    Prompt      = Clip (ConvertFrom-Messages $at['gen_ai.input.messages'])  $CellMax
                    Response    = Clip (ConvertFrom-Messages $at['gen_ai.output.messages']) $CellMax
                    ToolArgs    = Clip $toolArgs $CellMax
                    ToolResult  = Clip (ConvertFrom-ToolPayload $at['gen_ai.tool.call.result']) $CellMax
                    InTokens    = $at['gen_ai.usage.input_tokens']
                    OutTokens   = $at['gen_ai.usage.output_tokens']
                    Client      = $res['client.address']
                    SessionId   = $at['copilot_chat.chat_session_id']
                    TraceId     = $sp.traceId
                    SpanId      = $sp.spanId
                    ParentId    = $sp.parentSpanId
                    SpanName    = $sp.name
                })
            }
        }
    }
}

$records = $records | Sort-Object Time

switch ($Format) {
    'excel' {
        if (-not $Out) { $Out = './agent-traffic-flat.csv' }
        # Export-Csv -Encoding utf8 writes a BOM in PS 5.1, which is what makes
        # Excel read the file as UTF-8 instead of the system codepage.
        $records | Select-Object Time,DurationSec,Operation,Agent,Tool,ToolTarget,Model,
                                 UserRequest,Prompt,Response,ToolArgs,ToolResult,
                                 InTokens,OutTokens,Client,SessionId,TraceId,SpanId,ParentId,SpanName |
            Export-Csv -NoTypeInformation -Encoding utf8 $Out
        "wrote $($records.Count) spans -> $Out"
    }
    'csv'    {
        if (-not $Out) { $Out = './agent-traffic-flat.csv' }
        $records | Export-Csv -NoTypeInformation -Encoding utf8 $Out
        "wrote $($records.Count) spans -> $Out"
    }
    'ndjson' {
        $lines = $records | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 10 }
        if ($Out) { $lines | Out-File -Encoding utf8 $Out; "wrote $($records.Count) spans -> $Out" }
        else      { $lines }
    }
    'timeline' {
        "$($records.Count) spans from $Path"
        ""
        foreach ($r in $records) {
            $label = if ($r.Tool) { "$($r.Operation) $($r.Tool)" }
                     elseif ($r.Agent) { "$($r.Operation) [$($r.Agent)]" }
                     else { $r.Operation }
            "{0:HH:mm:ss}  {1,7}s  {2}" -f $r.Time, $r.DurationSec, $label
            if ($r.Model)      { "                     model:  $($r.Model)  in=$($r.InTokens) out=$($r.OutTokens)" }
            if ($r.ToolTarget) { "                     target: $(Clip $r.ToolTarget 160)" }
            if ($r.UserRequest){ "                     ask:    $(Clip ($r.UserRequest -replace "`r?`n",' ') 160)" }
            if ($r.ToolResult) { "                     result: $(Clip ($r.ToolResult -replace "`r?`n",' ') 160)" }
            if ($r.Response -and -not $r.Tool) { "                     out:    $(Clip ($r.Response -replace "`r?`n",' ') 160)" }
            ""
        }
    }
}
