# to-xlsx.ps1 — build a formatted Excel workbook from the flattened capture.
#
# flatten.ps1 -Format excel already produces a decoded CSV, but Excel opens a CSV
# with 8-character columns and no wrapping, so the long content fields look empty
# until you widen them by hand. This drives Excel via COM to do that once:
# frozen header, autofilter, sized columns, wrapped text, top-aligned rows.
#
# Usage:
#   .\to-xlsx.ps1                                     # from agent-traffic.json
#   .\to-xlsx.ps1 -Path .\agent-traffic-soc.json -Out .\soc.xlsx
param(
    [string]$Path = "./agent-traffic.json",
    [string]$Out  = "./copilot-spans.xlsx",
    [switch]$Full
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$csv  = Join-Path $env:TEMP "copilot-spans-$([guid]::NewGuid().ToString('N')).csv"

& (Join-Path $here 'flatten.ps1') -Path $Path -Format excel -Out $csv -Full:$Full | Out-Null
if (-not (Test-Path $csv)) { throw "flatten.ps1 produced no output for $Path" }

# Resolve to a full path: Excel's SaveAs resolves relative paths against its own
# working directory, not this script's.
$outFull = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Out))

$xl = New-Object -ComObject Excel.Application
$xl.Visible = $false
$xl.DisplayAlerts = $false
try {
    $wb = $xl.Workbooks.Open($csv)
    $ws = $wb.Worksheets.Item(1)
    $ws.Name = 'Copilot spans'

    $lastRow = $ws.UsedRange.Rows.Count
    $lastCol = $ws.UsedRange.Columns.Count

    # Header: bold, white on dark, frozen, filterable.
    $hdr = $ws.Range($ws.Cells.Item(1,1), $ws.Cells.Item(1,$lastCol))
    $hdr.Font.Bold = $true
    $hdr.Interior.Color = 4144959    # BGR 0x3F3F3F, dark grey
    $hdr.Font.Color     = 16777215   # white
    $ws.Rows.Item(1).AutoFilter() | Out-Null
    $xl.ActiveWindow.SplitRow = 1
    $xl.ActiveWindow.FreezePanes = $true

    # Narrow metadata columns auto-fit; wide content columns get a fixed width
    # plus wrapping, otherwise a 1,500-char prompt becomes one unreadable line.
    $ws.Columns.AutoFit() | Out-Null
    $wide = @{ 'UserRequest'=60; 'Prompt'=70; 'Response'=60; 'ToolArgs'=45; 'ToolResult'=55; 'ToolTarget'=40 }
    for ($c = 1; $c -le $lastCol; $c++) {
        $name = [string]$ws.Cells.Item(1,$c).Value2
        if ($wide.ContainsKey($name)) {
            $ws.Columns.Item($c).ColumnWidth = $wide[$name]
            $ws.Columns.Item($c).WrapText = $true
        } elseif ($ws.Columns.Item($c).ColumnWidth -gt 30) {
            $ws.Columns.Item($c).ColumnWidth = 30
        }
    }

    $body = $ws.Range($ws.Cells.Item(1,1), $ws.Cells.Item($lastRow,$lastCol))
    $body.VerticalAlignment = -4160        # xlTop
    $ws.Rows.Item("2:$lastRow").RowHeight = 90

    # 51 = xlOpenXMLWorkbook (.xlsx)
    $wb.SaveAs($outFull, 51)
    $wb.Close($false)
    "wrote $($lastRow - 1) spans -> $outFull"
}
finally {
    $xl.Quit()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($xl)
    Remove-Item $csv -Force -ErrorAction SilentlyContinue
}
