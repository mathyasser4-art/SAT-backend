Add-Type -AssemblyName System.Drawing

Get-ChildItem -Filter "mar26_us1_*.png" | ForEach-Object {
    $img = [System.Drawing.Image]::FromFile($_.FullName)
    $bmp = New-Object System.Drawing.Bitmap($img)
    $p = $bmp.GetPixel(5, 5)
    $bmp.Dispose()
    $img.Dispose()
    $isDark = ($p.R -lt 50 -and $p.G -lt 50 -and $p.B -lt 50)
    Write-Host "$($_.Name) -> R=$($p.R), G=$($p.G), B=$($p.B) | Dark: $isDark"
}
