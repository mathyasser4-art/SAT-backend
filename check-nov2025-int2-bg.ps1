Add-Type -AssemblyName System.Drawing
Get-ChildItem -Path "nov2025_int2_images\*_orig.png" | ForEach-Object {
    $bmp = New-Object System.Drawing.Bitmap($_.FullName)
    $c = $bmp.GetPixel(5, 5)
    $lum = [math]::Round(0.299 * $c.R + 0.587 * $c.G + 0.114 * $c.B)
    $status = if ($lum -lt 128) { 'DARK MODE' } else { 'LIGHT MODE' }
    Write-Host ('{0,-20} {1}x{2} RGB=({3},{4},{5}) Lum={6} => {7}' -f $_.Name, $bmp.Width, $bmp.Height, $c.R, $c.G, $c.B, $lum, $status)
    $bmp.Dispose()
}
