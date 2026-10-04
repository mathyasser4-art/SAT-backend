Add-Type -AssemblyName System.Drawing
Get-ChildItem 'march2026_int1_images\*.png' | ForEach-Object {
    $bmp = [System.Drawing.Bitmap]::FromFile($_.FullName)
    $c0 = $bmp.GetPixel(5, 5)
    $cm = $bmp.GetPixel([int]($bmp.Width/2), [int]($bmp.Height/2))
    Write-Host ("{0}: {1}x{2}, TopLeft: R={3},G={4},B={5}, Center: R={6},G={7},B={8}" -f $_.Name, $bmp.Width, $bmp.Height, $c0.R, $c0.G, $c0.B, $cm.R, $cm.G, $cm.B)
    $bmp.Dispose()
}
