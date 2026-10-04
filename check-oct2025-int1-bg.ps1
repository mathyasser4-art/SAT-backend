Add-Type -AssemblyName System.Drawing
$dir = "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\oct2025_int1_images"
Get-ChildItem -Path $dir -Filter "*_orig.png" | ForEach-Object {
    $bmp = [System.Drawing.Bitmap]::FromFile($_.FullName)
    $c1 = $bmp.GetPixel(5, 5)
    $c2 = $bmp.GetPixel($bmp.Width - 5, 5)
    $c3 = $bmp.GetPixel(5, $bmp.Height - 5)
    $b1 = ($c1.R + $c1.G + $c1.B)/3
    $b2 = ($c2.R + $c2.G + $c2.B)/3
    $b3 = ($c3.R + $c3.G + $c3.B)/3
    $avgB = ($b1 + $b2 + $b3)/3
    $isDark = $avgB -lt 128
    Write-Host "$($_.Name) [Size: $($bmp.Width)x$($bmp.Height)]: Avg Brightness = $([int]$avgB) -> DarkMode: $isDark"
    $bmp.Dispose()
}
