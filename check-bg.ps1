Add-Type -AssemblyName System.Drawing
foreach ($name in @('q4', 'q7', 'q20', 'q21', 'q22')) {
  $bmp = New-Object System.Drawing.Bitmap "$name.png"
  $c1 = $bmp.GetPixel(5, 5)
  $c2 = $bmp.GetPixel($bmp.Width - 5, 5)
  $c3 = $bmp.GetPixel(5, $bmp.Height - 5)
  $avgR = ($c1.R + $c2.R + $c3.R) / 3
  $avgG = ($c1.G + $c2.G + $c3.G) / 3
  $avgB = ($c1.B + $c2.B + $c3.B) / 3
  $isDark = ($avgR + $avgG + $avgB) / 3 -lt 128
  Write-Host "$name.png: Width=$($bmp.Width), Height=$($bmp.Height), CornerRGB=($([int]$avgR),$([int]$avgG),$([int]$avgB)), IsDark=$isDark"
  $bmp.Dispose()
}
