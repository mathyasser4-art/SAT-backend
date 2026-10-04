Add-Type -AssemblyName System.Drawing

function InvertToLightMode($inputPath, $outputPath) {
    $src = [System.Drawing.Bitmap]::FromFile((Resolve-Path $inputPath))
    $rect = New-Object System.Drawing.Rectangle(0, 0, $src.Width, $src.Height)
    $dest = New-Object System.Drawing.Bitmap($src.Width, $src.Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    
    $srcData = $src.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $destData = $dest.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    
    $bytes = [Math]::Abs($srcData.Stride) * $src.Height
    $rgbValues = New-Object byte[] $bytes
    [System.Runtime.InteropServices.Marshal]::Copy($srcData.Scan0, $rgbValues, 0, $bytes)
    
    for ($i = 0; $i -lt $bytes; $i += 4) {
        $b = $rgbValues[$i]
        $g = $rgbValues[$i + 1]
        $r = $rgbValues[$i + 2]
        
        # Invert colors
        $rgbValues[$i] = 255 - $b
        $rgbValues[$i + 1] = 255 - $g
        $rgbValues[$i + 2] = 255 - $r
        $rgbValues[$i + 3] = 255
    }
    
    [System.Runtime.InteropServices.Marshal]::Copy($rgbValues, 0, $destData.Scan0, $bytes)
    $src.UnlockBits($srcData)
    $dest.UnlockBits($destData)
    $src.Dispose()
    
    $dest.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $dest.Dispose()
    Write-Host "Converted $inputPath -> $outputPath (Light Mode)"
}

# 1. Invert Q5 and Q9
InvertToLightMode "m2_q5.png" "m2_q5_light.png"
InvertToLightMode "m2_q9.png" "m2_q9_light.png"

# 2. Render Q6 Right Triangle XYZ in clean vector Light Mode
$bmp6 = New-Object System.Drawing.Bitmap 450, 420
$g6 = [System.Drawing.Graphics]::FromImage($bmp6)
$g6.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g6.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$g6.Clear([System.Drawing.Color]::White)

$pen6 = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(25, 25, 25), 2.0)
$brush6 = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(20, 20, 20))
$fontSerif = New-Object System.Drawing.Font('Times New Roman', 20, [System.Drawing.FontStyle]::Italic)
$fontRegular = New-Object System.Drawing.Font('Times New Roman', 18, [System.Drawing.FontStyle]::Regular)
$fontNote = New-Object System.Drawing.Font('Times New Roman', 13, [System.Drawing.FontStyle]::Regular)

$pZ = New-Object System.Drawing.PointF 110, 300
$pX = New-Object System.Drawing.PointF 110, 80
$pY = New-Object System.Drawing.PointF 370, 300

$g6.DrawLine($pen6, $pZ, $pX)
$g6.DrawLine($pen6, $pZ, $pY)
$g6.DrawLine($pen6, $pX, $pY)

$sqPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(25, 25, 25), 1.5)
$g6.DrawRectangle($sqPen, 110, 280, 20, 20)

$g6.DrawString('X', $fontSerif, $brush6, 100, 45)
$g6.DrawString('Z', $fontSerif, $brush6, 80, 305)
$g6.DrawString('Y', $fontSerif, $brush6, 380, 295)
$g6.DrawString('22', $fontRegular, $brush6, 65, 180)
$g6.DrawString('28', $fontRegular, $brush6, 225, 315)

$sf = New-Object System.Drawing.StringFormat
$sf.Alignment = [System.Drawing.StringAlignment]::Center
$g6.DrawString('Note: Figure not drawn to scale.', $fontNote, $brush6, 225, 380, $sf)

$g6.Dispose()
$bmp6.Save('m2_q6_light.png', [System.Drawing.Imaging.ImageFormat]::Png)
$bmp6.Dispose()
Write-Host "Generated m2_q6_light.png (Light Mode)"

# 3. Render Q12 Scatterplot in clean vector Light Mode
$bmp12 = New-Object System.Drawing.Bitmap 480, 420
$g12 = [System.Drawing.Graphics]::FromImage($bmp12)
$g12.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g12.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$g12.Clear([System.Drawing.Color]::White)

$penAxis12 = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 30, 30), 1.5)
$penGrid12 = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(215, 215, 215), 1.0)
$penCurve12 = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(20, 20, 20), 2.0)
$brushPoint12 = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 15, 15))
$brushLabel12 = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(25, 25, 25))
$fontAxis12 = New-Object System.Drawing.Font('Times New Roman', 14, [System.Drawing.FontStyle]::Italic)
$fontNum12 = New-Object System.Drawing.Font('Times New Roman', 11, [System.Drawing.FontStyle]::Regular)

$originX = 70
$originY = 360

function MapX($x) { return $originX + $x * 30 }
function MapY($y) { return $originY - $y * 16.6 }

# Draw Grid Lines
for ($x = 2; $x -le 12; $x += 2) {
    $px = MapX $x
    $g12.DrawLine($penGrid12, $px, (MapY 18), $px, $originY)
    $g12.DrawString($x.ToString(), $fontNum12, $brushLabel12, ($px - 7), ($originY + 5))
}
for ($y = 2; $y -le 18; $y += 2) {
    $py = MapY $y
    $g12.DrawLine($penGrid12, $originX, $py, (MapX 12), $py)
    $g12.DrawString($y.ToString(), $fontNum12, $brushLabel12, ($originX - 25), ($py - 7))
}

# Draw Axes
$g12.DrawLine($penAxis12, $originX, $originY, (MapX 12.5), $originY)
$g12.DrawLine($penAxis12, $originX, $originY, $originX, (MapY 18.5))

# Axis Labels
$g12.DrawString('x', $fontAxis12, $brushLabel12, (MapX 12.3), ($originY + 5))
$g12.DrawString('y', $fontAxis12, $brushLabel12, ($originX - 25), (MapY 19.5))
$g12.DrawString('O', $fontNum12, $brushLabel12, ($originX - 18), ($originY + 5))

# Draw Quadratic Model Curve y = 0.04x^2 - 0.06x + 6.57
$prevPt = $null
for ($x = 0; $x -le 12; $x += 0.2) {
    $y = 0.04 * $x * $x - 0.06 * $x + 6.57
    $pt = New-Object System.Drawing.PointF (MapX $x), (MapY $y)
    if ($prevPt -ne $null) {
        $g12.DrawLine($penCurve12, $prevPt, $pt)
    }
    $prevPt = $pt
}

# 9 Data Points (Data Set A)
$points = @(
    @(0, 14.5), # The error point at x = 0
    @(1.5, 6.8),
    @(3.0, 6.9),
    @(4.5, 7.3),
    @(6.0, 7.8),
    @(7.5, 8.5),
    @(9.0, 9.4),
    @(10.5, 10.6),
    @(11.5, 11.8)
)

foreach ($p in $points) {
    $cx = MapX $p[0]
    $cy = MapY $p[1]
    $g12.FillEllipse($brushPoint12, ($cx - 4), ($cy - 4), 8, 8)
}

$g12.Dispose()
$bmp12.Save('m2_q12_light.png', [System.Drawing.Imaging.ImageFormat]::Png)
$bmp12.Dispose()
Write-Host "Generated m2_q12_light.png (Light Mode)"
