Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 480, 420
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$g.Clear([System.Drawing.Color]::FromArgb(10, 10, 10))

$penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(200, 200, 200), 1.5)
$penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(45, 45, 45), 1.0)
$penCurve = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(235, 235, 235), 2.0)
$brushPoint = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(240, 240, 240))
$brushLabel = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(220, 220, 220))
$fontAxis = New-Object System.Drawing.Font('Times New Roman', 14, [System.Drawing.FontStyle]::Italic)
$fontNum = New-Object System.Drawing.Font('Times New Roman', 11, [System.Drawing.FontStyle]::Regular)

# Origin at (70, 360)
# X goes from 0 to 12 (width: 360px => 30px per unit)
# Y goes from 0 to 18 (height: 300px => 16.6px per unit)
$originX = 70
$originY = 360

function MapX($x) { return $originX + $x * 30 }
function MapY($y) { return $originY - $y * 16.6 }

# Draw Grid Lines
for ($x = 2; $x -le 12; $x += 2) {
    $px = MapX $x
    $g.DrawLine($penGrid, $px, (MapY 18), $px, $originY)
    $g.DrawString($x.ToString(), $fontNum, $brushLabel, ($px - 7), ($originY + 5))
}
for ($y = 2; $y -le 18; $y += 2) {
    $py = MapY $y
    $g.DrawLine($penGrid, $originX, $py, (MapX 12), $py)
    $g.DrawString($y.ToString(), $fontNum, $brushLabel, ($originX - 25), ($py - 7))
}

# Draw Axes
$g.DrawLine($penAxis, $originX, $originY, (MapX 12.5), $originY)
$g.DrawLine($penAxis, $originX, $originY, $originX, (MapY 18.5))

# Axis Labels
$g.DrawString('x', $fontAxis, $brushLabel, (MapX 12.3), ($originY + 5))
$g.DrawString('y', $fontAxis, $brushLabel, ($originX - 25), (MapY 19.5))
$g.DrawString('O', $fontNum, $brushLabel, ($originX - 18), ($originY + 5))


# Draw Quadratic Model Curve y = 0.04x^2 - 0.06x + 6.57
$prevPt = $null
for ($x = 0; $x -le 12; $x += 0.2) {
    $y = 0.04 * $x * $x - 0.06 * $x + 6.57
    $pt = New-Object System.Drawing.PointF (MapX $x), (MapY $y)
    if ($prevPt -ne $null) {
        $g.DrawLine($penCurve, $prevPt, $pt)
    }
    $prevPt = $pt
}

# 9 Data Points (Data Set A)
# Point at x = 0 is an outlier at y = 14.5
# Other 8 points cluster near the model curve
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
    $g.FillEllipse($brushPoint, ($cx - 4), ($cy - 4), 8, 8)
}

$g.Dispose()
$bmp.Save('scatterplot_q12.png', [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host 'Rendered scatterplot_q12.png successfully!'
