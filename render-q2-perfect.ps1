Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "sep2025_us1_images"
$outPath = Join-Path $imgDir "m1_q2_light.png"

$w = 540; $h = 420
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$g.Clear([System.Drawing.Color]::White)

$cDark = [System.Drawing.Color]::FromArgb(30, 41, 59)
$penLine = New-Object System.Drawing.Pen($cDark, 2.2)
$penLine.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$penLine.EndCap = [System.Drawing.Drawing2D.LineCap]::Round

$brushDark = New-Object System.Drawing.SolidBrush($cDark)
$brushBg = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)

# Fonts matching official SAT typography (Times New Roman / Latin Modern)
$fontLabel = New-Object System.Drawing.Font("Times New Roman", 15.0, [System.Drawing.FontStyle]::Italic)
$fontVal = New-Object System.Drawing.Font("Times New Roman", 14.0, [System.Drawing.FontStyle]::Regular)
$deg = [char]0x00B0

# Horizontal parallel lines r and s
$leftX = 60.0; $rightX = 470.0
$ry = 140.0; $sy = 270.0

# Transversal line t: slope = 1.0 (45 degrees)
# From (90, 390) to (450, 30)
# dx/dy = (450 - 90)/(30 - 390) = 360 / (-360) = -1.0
$t1x = 90.0;  $t1y = 390.0
$t2x = 450.0; $t2y = 30.0

$g.DrawLine($penLine, [float]$leftX, [float]$ry, [float]$rightX, [float]$ry)
$g.DrawLine($penLine, [float]$leftX, [float]$sy, [float]$rightX, [float]$sy)
$g.DrawLine($penLine, [float]$t1x, [float]$t1y, [float]$t2x, [float]$t2y)

# Intersections:
# ix_r at y = 140: x = 90 + (140 - 390) * (-1.0) = 90 + 250 = 340.0
$ix_r = 340.0
# ix_s at y = 270: x = 90 + (270 - 390) * (-1.0) = 90 + 120 = 210.0
$ix_s = 210.0

# Function to draw text with a protective white halo/padding so lines never cut through
function Draw-LabelWithHalo($text, $font, $x, $y) {
    $size = $g.MeasureString($text, $font)
    $pad = 3.0
    $rect = New-Object System.Drawing.RectangleF([float]($x - $pad), [float]($y - $pad), [float]($size.Width + $pad * 2), [float]($size.Height + $pad * 2))
    $g.FillRectangle($brushBg, $rect)
    $g.DrawString($text, $font, $brushDark, [float]$x, [float]$y)
}

# Line labels r, s, t
$g.DrawString("r", $fontLabel, $brushDark, [float]($rightX + 16), [float]($ry - 12))
$g.DrawString("s", $fontLabel, $brushDark, [float]($rightX + 16), [float]($sy - 12))
$g.DrawString("t", $fontLabel, $brushDark, [float]($t2x + 12), [float]($t2y - 10))

# Angle labels at line r:
# 103 deg is in the obtuse upper-left angle (left of t, above r)
# At y = 110, line t is at x = 370. ix_r is at 340. Upper-left quadrant is x < 340, y < 140.
Draw-LabelWithHalo "103$deg" $fontVal 275.0 108.0

# 77 deg is in the acute upper-right angle (right of t, above r)
# At y = 110, line t is at x = 370. To be comfortably to the right of line t: x >= 390!
Draw-LabelWithHalo "77$deg" $fontVal 392.0 108.0

# Angle labels at line s:
# a deg is in the acute upper-right angle (right of t, above s)
# At y = 240, line t is at x = 240. To be comfortably to the right of line t: x >= 255!
Draw-LabelWithHalo "a$deg" $fontVal 255.0 238.0

# 77 deg is in the acute lower-left angle (left of t, below s)
# At y = 300, line t is at x = 180. To be comfortably to the left of line t: x <= 135!
Draw-LabelWithHalo "77$deg" $fontVal 125.0 295.0

$bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host "Generated perfect Q2 image: $outPath"
