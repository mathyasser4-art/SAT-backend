Add-Type -AssemblyName System.Drawing

$outDir = "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\dec2024_int1_light_images"
if (!(Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

function Save-Bitmap($bmp, $filename) {
    $path = Join-Path $outDir $filename
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Created light image: $filename"
}

# -------------------------------------------------------------
# 1. M1_Q1: Two lines intersecting at (-4, 2)
# Grid: x in [-6, 6], y in [-6, 6]
# Line 1: y = 0.25x + 3 (passes through (-4, 2), (0, 3), (4, 4))
# Line 2: y = -1.75x - 5 (passes through (-4, 2), (0, -5))
# -------------------------------------------------------------
$w = 500; $h = 500
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$ox = 250; $oy = 250
$scale = 32.0 # 1 unit = 32 px

$penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(215, 222, 230), 1)
$penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 50, 60), 2)
$penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
$fontTick = New-Object System.Drawing.Font("Segoe UI", 9)
$brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(50, 60, 70))

for ($i = -6; $i -le 6; $i++) {
    $x = $ox + $i * $scale
    $g.DrawLine($penGrid, [float]$x, 30.0, [float]$x, 470.0)
    $y = $oy - $i * $scale
    $g.DrawLine($penGrid, 30.0, [float]$y, 470.0, [float]$y)
}

# Ticks and labels
for ($i = -6; $i -le 6; $i++) {
    if ($i -ne 0) {
        $x = $ox + $i * $scale
        $g.DrawString("$i", $fontTick, $brushText, [float]($x - 8), [float]($oy + 3))
        $y = $oy - $i * $scale
        $g.DrawString("$i", $fontTick, $brushText, [float]($ox + 4), [float]($y - 7))
    }
}
$g.DrawString("O", $fontTick, $brushText, [float]($ox - 15), [float]($oy + 3))
$g.DrawString("x", (New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Italic)), $brushText, 475.0, [float]($oy - 10))
$g.DrawString("y", (New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Italic)), $brushText, [float]($ox - 8), 10.0)

# Axes
$g.DrawLine($penAxis, 25.0, [float]$oy, 475.0, [float]$oy)
$penAxisY = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 50, 60), 2)
$penAxisY.CustomEndCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap(4, 5)
$penAxisY.CustomStartCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap(4, 5)
$g.DrawLine($penAxis, [float]$ox, 475.0, [float]$ox, 25.0)

# Line 1: y = 0.25x + 3
$p1_start_x = -6.0; $p1_start_y = 0.25 * (-6.0) + 3.0
$p1_end_x = 6.0; $p1_end_y = 0.25 * 6.0 + 3.0
$penLine1 = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 80, 180), 2.5)
$g.DrawLine($penLine1, [float]($ox + $p1_start_x * $scale), [float]($oy - $p1_start_y * $scale), [float]($ox + $p1_end_x * $scale), [float]($oy - $p1_end_y * $scale))

# Line 2: y = -1.75x - 5
$p2_start_x = -6.0; $p2_start_y = -1.75 * (-6.0) - 5.0 # 5.5
$p2_end_x = 0.3; $p2_end_y = -1.75 * 0.3 - 5.0 # -5.525
$penLine2 = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(210, 50, 50), 2.5)
$g.DrawLine($penLine2, [float]($ox + $p2_start_x * $scale), [float]($oy - $p2_start_y * $scale), [float]($ox + $p2_end_x * $scale), [float]($oy - $p2_end_y * $scale))

# Intersection point (-4, 2)
$ix = $ox - 4.0 * $scale; $iy = $oy - 2.0 * $scale
$brushPt = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(20, 30, 40))
$g.FillEllipse($brushPt, [float]($ix - 4), [float]($iy - 4), 8.0, 8.0)

$g.Dispose()
Save-Bitmap $bmp "M1_Q1_6aa58665ec7ba02921a44445.png"


# -------------------------------------------------------------
# 2. M1_Q3: Table x, y
# -------------------------------------------------------------
$w = 340; $h = 220
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$penBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(70, 80, 95), 1.5)
$brushHdr = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(240, 244, 248))
$g.FillRectangle($brushHdr, 40, 25, 260, 40)
$g.DrawRectangle($penBorder, 40, 25, 260, 160)
$g.DrawLine($penBorder, 170, 25, 170, 185)

$fontHdr = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$fontItalic = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Italic)
$fontCell = New-Object System.Drawing.Font("Segoe UI", 11)
$brushT = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 40, 50))

$sf = New-Object System.Drawing.StringFormat
$sf.Alignment = [System.Drawing.StringAlignment]::Center
$sf.LineAlignment = [System.Drawing.StringAlignment]::Center

$g.DrawString("x", $fontItalic, $brushT, (New-Object System.Drawing.RectangleF(40, 25, 130, 40)), $sf)
$g.DrawString("y", $fontItalic, $brushT, (New-Object System.Drawing.RectangleF(170, 25, 130, 40)), $sf)

$rows = @(
    @("0", "22"),
    @("1", "23"),
    @("2", "24")
)

for ($i = 0; $i -lt 3; $i++) {
    $yTop = 65 + $i * 40
    $g.DrawLine($penBorder, 40, $yTop, 300, $yTop)
    $g.DrawString($rows[$i][0], $fontCell, $brushT, (New-Object System.Drawing.RectangleF(40, $yTop, 130, 40)), $sf)
    $g.DrawString($rows[$i][1], $fontCell, $brushT, (New-Object System.Drawing.RectangleF(170, $yTop, 130, 40)), $sf)
}

$g.Dispose()
Save-Bitmap $bmp "M1_Q3_6aa5874bec7ba02921a4444d.png"


# -------------------------------------------------------------
# 3. M1_Q6: Parabola
# x-axis: Time (seconds) [0..10]
# y-axis: Height above ground (meters) [0..60]
# Vertex at (2, 20)
# -------------------------------------------------------------
$w = 480; $h = 420
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$ox = 90; $oy = 350
$scaleX = 34.0 # 10 units = 340 px
$scaleY = 5.0  # 60 units = 300 px

$penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 226, 232), 1)
$penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 50, 60), 2)
$fontTick = New-Object System.Drawing.Font("Segoe UI", 9)
$fontLabel = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$brushT = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(40, 50, 60))

for ($x = 0; $x -le 10; $x++) {
    $px = $ox + $x * $scaleX
    $g.DrawLine($penGrid, [float]$px, [float]($oy - 300), [float]$px, [float]$oy)
    if ($x -gt 0) {
        $g.DrawString("$x", $fontTick, $brushT, [float]($px - 5), [float]($oy + 5))
    }
}
for ($y = 0; $y -le 60; $y += 10) {
    $py = $oy - $y * $scaleY
    $g.DrawLine($penGrid, [float]$ox, [float]$py, [float]($ox + 340), [float]$py)
    if ($y -gt 0) {
        $g.DrawString("$y", $fontTick, $brushT, [float]($ox - 25), [float]($py - 7))
    }
}
$g.DrawString("O", $fontTick, $brushT, [float]($ox - 15), [float]($oy + 3))

# Axes
$g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]($ox + 355), [float]$oy)
$g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, [float]($oy - 315))

# Parabola: y = -5x(x - 4) = -5x^2 + 20x. Vertex (2, 20)
$pts = @()
for ($step = 0; $step -le 40; $step++) {
    $xVal = $step * 0.1
    $yVal = -5.0 * $xVal * ($xVal - 4.0)
    $pts += New-Object System.Drawing.PointF([float]($ox + $xVal * $scaleX), [float]($oy - $yVal * $scaleY))
}
$penCurve = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 90, 200), 2.5)
$g.DrawCurve($penCurve, $pts)

# Vertex point
$vx = $ox + 2.0 * $scaleX; $vy = $oy - 20.0 * $scaleY
$g.FillEllipse($brushT, [float]($vx - 4), [float]($vy - 4), 8.0, 8.0)

# Labels
$sfCenter = New-Object System.Drawing.StringFormat
$sfCenter.Alignment = [System.Drawing.StringAlignment]::Center
$g.DrawString("Time (seconds)", $fontLabel, $brushT, (New-Object System.Drawing.RectangleF($ox, ($oy + 25), 340, 25)), $sfCenter)

# Y-axis label rotated
$g.TranslateTransform(25, 200)
$g.RotateTransform(-90)
$g.DrawString("Height above ground (meters)", $fontLabel, $brushT, 0, 0, $sfCenter)
$g.ResetTransform()

$g.Dispose()
Save-Bitmap $bmp "M1_Q6_6aa5896aec7ba02921a44460.png"


# -------------------------------------------------------------
# 4. M1_Q8: Table Task | Time (minutes)
# -------------------------------------------------------------
$w = 340; $h = 280
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$penBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(70, 80, 95), 1.5)
$brushHdr = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(240, 244, 248))
$g.FillRectangle($brushHdr, 40, 20, 260, 40)
$g.DrawRectangle($penBorder, 40, 20, 260, 240)
$g.DrawLine($penBorder, 140, 20, 140, 260)

$fontHdr = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontCell = New-Object System.Drawing.Font("Segoe UI", 11)
$brushT = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 40, 50))

$g.DrawString("Task", $fontHdr, $brushT, (New-Object System.Drawing.RectangleF(40, 20, 100, 40)), $sf)
$g.DrawString("Time (minutes)", $fontHdr, $brushT, (New-Object System.Drawing.RectangleF(140, 20, 160, 40)), $sf)

$tasks = @(
    @("A", "8"),
    @("B", "6"),
    @("C", "14"),
    @("D", "11"),
    @("E", "11")
)

for ($i = 0; $i -lt 5; $i++) {
    $yTop = 60 + $i * 40
    $g.DrawLine($penBorder, 40, $yTop, 300, $yTop)
    $g.DrawString($tasks[$i][0], $fontCell, $brushT, (New-Object System.Drawing.RectangleF(40, $yTop, 100, 40)), $sf)
    $g.DrawString($tasks[$i][1], $fontCell, $brushT, (New-Object System.Drawing.RectangleF(140, $yTop, 160, 40)), $sf)
}

$g.Dispose()
Save-Bitmap $bmp "M1_Q8_6aa58a32ec7ba02921a44468.png"


# -------------------------------------------------------------
# 5. M1_Q10: Scatterplot with Line of Best Fit
# x in [0..8], y in [0..16]
# -------------------------------------------------------------
$w = 460; $h = 440
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$ox = 60; $oy = 380
$scaleX = 42.0 # 8 units = 336 px
$scaleY = 20.0 # 16 units = 320 px

$penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 226, 232), 1)
$penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 50, 60), 2)
$fontTick = New-Object System.Drawing.Font("Segoe UI", 9)
$brushT = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(40, 50, 60))

for ($x = 0; $x -le 8; $x++) {
    $px = $ox + $x * $scaleX
    $g.DrawLine($penGrid, [float]$px, [float]($oy - 320), [float]$px, [float]$oy)
    if ($x -gt 0) {
        $g.DrawString("$x", $fontTick, $brushT, [float]($px - 5), [float]($oy + 5))
    }
}
for ($y = 0; $y -le 16; $y += 2) {
    $py = $oy - $y * $scaleY
    $g.DrawLine($penGrid, [float]$ox, [float]$py, [float]($ox + 336), [float]$py)
    if ($y -gt 0) {
        $g.DrawString("$y", $fontTick, $brushT, [float]($ox - 22), [float]($py - 7))
    }
}
$g.DrawString("O", $fontTick, $brushT, [float]($ox - 15), [float]($oy + 3))
$g.DrawString("x", (New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Italic)), $brushT, [float]($ox + 345), [float]($oy - 8))
$g.DrawString("y", (New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Italic)), $brushT, [float]($ox - 7), [float]($oy - 338))

# Axes
$g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]($ox + 348), [float]$oy)
$g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, [float]($oy - 328))

# Line of best fit: y = -0.84x + 11.19
$penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 80, 180), 2.5)
$lx1 = 0.0; $ly1 = 11.19
$lx2 = 8.0; $ly2 = -0.84 * 8.0 + 11.19 # 4.47
$g.DrawLine($penLine, [float]($ox + $lx1 * $scaleX), [float]($oy - $ly1 * $scaleY), [float]($ox + $lx2 * $scaleX), [float]($oy - $ly2 * $scaleY))

# Scatter points: (1, 10.4), (2, 9.6), (4, 7.6), (5, 6.8), (6, 6.1), (7, 5.6)
$pts = @(
    @(1.0, 10.4),
    @(2.0, 9.6),
    @(4.0, 7.6),
    @(5.0, 6.8),
    @(6.0, 6.1),
    @(7.0, 5.6)
)
$brushDot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(220, 50, 50))
$penDot = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(50, 50, 50), 1)
foreach ($pt in $pts) {
    $dx = $ox + $pt[0] * $scaleX
    $dy = $oy - $pt[1] * $scaleY
    $g.FillEllipse($brushDot, [float]($dx - 4), [float]($dy - 4), 8.0, 8.0)
    $g.DrawEllipse($penDot, [float]($dx - 4), [float]($dy - 4), 8.0, 8.0)
}

$g.Dispose()
Save-Bitmap $bmp "M1_Q10_6aa58ad8ec7ba02921a44470.png"


# -------------------------------------------------------------
# 6. M1_Q11: Parallel lines q, r intersected by s
# -------------------------------------------------------------
$w = 460; $h = 360
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 50, 60), 2)
$fontL = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Italic)
$fontAng = New-Object System.Drawing.Font("Segoe UI", 11)
$brushT = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 40, 50))

# Horizontal lines q and r
$g.DrawLine($penLine, 50, 110, 390, 110)
$g.DrawString("q", $fontL, $brushT, 400, 100)

$g.DrawLine($penLine, 50, 230, 390, 230)
$g.DrawString("r", $fontL, $brushT, 400, 220)

# Transversal s: angle ~ 45 deg, from bottom-left to top-right
$g.DrawLine($penLine, 70, 310, 370, 30)
$g.DrawString("s", $fontL, $brushT, 50, 310)

# Intersection 1: (290, 110)
# Angle 77° is acute angle top-right of transversal above line q
$g.DrawString("77°", $fontAng, $brushT, 315, 80)

# Intersection 2: (170, 230)
# Angle y° is obtuse angle left of transversal above line r
$g.DrawString("y°", $fontAng, $brushT, 145, 205)

$fontNote = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
$g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushT, (New-Object System.Drawing.RectangleF(0, 325, 460, 25)), $sfCenter)

$g.Dispose()
Save-Bitmap $bmp "M1_Q11_6aa58b67ec7ba02921a44474.png"


# -------------------------------------------------------------
# 7. M2_Q1: Right triangle with 24° and a°
# -------------------------------------------------------------
$w = 420; $h = 360
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$penTri = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(35, 45, 55), 2.5)
$brushT = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 40, 50))
$fontAng = New-Object System.Drawing.Font("Segoe UI", 11)

$ptsTri = @(
    (New-Object System.Drawing.PointF(70, 50)),
    (New-Object System.Drawing.PointF(70, 290)),
    (New-Object System.Drawing.PointF(370, 290))
)
$g.DrawPolygon($penTri, $ptsTri)

# Right angle square at (70, 290)
$g.DrawRectangle($penTri, 70, 270, 20, 20)

# Top angle 24°
$g.DrawString("24°", $fontAng, $brushT, 78, 85)

# Bottom-right angle a°
$g.DrawString("a°", (New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Italic)), $brushT, 310, 260)

$fontNote = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
$g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushT, (New-Object System.Drawing.RectangleF(0, 325, 420, 25)), $sfCenter)

$g.Dispose()
Save-Bitmap $bmp "M2_Q1_6aa599feec7ba02921a444c7.png"


# -------------------------------------------------------------
# 8. M2_Q7: 2-way frequency table (Hawks / Stars)
# -------------------------------------------------------------
$w = 420; $h = 280
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$penBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(70, 80, 95), 1.5)
$brushHdr = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(240, 244, 248))
$g.FillRectangle($brushHdr, 30, 20, 360, 45)
$g.DrawRectangle($penBorder, 30, 20, 360, 225)

# Columns: 110, 85, 85, 80
$g.DrawLine($penBorder, 140, 20, 140, 245)
$g.DrawLine($penBorder, 225, 20, 225, 245)
$g.DrawLine($penBorder, 310, 20, 310, 245)

$fontHdr = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontCell = New-Object System.Drawing.Font("Segoe UI", 11)
$brushT = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 40, 50))

$g.DrawString("Hawks", $fontHdr, $brushT, (New-Object System.Drawing.RectangleF(140, 20, 85, 45)), $sf)
$g.DrawString("Stars", $fontHdr, $brushT, (New-Object System.Drawing.RectangleF(225, 20, 85, 45)), $sf)
$g.DrawString("Total", $fontHdr, $brushT, (New-Object System.Drawing.RectangleF(310, 20, 80, 45)), $sf)

$tableData = @(
    @("Small", "6", "9", "15"),
    @("Medium", "21", "34", "55"),
    @("Large", "15", "25", "40"),
    @("Total", "42", "68", "110")
)

for ($i = 0; $i -lt 4; $i++) {
    $yTop = 65 + $i * 45
    $g.DrawLine($penBorder, 30, $yTop, 390, $yTop)
    $fRow = if ($i -eq 3) { $fontHdr } else { $fontCell }
    $g.DrawString($tableData[$i][0], $fRow, $brushT, (New-Object System.Drawing.RectangleF(30, $yTop, 110, 45)), $sf)
    $g.DrawString($tableData[$i][1], $fRow, $brushT, (New-Object System.Drawing.RectangleF(140, $yTop, 85, 45)), $sf)
    $g.DrawString($tableData[$i][2], $fRow, $brushT, (New-Object System.Drawing.RectangleF(225, $yTop, 85, 45)), $sf)
    $g.DrawString($tableData[$i][3], $fRow, $brushT, (New-Object System.Drawing.RectangleF(310, $yTop, 80, 45)), $sf)
}

$g.Dispose()
Save-Bitmap $bmp "M2_Q7_6aa59bd3ec7ba02921a444df.png"


# -------------------------------------------------------------
# 9. M2_Q9: Right triangle JKL, hypotenuse JL = 90
# -------------------------------------------------------------
$w = 420; $h = 360
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$penTri = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(35, 45, 55), 2.5)
$brushT = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 40, 50))
$fontV = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Italic)
$fontVal = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)

$ptsTri = @(
    (New-Object System.Drawing.PointF(70, 280)),  # L
    (New-Object System.Drawing.PointF(350, 280)), # K
    (New-Object System.Drawing.PointF(350, 60))   # J
)
$g.DrawPolygon($penTri, $ptsTri)

# Right angle at K (350, 280)
$g.DrawRectangle($penTri, 330, 260, 20, 20)

# Labels
$g.DrawString("L", $fontV, $brushT, 50, 275)
$g.DrawString("K", $fontV, $brushT, 355, 280)
$g.DrawString("J", $fontV, $brushT, 355, 45)

# Hypotenuse 90
$g.DrawString("90", $fontVal, $brushT, 190, 140)

$fontNote = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
$g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushT, (New-Object System.Drawing.RectangleF(0, 325, 420, 25)), $sfCenter)

$g.Dispose()
Save-Bitmap $bmp "M2_Q9_6aa59cadec7ba02921a444e7.png"


# -------------------------------------------------------------
# 10. M2_Q16: Line y = f(x) + 11
# -------------------------------------------------------------
$w = 460; $h = 440
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$ox = 210; $oy = 370
$scaleX = 35.0
$scaleY = 32.0

$penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 226, 232), 1)
$penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 50, 60), 2)
$fontTick = New-Object System.Drawing.Font("Segoe UI", 9)
$brushT = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(40, 50, 60))

for ($i = -5; $i -le 6; $i++) {
    $px = $ox + $i * $scaleX
    $g.DrawLine($penGrid, [float]$px, 20.0, [float]$px, 400.0)
    if ($i -ne 0 -and $i % 2 -eq 0) {
        $g.DrawString("$i", $fontTick, $brushT, [float]($px - 8), [float]($oy + 4))
    }
}
for ($j = 0; $j -le 11; $j++) {
    $py = $oy - $j * $scaleY
    $g.DrawLine($penGrid, 20.0, [float]$py, 430.0, [float]$py)
    if ($j -ne 0 -and $j % 2 -eq 0) {
        $g.DrawString("$j", $fontTick, $brushT, [float]($ox - 22), [float]($py - 7))
    }
}
$g.DrawString("O", $fontTick, $brushT, [float]($ox - 15), [float]($oy + 3))
$g.DrawString("x", (New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Italic)), $brushT, 435.0, [float]($oy - 8))
$g.DrawString("y", (New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Italic)), $brushT, [float]($ox - 7), 5.0)

# Axes
$g.DrawLine($penAxis, 15.0, [float]$oy, 435.0, [float]$oy)
$g.DrawLine($penAxis, [float]$ox, 405.0, [float]$ox, 15.0)

# Line with negative slope: passes through (0, 1.5) and (-4, 9.5) -> slope = -2
$penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 80, 180), 2.5)
$lx1 = -5.0; $ly1 = -2.0 * (-5.0) + 1.5 # 11.5
$lx2 = 1.0; $ly2 = -2.0 * 1.0 + 1.5   # -0.5
$g.DrawLine($penLine, [float]($ox + $lx1 * $scaleX), [float]($oy - $ly1 * $scaleY), [float]($ox + $lx2 * $scaleX), [float]($oy - $ly2 * $scaleY))

$g.Dispose()
Save-Bitmap $bmp "M2_Q16_6aa5aeb1ec7ba02921a44518.png"


# -------------------------------------------------------------
# 11. M2_Q22: Inscribed right triangle ABC in circle
# -------------------------------------------------------------
$w = 460; $h = 460
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::White)

$penCircle = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 50, 60), 2.2)
$penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 40, 50), 2.0)
$fontV = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Italic)
$brushT = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 40, 50))

# Circle center (230, 220), radius 180
$cx = 230.0; $cy = 220.0; $r = 180.0
$g.DrawEllipse($penCircle, [float]($cx - $r), [float]($cy - $r), [float]($r * 2), [float]($r * 2))

# Triangle ABC: AC is diameter roughly horizontal (angle 10 deg)
# A at left, C at right
$ax = 55.0; $ay = 240.0
$cx_pt = 405.0; $cy_pt = 180.0
# B on circle above: angle ~ 125 deg
$bx = 100.0; $by = 85.0
# E on circle below: chord BE perpendicular to AC
$ex = 145.0; $ey = 385.0

# D is intersection of AC and BE
$dx = 115.0; $dy = 227.0

# Draw triangle ABC
$g.DrawLine($penLine, [float]$ax, [float]$ay, [float]$bx, [float]$by) # AB
$g.DrawLine($penLine, [float]$bx, [float]$by, [float]$cx_pt, [float]$cy_pt) # BC
$g.DrawLine($penLine, [float]$ax, [float]$ay, [float]$cx_pt, [float]$cy_pt) # AC

# Draw chord BE
$g.DrawLine($penLine, [float]$bx, [float]$by, [float]$ex, [float]$ey)

# Right angle at B
$penRt = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(60, 70, 80), 1.5)
$g.DrawRectangle($penRt, [float]($bx + 2), [float]($by + 10), 12.0, 12.0)

# Right angle at D
$g.DrawRectangle($penRt, [float]($dx + 3), [float]($dy + 4), 12.0, 12.0)

# Labels
$g.DrawString("A", $fontV, $brushT, [float]($ax - 22), [float]($ay - 10))
$g.DrawString("B", $fontV, $brushT, [float]($bx - 18), [float]($by - 20))
$g.DrawString("C", $fontV, $brushT, [float]($cx_pt + 8), [float]($cy_pt - 10))
$g.DrawString("D", $fontV, $brushT, [float]($dx + 5), [float]($dy - 20))
$g.DrawString("E", $fontV, $brushT, [float]($ex - 10), [float]($ey + 5))

$fontNote = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
$g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushT, (New-Object System.Drawing.RectangleF(0, 430, 460, 25)), $sfCenter)

$g.Dispose()
Save-Bitmap $bmp "M2_Q22_6aa5b103ec7ba02921a44616.png"

Write-Host "All 11 light mode images generated successfully!"
