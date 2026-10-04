Add-Type -AssemblyName System.Drawing

$outDir = "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\march2026_us2_images"
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

# Styling Constants
$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)      # Deep slate for text and main lines
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)    # Soft slate grid
$cBlue = [System.Drawing.Color]::FromArgb(37, 99, 235)      # Royal blue for points/curves
$cShade = [System.Drawing.Color]::FromArgb(50, 59, 130, 246) # Soft translucent blue

$fontSerifItalic = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
$fontSerif = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
$fontSans = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
$fontSansBold = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Bold)

# -------------------------------------------------------------
# 1. M1 Q3: Scatterplot d vs t (230-280, 245-525)
# -------------------------------------------------------------
function Create-M1-Q3 {
    param($outFile)
    $w = 540; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 75.0; $right = 490.0; $top = 40.0; $bottom = 370.0
    $pW = $right - $left; $pH = $bottom - $top

    function TX($t) { return $left + (($t - 225.0) / 60.0) * $pW }
    function DY($d) { return $bottom - (($d - 230.0) / 310.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($t = 230; $t -le 280; $t += 10) {
        $x = TX $t
        $g.DrawLine($penGrid, [float]$x, [float]$top, [float]$x, [float]$bottom)
    }
    for ($d = 245; $d -le 525; $d += 35) {
        $y = DY $d
        $g.DrawLine($penGrid, [float]$left, [float]$y, [float]$right, [float]$y)
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float]$left, [float]($bottom + 15), [float]$left, [float]($top - 20)) # Vertical axis
    $g.DrawLine($penAxis, [float]($left - 15), [float]$bottom, [float]($right + 25), [float]$bottom) # Horizontal axis

    # Axis Labels
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $g.DrawString("d", $fontSerifItalic, $brushDark, [float]($left - 8), [float]($top - 38))
    $g.DrawString("t", $fontSerifItalic, $brushDark, [float]($right + 30), [float]($bottom - 10))

    # Ticks & Tick Labels
    for ($t = 230; $t -le 270; $t += 10) {
        $x = TX $t
        $g.DrawLine($penAxis, [float]$x, [float]$bottom, [float]$x, [float]($bottom + 5))
        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = [System.Drawing.StringAlignment]::Center
        $g.DrawString("$t", $fontSans, $brushDark, [float]$x, [float]($bottom + 8), $sf)
    }
    for ($d = 245; $d -le 525; $d += 35) {
        $y = DY $d
        $g.DrawLine($penAxis, [float]$left, [float]$y, [float]($left - 5), [float]$y)
        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = [System.Drawing.StringAlignment]::Far
        $g.DrawString("$d", $fontSans, $brushDark, [float]($left - 8), [float]($y - 8), $sf)
    }

    # Axis breaks near origin
    $penBreak = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 5.0)
    $g.DrawLine($penBreak, [float]($left - 6), [float]($bottom + 5), [float]($left + 6), [float]($bottom + 12))
    $penBreakLine = New-Object System.Drawing.Pen($cDark, 1.5)
    $g.DrawLine($penBreakLine, [float]($left - 5), [float]($bottom + 6), [float]($left + 5), [float]($bottom + 9))
    $g.DrawLine($penBreakLine, [float]($left - 5), [float]($bottom + 10), [float]($left + 5), [float]($bottom + 13))
    $g.DrawString("0", $fontSans, $brushDark, [float]($left - 18), [float]($bottom + 2))

    # Line of Best Fit
    $penLine = New-Object System.Drawing.Pen($cDark, 2.2)
    $x1 = TX 228; $y1 = DY 396
    $x2 = TX 280; $y2 = DY 500
    $g.DrawLine($penLine, [float]$x1, [float]$y1, [float]$x2, [float]$y2)

    # Data Points
    $pts = @(
        @(231, 403), @(235, 425), @(243, 420), @(258, 458), @(262, 450), @(270, 462), @(276, 485)
    )
    $brushPt = New-Object System.Drawing.SolidBrush($cBlue)
    $penPt = New-Object System.Drawing.Pen($cDark, 1.5)
    foreach ($pt in $pts) {
        $px = TX $pt[0]
        $py = DY $pt[1]
        $g.FillEllipse($brushPt, [float]($px - 5), [float]($py - 5), 10.0, 10.0)
        $g.DrawEllipse($penPt, [float]($px - 5), [float]($py - 5), 10.0, 10.0)
    }

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 2. M1 Q10: Scatterplot with line of best fit y = 9.5 - 0.4x
# -------------------------------------------------------------
function Create-M1-Q10 {
    param($outFile)
    $w = 460; $h = 470
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 50.0; $right = 410.0; $top = 40.0; $bottom = 400.0
    $pW = $right - $left; $pH = $bottom - $top

    function X10($x) { return $left + ($x / 14.0) * $pW }
    function Y10($y) { return $bottom - ($y / 15.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($x = 1; $x -le 13; $x++) {
        $gx = X10 $x
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($y = 1; $y -le 15; $y++) {
        $gy = Y10 $y
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float]$left, [float]($bottom + 10), [float]$left, [float]($top - 20))
    $g.DrawLine($penAxis, [float]($left - 10), [float]$bottom, [float]($right + 25), [float]$bottom)

    # Labels
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $g.DrawString("y", $fontSerifItalic, $brushDark, [float]($left - 8), [float]($top - 38))
    $g.DrawString("x", $fontSerifItalic, $brushDark, [float]($right + 30), [float]($bottom - 10))
    $g.DrawString("O", $fontSerifItalic, $brushDark, [float]($left - 20), [float]($bottom + 2))

    for ($x = 2; $x -le 14; $x += 2) {
        $gx = X10 $x
        $g.DrawLine($penAxis, [float]$gx, [float]$bottom, [float]$gx, [float]($bottom + 5))
        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = [System.Drawing.StringAlignment]::Center
        $g.DrawString("$x", $fontSans, $brushDark, [float]$gx, [float]($bottom + 8), $sf)
    }
    for ($y = 2; $y -le 14; $y += 2) {
        $gy = Y10 $y
        $g.DrawLine($penAxis, [float]$left, [float]$gy, [float]($left - 5), [float]$gy)
        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = [System.Drawing.StringAlignment]::Far
        $g.DrawString("$y", $fontSans, $brushDark, [float]($left - 8), [float]($gy - 8), $sf)
    }

    # Line of best fit
    $penLine = New-Object System.Drawing.Pen($cDark, 2.2)
    $lx1 = X10 0; $ly1 = Y10 9.5
    $lx2 = X10 13.5; $ly2 = Y10 4.1
    $g.DrawLine($penLine, [float]$lx1, [float]$ly1, [float]$lx2, [float]$ly2)

    # Data Points
    $pts = @(
        @(1.0, 8.2), @(1.0, 10.2), @(3.0, 7.1), @(3.0, 8.3), @(6.0, 4.1),
        @(6.0, 7.2), @(6.0, 11.2), @(8.5, 5.1), @(10.5, 7.1), @(12.0, 3.3)
    )
    $brushPt = New-Object System.Drawing.SolidBrush($cBlue)
    $penPt = New-Object System.Drawing.Pen($cDark, 1.5)
    foreach ($pt in $pts) {
        $px = X10 $pt[0]
        $py = Y10 $pt[1]
        $g.FillEllipse($brushPt, [float]($px - 5), [float]($py - 5), 10.0, 10.0)
        $g.DrawEllipse($penPt, [float]($px - 5), [float]($py - 5), 10.0, 10.0)
    }

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 3. M1 Q13: Sunspots linear model from (0, 120) to (30, 29)
# -------------------------------------------------------------
function Create-M1-Q13 {
    param($outFile)
    $w = 520; $h = 470
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 135.0; $right = 470.0; $top = 40.0; $bottom = 380.0
    $pW = $right - $left; $pH = $bottom - $top

    function SX($x) { return $left + ($x / 30.0) * $pW }
    function SY($y) { return $bottom - ($y / 130.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($x = 5; $x -le 30; $x += 5) {
        $gx = SX $x
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($y = 20; $y -le 120; $y += 20) {
        $gy = SY $y
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float]$left, [float]($bottom + 10), [float]$left, [float]($top - 20))
    $g.DrawLine($penAxis, [float]($left - 10), [float]$bottom, [float]($right + 25), [float]$bottom)

    # Axis Labels
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $g.DrawString("y", $fontSerifItalic, $brushDark, [float]($left - 8), [float]($top - 38))
    $g.DrawString("x", $fontSerifItalic, $brushDark, [float]($right + 30), [float]($bottom - 10))
    $g.DrawString("0", $fontSans, $brushDark, [float]($left - 18), [float]($bottom + 2))

    # Multiline axis descriptions
    $sfCenter = New-Object System.Drawing.StringFormat
    $sfCenter.Alignment = [System.Drawing.StringAlignment]::Center
    $g.DrawString("Months since December 2013", $fontSerif, $brushDark, [float](($left + $right) / 2.0), [float]($bottom + 35), $sfCenter)

    $sfRight = New-Object System.Drawing.StringFormat
    $sfRight.Alignment = [System.Drawing.StringAlignment]::Far
    $yDesc = "Monthly`nmean`nnumber`nof`nsunspots"
    $g.DrawString($yDesc, $fontSerif, $brushDark, [float]($left - 30), [float](($top + $bottom) / 2.0 - 50), $sfRight)

    for ($x = 5; $x -le 30; $x += 5) {
        $gx = SX $x
        $g.DrawLine($penAxis, [float]$gx, [float]$bottom, [float]$gx, [float]($bottom + 5))
        $g.DrawString("$x", $fontSans, $brushDark, [float]$gx, [float]($bottom + 8), $sfCenter)
    }
    for ($y = 20; $y -le 120; $y += 20) {
        $gy = SY $y
        $g.DrawLine($penAxis, [float]$left, [float]$gy, [float]($left - 5), [float]$gy)
        $g.DrawString("$y", $fontSans, $brushDark, [float]($left - 8), [float]($gy - 8), $sfRight)
    }

    # Line
    $penLine = New-Object System.Drawing.Pen($cBlue, 2.5)
    $lx1 = SX 0; $ly1 = SY 120
    $lx2 = SX 30; $ly2 = SY 29
    $g.DrawLine($penLine, [float]$lx1, [float]$ly1, [float]$lx2, [float]$ly2)

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 4. M1 Q15: Inequality y < 4x + 1
# -------------------------------------------------------------
function Create-M1-Q15 {
    param($outFile)
    $w = 460; $h = 470
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 40.0; $right = 420.0; $top = 40.0; $bottom = 410.0
    $pW = $right - $left; $pH = $bottom - $top

    function X15($x) { return $left + (($x - (-5.0)) / 14.0) * $pW }
    function Y15($y) { return $bottom - (($y - (-2.0)) / 18.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($x = -5; $x -le 9; $x++) {
        $gx = X15 $x
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($y = -2; $y -le 16; $y += 2) {
        $gy = Y15 $y
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Shaded region: y < 4x + 1
    # Boundary: at y = -2, x = -0.75; at y = 16, x = 3.75
    # Shaded polygon: (-0.75, -2) -> (3.75, 16) -> (9, 16) -> (9, -2)
    $polyPts = @(
        (New-Object System.Drawing.PointF((X15 -0.75), (Y15 -2.0))),
        (New-Object System.Drawing.PointF((X15 3.75), (Y15 16.0))),
        (New-Object System.Drawing.PointF((X15 9.0), (Y15 16.0))),
        (New-Object System.Drawing.PointF((X15 9.0), (Y15 -2.0)))
    )
    $brushShade = New-Object System.Drawing.SolidBrush($cShade)
    $g.FillPolygon($brushShade, $polyPts)

    # Dashed Boundary Line
    $penDashed = New-Object System.Drawing.Pen($cDark, 2.5)
    $penDashed.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $g.DrawLine($penDashed, [float](X15 -0.75), [float](Y15 -2.0), [float](X15 3.75), [float](Y15 16.0))

    # Axes
    $ox = X15 0; $oy = Y15 0
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float]$ox, [float]($bottom + 10), [float]$ox, [float]($top - 20))
    $g.DrawLine($penAxis, [float]($left - 10), [float]$oy, [float]($right + 25), [float]$oy)

    # Labels
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $g.DrawString("y", $fontSerifItalic, $brushDark, [float]($ox - 8), [float]($top - 38))
    $g.DrawString("x", $fontSerifItalic, $brushDark, [float]($right + 30), [float]($oy - 10))
    $g.DrawString("O", $fontSerifItalic, $brushDark, [float]($ox - 20), [float]($oy + 2))

    $sfCenter = New-Object System.Drawing.StringFormat; $sfCenter.Alignment = [System.Drawing.StringAlignment]::Center
    $sfRight = New-Object System.Drawing.StringFormat; $sfRight.Alignment = [System.Drawing.StringAlignment]::Far

    for ($x = -4; $x -le 8; $x += 4) {
        if ($x -ne 0) {
            $gx = X15 $x
            $g.DrawLine($penAxis, [float]$gx, [float]$oy, [float]$gx, [float]($oy + 5))
            $g.DrawString("$x", $fontSans, $brushDark, [float]$gx, [float]($oy + 8), $sfCenter)
        }
    }
    for ($y = 4; $y -le 12; $y += 4) {
        $gy = Y15 $y
        $g.DrawLine($penAxis, [float]$ox, [float]$gy, [float]($ox - 5), [float]$gy)
        $g.DrawString("$y", $fontSans, $brushDark, [float]($ox - 8), [float]($gy - 8), $sfRight)
    }

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 5. M1 Q17: Right Triangles ACE and BCD
# -------------------------------------------------------------
function Create-M1-Q17 {
    param($outFile)
    $w = 420; $h = 460
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    # Triangle vertices
    $ax = 70.0; $ay = 390.0
    $ex = 330.0; $ey = 390.0
    $cx = 330.0; $cy = 60.0

    # Intermediate line BD (parallel to AE)
    $dy = 225.0; $dx = 330.0
    # B is on hypotenuse AC
    # t = (dy - cy) / (ay - cy) = (225 - 60) / (390 - 60) = 165 / 330 = 0.5
    $bx = $cx + 0.5 * ($ax - $cx) # 330 + 0.5 * (70 - 330) = 200
    $by = $cy + 0.5 * ($ay - $cy) # 225

    # Draw Triangles
    $penOutline = New-Object System.Drawing.Pen($cDark, 2.4)
    # AC, CE, EA
    $g.DrawLine($penOutline, [float]$ax, [float]$ay, [float]$cx, [float]$cy)
    $g.DrawLine($penOutline, [float]$cx, [float]$cy, [float]$ex, [float]$ey)
    $g.DrawLine($penOutline, [float]$ex, [float]$ey, [float]$ax, [float]$ay)

    # BD
    $g.DrawLine($penOutline, [float]$bx, [float]$by, [float]$dx, [float]$dy)

    # Right angle indicators at E and D
    $penRight = New-Object System.Drawing.Pen($cDark, 1.8)
    $sq = 18.0
    # At E: square inside triangle (up and left)
    $g.DrawLine($penRight, [float]($ex - $sq), [float]$ey, [float]($ex - $sq), [float]($ey - $sq))
    $g.DrawLine($penRight, [float]($ex - $sq), [float]($ey - $sq), [float]$ex, [float]($ey - $sq))

    # At D: square inside triangle BDC (up and left)
    $g.DrawLine($penRight, [float]($dx - $sq), [float]$dy, [float]($dx - $sq), [float]($dy - $sq))
    $g.DrawLine($penRight, [float]($dx - $sq), [float]($dy - $sq), [float]$dx, [float]($dy - $sq))

    # Vertex labels
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $g.DrawString("A", $fontSerifItalic, $brushDark, [float]($ax - 25), [float]($ay - 8))
    $g.DrawString("E", $fontSerifItalic, $brushDark, [float]($ex + 10), [float]($ey - 8))
    $g.DrawString("C", $fontSerifItalic, $brushDark, [float]($cx + 8), [float]($cy - 20))
    $g.DrawString("B", $fontSerifItalic, $brushDark, [float]($bx - 26), [float]($by - 12))
    $g.DrawString("D", $fontSerifItalic, $brushDark, [float]($dx + 10), [float]($dy - 12))

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 6. M1 Q21: Parabola y = 6x^2 + 12x - 3
# -------------------------------------------------------------
function Create-M1-Q21 {
    param($outFile)
    $w = 460; $h = 480
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 40.0; $right = 420.0; $top = 40.0; $bottom = 440.0
    $pW = $right - $left; $pH = $bottom - $top

    function X21($x) { return $left + (($x - (-7.0)) / 12.0) * $pW }
    function Y21($y) { return $bottom - (($y - (-11.0)) / 16.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($x = -6; $x -le 5; $x++) {
        $gx = X21 $x
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($y = -10; $y -le 4; $y++) {
        $gy = Y21 $y
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Axes
    $ox = X21 0; $oy = Y21 0
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float]$ox, [float]($bottom + 10), [float]$ox, [float]($top - 20))
    $g.DrawLine($penAxis, [float]($left - 10), [float]$oy, [float]($right + 25), [float]$oy)

    # Labels
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $g.DrawString("y", $fontSerifItalic, $brushDark, [float]($ox - 8), [float]($top - 38))
    $g.DrawString("x", $fontSerifItalic, $brushDark, [float]($right + 30), [float]($oy - 10))
    $g.DrawString("O", $fontSerifItalic, $brushDark, [float]($ox - 20), [float]($oy + 2))

    $sfCenter = New-Object System.Drawing.StringFormat; $sfCenter.Alignment = [System.Drawing.StringAlignment]::Center
    $sfRight = New-Object System.Drawing.StringFormat; $sfRight.Alignment = [System.Drawing.StringAlignment]::Far

    for ($x = -6; $x -le 4; $x += 2) {
        if ($x -ne 0) {
            $gx = X21 $x
            $g.DrawLine($penAxis, [float]$gx, [float]$oy, [float]$gx, [float]($oy + 5))
            $g.DrawString("$x", $fontSans, $brushDark, [float]$gx, [float]($oy + 8), $sfCenter)
        }
    }
    for ($y = -10; $y -le 4; $y += 2) {
        if ($y -ne 0) {
            $gy = Y21 $y
            $g.DrawLine($penAxis, [float]$ox, [float]$gy, [float]($ox - 5), [float]$gy)
            $g.DrawString("$y", $fontSans, $brushDark, [float]($ox - 8), [float]($gy - 8), $sfRight)
        }
    }

    # Parabola Curve: y = 6x^2 + 12x - 3
    $curvePts = [System.Collections.Generic.List[System.Drawing.PointF]]::new()
    for ($xf = -2.6; $xf -le 0.6; $xf += 0.05) {
        $yf = 6.0 * $xf * $xf + 12.0 * $xf - 3.0
        if ($yf -ge -10.0 -and $yf -le 4.5) {
            $curvePts.Add((New-Object System.Drawing.PointF((X21 $xf), (Y21 $yf))))
        }
    }
    $penCurve = New-Object System.Drawing.Pen($cBlue, 2.5)
    $g.DrawCurve($penCurve, $curvePts.ToArray())

    # Highlighted dots at (-2, -3) and (0, -3)
    $brushPt = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $penPt = New-Object System.Drawing.Pen($cDark, 2.0)
    $dots = @( @(-2.0, -3.0), @(0.0, -3.0) )
    foreach ($d in $dots) {
        $dx = X21 $d[0]
        $dy = Y21 $d[1]
        $g.FillEllipse($brushPt, [float]($dx - 6), [float]($dy - 6), 12.0, 12.0)
        $g.DrawEllipse($penPt, [float]($dx - 6), [float]($dy - 6), 12.0, 12.0)
    }

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 7. M2 Q11: Sunspots linear model from (0, 80) to (30, 9)
# -------------------------------------------------------------
function Create-M2-Q11 {
    param($outFile)
    $w = 520; $h = 470
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 135.0; $right = 470.0; $top = 40.0; $bottom = 380.0
    $pW = $right - $left; $pH = $bottom - $top

    function SX11($x) { return $left + ($x / 30.0) * $pW }
    function SY11($y) { return $bottom - ($y / 130.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($x = 5; $x -le 30; $x += 5) {
        $gx = SX11 $x
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($y = 20; $y -le 120; $y += 20) {
        $gy = SY11 $y
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float]$left, [float]($bottom + 10), [float]$left, [float]($top - 20))
    $g.DrawLine($penAxis, [float]($left - 10), [float]$bottom, [float]($right + 25), [float]$bottom)

    # Axis Labels
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $g.DrawString("y", $fontSerifItalic, $brushDark, [float]($left - 8), [float]($top - 38))
    $g.DrawString("x", $fontSerifItalic, $brushDark, [float]($right + 30), [float]($bottom - 10))
    $g.DrawString("0", $fontSans, $brushDark, [float]($left - 18), [float]($bottom + 2))

    $sfCenter = New-Object System.Drawing.StringFormat; $sfCenter.Alignment = [System.Drawing.StringAlignment]::Center
    $sfRight = New-Object System.Drawing.StringFormat; $sfRight.Alignment = [System.Drawing.StringAlignment]::Far
    $g.DrawString("Months since April 2015", $fontSerif, $brushDark, [float](($left + $right) / 2.0), [float]($bottom + 35), $sfCenter)

    $yDesc = "Monthly`nmean`nnumber`nof`nsunspots"
    $g.DrawString($yDesc, $fontSerif, $brushDark, [float]($left - 30), [float](($top + $bottom) / 2.0 - 50), $sfRight)

    for ($x = 5; $x -le 30; $x += 5) {
        $gx = SX11 $x
        $g.DrawLine($penAxis, [float]$gx, [float]$bottom, [float]$gx, [float]($bottom + 5))
        $g.DrawString("$x", $fontSans, $brushDark, [float]$gx, [float]($bottom + 8), $sfCenter)
    }
    for ($y = 20; $y -le 120; $y += 20) {
        $gy = SY11 $y
        $g.DrawLine($penAxis, [float]$left, [float]$gy, [float]($left - 5), [float]$gy)
        $g.DrawString("$y", $fontSans, $brushDark, [float]($left - 8), [float]($gy - 8), $sfRight)
    }

    # Line
    $penLine = New-Object System.Drawing.Pen($cBlue, 2.5)
    $lx1 = SX11 0; $ly1 = SY11 80
    $lx2 = SX11 30; $ly2 = SY11 9
    $g.DrawLine($penLine, [float]$lx1, [float]$ly1, [float]$lx2, [float]$ly2)

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 8. M2 Q12: Inequality y < 3x + 5
# -------------------------------------------------------------
function Create-M2-Q12 {
    param($outFile)
    $w = 460; $h = 470
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 40.0; $right = 420.0; $top = 40.0; $bottom = 410.0
    $pW = $right - $left; $pH = $bottom - $top

    function X12($x) { return $left + (($x - (-5.0)) / 14.0) * $pW }
    function Y12($y) { return $bottom - (($y - (-1.0)) / 17.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($x = -5; $x -le 9; $x++) {
        $gx = X12 $x
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($y = 0; $y -le 16; $y++) {
        $gy = Y12 $y
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Shaded region: y < 3x + 5
    # Boundary: at y = -1, x = -2; at y = 16, x = 3.667
    $polyPts = @(
        (New-Object System.Drawing.PointF((X12 -2.0), (Y12 -1.0))),
        (New-Object System.Drawing.PointF((X12 3.667), (Y12 16.0))),
        (New-Object System.Drawing.PointF((X12 9.0), (Y12 16.0))),
        (New-Object System.Drawing.PointF((X12 9.0), (Y12 -1.0)))
    )
    $brushShade = New-Object System.Drawing.SolidBrush($cShade)
    $g.FillPolygon($brushShade, $polyPts)

    # Dashed Boundary Line
    $penDashed = New-Object System.Drawing.Pen($cDark, 2.5)
    $penDashed.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $g.DrawLine($penDashed, [float](X12 -2.0), [float](Y12 -1.0), [float](X12 3.667), [float](Y12 16.0))

    # Axes
    $ox = X12 0; $oy = Y12 0
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float]$ox, [float]($bottom + 10), [float]$ox, [float]($top - 20))
    $g.DrawLine($penAxis, [float]($left - 10), [float]$oy, [float]($right + 25), [float]$oy)

    # Labels
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $g.DrawString("y", $fontSerifItalic, $brushDark, [float]($ox - 8), [float]($top - 38))
    $g.DrawString("x", $fontSerifItalic, $brushDark, [float]($right + 30), [float]($oy - 10))
    $g.DrawString("O", $fontSerifItalic, $brushDark, [float]($ox - 20), [float]($oy + 2))

    $sfCenter = New-Object System.Drawing.StringFormat; $sfCenter.Alignment = [System.Drawing.StringAlignment]::Center
    $sfRight = New-Object System.Drawing.StringFormat; $sfRight.Alignment = [System.Drawing.StringAlignment]::Far

    for ($x = -4; $x -le 8; $x += 4) {
        if ($x -ne 0) {
            $gx = X12 $x
            $g.DrawLine($penAxis, [float]$gx, [float]$oy, [float]$gx, [float]($oy + 5))
            $g.DrawString("$x", $fontSans, $brushDark, [float]$gx, [float]($oy + 8), $sfCenter)
        }
    }
    for ($y = 4; $y -le 12; $y += 4) {
        $gy = Y12 $y
        $g.DrawLine($penAxis, [float]$ox, [float]$gy, [float]($ox - 5), [float]$gy)
        $g.DrawString("$y", $fontSans, $brushDark, [float]($ox - 8), [float]($gy - 8), $sfRight)
    }

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 9. M2 Q15: Right Rectangular Pyramid
# -------------------------------------------------------------
function Create-M2-Q15 {
    param($outFile)
    $w = 440; $h = 480
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    # Pyramid Coordinates in 3D projection
    $apex = New-Object System.Drawing.PointF(310.0, 50.0)
    $baseFront = New-Object System.Drawing.PointF(245.0, 380.0)
    $baseLeft = New-Object System.Drawing.PointF(90.0, 215.0)
    $baseBack = New-Object System.Drawing.PointF(190.0, 160.0)
    $baseRight = New-Object System.Drawing.PointF(345.0, 315.0)

    # Center of base
    $baseCenter = New-Object System.Drawing.PointF(
        (($baseFront.X + $baseBack.X) / 2.0),
        (($baseFront.Y + $baseBack.Y) / 2.0)
    )

    $penSolid = New-Object System.Drawing.Pen($cDark, 2.4)
    $penDashed = New-Object System.Drawing.Pen($cDark, 1.8)
    $penDashed.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash

    # Dashed edges (back edges)
    $g.DrawLine($penDashed, $baseLeft, $baseBack)
    $g.DrawLine($penDashed, $baseBack, $baseRight)
    $g.DrawLine($penDashed, $apex, $baseBack)

    # Altitude height h
    $g.DrawLine($penDashed, $apex, $baseCenter)

    # Height right-angle indicator at base center
    $ra1 = New-Object System.Drawing.PointF(($baseCenter.X - 8), ($baseCenter.Y - 5))
    $ra2 = New-Object System.Drawing.PointF(($baseCenter.X - 14), ($baseCenter.Y + 2))
    $ra3 = New-Object System.Drawing.PointF(($baseCenter.X - 6), ($baseCenter.Y + 7))
    $g.DrawLine($penDashed, $baseCenter, $ra1)
    $g.DrawLine($penDashed, $ra1, $ra2)
    $g.DrawLine($penDashed, $ra2, $ra3)

    # Base midlines dashed
    $midLeft = New-Object System.Drawing.PointF((($baseLeft.X + $baseBack.X)/2.0), (($baseLeft.Y + $baseBack.Y)/2.0))
    $midRight = New-Object System.Drawing.PointF((($baseFront.X + $baseRight.X)/2.0), (($baseFront.Y + $baseRight.Y)/2.0))
    $g.DrawLine($penDashed, $midLeft, $baseCenter)
    $g.DrawLine($penDashed, $baseCenter, $midRight)

    # Solid outer edges
    $g.DrawLine($penSolid, $apex, $baseLeft)
    $g.DrawLine($penSolid, $apex, $baseFront)
    $g.DrawLine($penSolid, $apex, $baseRight)
    $g.DrawLine($penSolid, $baseLeft, $baseFront)
    $g.DrawLine($penSolid, $baseFront, $baseRight)

    # Labels
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $g.DrawString("h", $fontSerifItalic, $brushDark, [float]($apex.X - 80), [float](($apex.Y + $baseCenter.Y)/2.0 - 20))
    $g.DrawString("l", $fontSerifItalic, $brushDark, [float](($baseLeft.X + $baseFront.X)/2.0 - 25), [float](($baseLeft.Y + $baseFront.Y)/2.0 + 8))
    $g.DrawString("w", $fontSerifItalic, $brushDark, [float](($baseFront.X + $baseRight.X)/2.0 + 10), [float](($baseFront.Y + $baseRight.Y)/2.0 + 8))

    # Note
    $sfCenter = New-Object System.Drawing.StringFormat; $sfCenter.Alignment = [System.Drawing.StringAlignment]::Center
    $g.DrawString("Note: Figure not drawn to scale.", $fontSerif, $brushDark, [float]($w / 2.0), [float]445.0, $sfCenter)

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# --- Execute All Renderers ---
Write-Host "Generating all 9 light mode images for March 2026 US 2..."
Create-M1-Q3 "$outDir\m1_q3_light.png"
Create-M1-Q10 "$outDir\m1_q10_light.png"
Create-M1-Q13 "$outDir\m1_q13_light.png"
Create-M1-Q15 "$outDir\m1_q15_light.png"
Create-M1-Q17 "$outDir\m1_q17_light.png"
Create-M1-Q21 "$outDir\m1_q21_light.png"
Create-M2-Q11 "$outDir\m2_q11_light.png"
Create-M2-Q12 "$outDir\m2_q12_light.png"
Create-M2-Q15 "$outDir\m2_q15_light.png"
Write-Host "Done rendering all 9 images."
