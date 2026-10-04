Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "aug2025_int2_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42) # Slate 900
$cGray = [System.Drawing.Color]::FromArgb(100, 116, 139) # Slate 500

# ==============================================================================
# 1. M1 Q4: Triangle ABC with base AB = 48
# ==============================================================================
function Render-M1Q4 {
    $outPath = Join-Path $imgDir "m1_q4_light.png"
    $w = 380; $h = 280
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $fontLabel = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Italic)

    # Triangle coordinates
    $Ax = 60.0;  $Ay = 205.0
    $Bx = 320.0; $By = 205.0
    $Cx = 190.0; $Cy = 45.0

    # Draw triangle ABC
    $pts = @(
        (New-Object System.Drawing.PointF($Ax, $Ay)),
        (New-Object System.Drawing.PointF($Bx, $By)),
        (New-Object System.Drawing.PointF($Cx, $Cy))
    )
    $g.DrawPolygon($penLine, $pts)

    # Labels
    $g.DrawString("C", $fontLabel, $brushDark, [float]($Cx - 7), [float]($Cy - 24))
    $g.DrawString("A", $fontLabel, $brushDark, [float]($Ax - 22), [float]($Ay - 2))
    $g.DrawString("B", $fontLabel, $brushDark, [float]($Bx + 8), [float]($By - 2))

    # Side label 48 under AB
    $g.DrawString("48", $fontVal, $brushDark, [float](($Ax + $Bx)/2 - 10), [float]($Ay + 8))

    # Note
    $note = "Note: Figure not drawn to scale."
    $noteSize = $g.MeasureString($note, $fontNote)
    $g.DrawString($note, $fontNote, $brushGray, [float](($w - $noteSize.Width)/2), [float]($h - 22))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 2. M1 Q22: Parallel lines q and r cut by transversal line s
# ==============================================================================
function Render-M1Q22 {
    $outPath = Join-Path $imgDir "m1_q22_light.png"
    $w = 400; $h = 300
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $penArc = New-Object System.Drawing.Pen($cDark, 1.4)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $fontLabel = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Italic)

    # Parallel lines q (top) and r (bottom)
    $lx = 40.0; $rx = 340.0
    $qy = 90.0; $ry = 200.0
    $g.DrawLine($penLine, [float]$lx, [float]$qy, [float]$rx, [float]$qy)
    $g.DrawLine($penLine, [float]$lx, [float]$ry, [float]$rx, [float]$ry)

    # Transversal line s: slope ~ 1.1
    $tx1 = 80.0;  $ty1 = 265.0
    $tx2 = 290.0; $ty2 = 35.0
    $g.DrawLine($penLine, [float]$tx1, [float]$ty1, [float]$tx2, [float]$ty2)

    # Intersections:
    # slope m = (ty2 - ty1)/(tx2 - tx1) = -230/210 = -1.095
    # y - ty1 = m(x - tx1) -> x = tx1 + (y - ty1)/m
    $m = ($ty2 - $ty1) / ($tx2 - $tx1)
    $iq_x = $tx1 + ($qy - $ty1) / $m # intersection with q
    $ir_x = $tx1 + ($ry - $ty1) / $m # intersection with r

    # Line labels
    $g.DrawString("q", $fontLabel, $brushDark, [float]($rx + 12), [float]($qy - 10))
    $g.DrawString("r", $fontLabel, $brushDark, [float]($rx + 12), [float]($ry - 10))
    $g.DrawString("s", $fontLabel, $brushDark, [float]($tx2 + 8), [float]($ty2 - 12))

    # Angle 51 deg at q (top-right acute angle)
    # Arc from horizontal ray (right, 0 deg) upward-right towards transversal line
    # Vector of line s is (tx2-tx1, ty2-ty1) = (210, -230), angle is -47.6 deg (or 312.4 deg)
    $g.DrawArc($penArc, [float]($iq_x - 22), [float]($qy - 22), 44.0, 44.0, 312.0, 48.0)
    $g.DrawString("51°", $fontVal, $brushDark, [float]($iq_x + 14), [float]($qy - 26))

    # Angle y deg at r (bottom-right obtuse angle between transversal down-left and horizontal right, or between transversal up-right and horizontal left)
    # From orig image, arc is at bottom-right of bottom intersection (under line r, to the right of line s)
    $g.DrawArc($penArc, [float]($ir_x - 20), [float]($ry - 20), 40.0, 40.0, 0.0, 132.0)
    $g.DrawString("y°", $fontVal, $brushDark, [float]($ir_x + 6), [float]($ry + 10))

    # Note
    $note = "Note: Figure not drawn to scale."
    $noteSize = $g.MeasureString($note, $fontNote)
    $g.DrawString($note, $fontNote, $brushGray, [float](($w - $noteSize.Width)/2), [float]($h - 20))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 3. M2 Q1: Parallel lines r and s cut by transversal line t
# ==============================================================================
function Render-M2Q1 {
    $outPath = Join-Path $imgDir "m2_q1_light.png"
    $w = 340; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $penArc = New-Object System.Drawing.Pen($cDark, 1.4)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $fontLabel = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Italic)

    # Parallel lines r (top) and s (bottom)
    $lx = 30.0; $rx = 275.0
    $ry = 115.0; $sy = 215.0
    $g.DrawLine($penLine, [float]$lx, [float]$ry, [float]$rx, [float]$ry)
    $g.DrawLine($penLine, [float]$lx, [float]$sy, [float]$rx, [float]$sy)

    # Transversal line t: positive slope (from bottom-left to top-right)
    $tx1 = 40.0;  $ty1 = 315.0
    $tx2 = 280.0; $ty2 = 45.0
    $g.DrawLine($penLine, [float]$tx1, [float]$ty1, [float]$tx2, [float]$ty2)

    # Intersections:
    $m = ($ty2 - $ty1) / ($tx2 - $tx1)
    $ir_x = $tx1 + ($ry - $ty1) / $m
    $is_x = $tx1 + ($sy - $ty1) / $m

    # Line labels
    $g.DrawString("r", $fontLabel, $brushDark, [float]($rx + 12), [float]($ry - 10))
    $g.DrawString("s", $fontLabel, $brushDark, [float]($rx + 12), [float]($sy - 10))
    $g.DrawString("t", $fontLabel, $brushDark, [float]($tx2 + 8), [float]($ty2 - 12))

    # Angle x deg at r (top-right acute angle)
    $g.DrawArc($penArc, [float]($ir_x - 22), [float]($ry - 22), 44.0, 44.0, 312.0, 48.0)
    $g.DrawString("x°", $fontVal, $brushDark, [float]($ir_x + 16), [float]($ry - 24))

    # Angle 21 deg at s (top-right acute angle)
    $g.DrawArc($penArc, [float]($is_x - 22), [float]($sy - 22), 44.0, 44.0, 312.0, 48.0)
    $g.DrawString("21°", $fontVal, $brushDark, [float]($is_x + 16), [float]($sy - 24))

    # Note
    $note = "Note: Figure not drawn to scale."
    $noteSize = $g.MeasureString($note, $fontNote)
    $g.DrawString($note, $fontNote, $brushGray, [float](($w - $noteSize.Width)/2), [float]($h - 22))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 4. M2 Q9: Quadrilateral KLMN (kite)
# ==============================================================================
function Render-M2Q9 {
    $outPath = Join-Path $imgDir "m2_q9_light.png"
    $w = 260; $h = 420
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $fontLabel = New-Object System.Drawing.Font("Arial", 13.0, [System.Drawing.FontStyle]::Italic)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Italic)

    # Kite vertices:
    # L at top, N at bottom (further down), K at left, M at right
    $Lx = 130.0; $Ly = 40.0
    $Kx = 55.0;  $Ky = 190.0
    $Mx = 205.0; $My = 190.0
    $Nx = 130.0; $Ny = 370.0

    $pts = @(
        (New-Object System.Drawing.PointF($Lx, $Ly)),
        (New-Object System.Drawing.PointF($Mx, $My)),
        (New-Object System.Drawing.PointF($Nx, $Ny)),
        (New-Object System.Drawing.PointF($Kx, $Ky))
    )
    $g.DrawPolygon($penLine, $pts)

    # Vertex labels
    $g.DrawString("L", $fontLabel, $brushDark, [float]($Lx - 7), [float]($Ly - 26))
    $g.DrawString("K", $fontLabel, $brushDark, [float]($Kx - 24), [float]($Ky - 10))
    $g.DrawString("M", $fontLabel, $brushDark, [float]($Mx + 8), [float]($My - 10))
    $g.DrawString("N", $fontLabel, $brushDark, [float]($Nx - 7), [float]($Ny + 6))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

Render-M1Q4
Render-M1Q22
Render-M2Q1
Render-M2Q9
Write-Host "All August 2025 · INT 2 light images rendered successfully!"
