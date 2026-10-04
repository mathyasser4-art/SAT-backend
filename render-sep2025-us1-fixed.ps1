Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "sep2025_us1_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cAxis = [System.Drawing.Color]::FromArgb(51, 65, 85)
$cGrid = [System.Drawing.Color]::FromArgb(203, 213, 225)
$cPoint = [System.Drawing.Color]::FromArgb(15, 23, 42)
$deg = [char]0x00B0

# ==============================================================================
# 1. M1 Q2: Parallel horizontal lines r and s cut by transversal t
# ==============================================================================
function Render-M1Q2 {
    $outPath = Join-Path $imgDir "m1_q2_light.png"
    $w = 460; $h = 380
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.2)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontLabel = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Regular)

    # Horizontal parallel lines r and s
    $leftX = 50.0; $rightX = 400.0
    $ry = 130.0; $sy = 250.0
    $g.DrawLine($penLine, [float]$leftX, [float]$ry, [float]$rightX, [float]$ry)
    $g.DrawLine($penLine, [float]$leftX, [float]$sy, [float]$rightX, [float]$sy)

    # Transversal line t: positive slope from (70, 350) to (390, 40)
    $t1x = 70.0;  $t1y = 350.0
    $t2x = 390.0; $t2y = 40.0
    $g.DrawLine($penLine, [float]$t1x, [float]$t1y, [float]$t2x, [float]$t2y)

    # Intersections:
    # slope dx/dy = (390 - 70) / (40 - 350) = 320 / (-310) = -1.032258
    # ix_r at y = 130 -> x = 70 + (130 - 350) * (-1.032258) = 70 + (-220)*(-1.032258) = 297.1
    $ix_r = 297.1
    # ix_s at y = 250 -> x = 70 + (250 - 350) * (-1.032258) = 70 + (-100)*(-1.032258) = 173.2
    $ix_s = 173.2

    # Labels r, s, t
    $g.DrawString("r", $fontLabel, $brushDark, [float]($rightX + 15), [float]($ry - 10))
    $g.DrawString("s", $fontLabel, $brushDark, [float]($rightX + 15), [float]($sy - 10))
    $g.DrawString("t", $fontLabel, $brushDark, [float]($t2x + 10), [float]($t2y - 12))

    # Angle labels at line r
    $g.DrawString("103$deg", $fontVal, $brushDark, [float]($ix_r - 54), [float]($ry - 26))
    $g.DrawString("77$deg", $fontVal, $brushDark, [float]($ix_r + 16), [float]($ry - 26))

    # Angle labels at line s
    $g.DrawString("a$deg", $fontVal, $brushDark, [float]($ix_s + 18), [float]($sy - 26))
    $g.DrawString("77$deg", $fontVal, $brushDark, [float]($ix_s - 50), [float]($sy + 8))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 2. M1 Q3: Scatterplot with Line of Best Fit (Fur Seal)
# ==============================================================================
function Render-M1Q3 {
    $outPath = Join-Path $imgDir "m1_q3_light.png"
    $w = 560; $h = 480
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.8)
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penLineOfBestFit = New-Object System.Drawing.Pen($cDark, 2.2)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushPoint = New-Object System.Drawing.SolidBrush($cPoint)
    $brushGridText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(71, 85, 105))

    $fontTitle = New-Object System.Drawing.Font("Arial", 11.5, [System.Drawing.FontStyle]::Bold)
    $fontAxisLabel = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Regular)
    $fontNum = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Regular)

    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Coordinate mapping:
    # X: Age 0 to 7 (Domain: 0..7)
    # Y: Body Length 60 to 140 cm (Range: 60..140)
    $originX = 85.0
    $originY = 390.0
    $plotW = 420.0  # 60 px per year
    $plotH = 320.0  # 40 px per 10 cm (from y=60 at 390 to y=140 at 70)

    function Get-X([float]$age) {
        return $originX + ($age / 7.0) * $plotW
    }

    function Get-Y([float]$len) {
        return $originY - (($len - 60.0) / 80.0) * $plotH
    }

    # Vertical grid lines & X-axis numbers (Age 0 to 7)
    for ($a = 0; $a -le 7; $a++) {
        $gx = Get-X $a
        $g.DrawLine($penGrid, [float]$gx, (Get-Y 140), [float]$gx, [float]$originY)
        $g.DrawString($a.ToString(), $fontNum, $brushGridText, [float]$gx, [float]($originY + 6), $sfC)
    }

    # Horizontal grid lines & Y-axis numbers (Body Length 60 to 140 in steps of 10)
    for ($l = 60; $l -le 140; $l += 10) {
        $gy = Get-Y $l
        $g.DrawLine($penGrid, [float]$originX, [float]$gy, (Get-X 7), [float]$gy)
        $g.DrawString($l.ToString(), $fontNum, $brushGridText, [float]($originX - 8), [float]($gy - 7), $sfR)
    }

    # Axes lines
    $g.DrawLine($penAxis, [float]$originX, [float]$originY, (Get-X 7.2), [float]$originY)
    $g.DrawLine($penAxis, [float]$originX, [float]$originY, [float]$originX, (Get-Y 143))

    # Axis Labels
    # X-axis label
    $g.DrawString("Age (years)", $fontAxisLabel, $brushDark, [float]($originX + $plotW / 2), [float]($originY + 34), $sfC)

    # Y-axis label (Rotated)
    $state = $g.Save()
    $g.TranslateTransform(24, [float]($originY - $plotH / 2))
    $g.RotateTransform(-90)
    $g.DrawString("Body length (centimeters)", $fontAxisLabel, $brushDark, 0, 0, $sfC)
    $g.Restore($state)

    # Line of Best Fit:
    # Passes cleanly through (3, 100). Model: y = 12x + 64
    # At x = 0.5: y = 70 -> pixel (Get-X 0.5, Get-Y 70)
    # At x = 6.2: y = 138.4 -> pixel (Get-X 6.2, Get-Y 138.4)
    $lx1 = Get-X 0.5;   $ly1 = Get-Y 70.0
    $lx2 = Get-X 6.25;  $ly2 = Get-Y 139.0
    $g.DrawLine($penLineOfBestFit, [float]$lx1, [float]$ly1, [float]$lx2, [float]$ly2)

    # 5 Data Points (Measurements of 5 individual seals from 1 to 6 years old, excluding age 3)
    $sealPoints = @(
        @(1.0, 74.0),
        @(2.0, 92.0),
        @(4.0, 108.0),
        @(5.0, 126.0),
        @(6.0, 134.0)
    )

    $dotRadius = 4.5
    foreach ($pt in $sealPoints) {
        $px = Get-X $pt[0]
        $py = Get-Y $pt[1]
        $g.FillEllipse($brushPoint, [float]($px - $dotRadius), [float]($py - $dotRadius), [float]($dotRadius * 2), [float]($dotRadius * 2))
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 3. M1 Q13: Right triangle QRS with sides 4, 9, c
# ==============================================================================
function Render-M1Q13 {
    $outPath = Join-Path $imgDir "m1_q13_light.png"
    $w = 440; $h = 400
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penTri = New-Object System.Drawing.Pen($cDark, 2.4)
    $penBox = New-Object System.Drawing.Pen($cDark, 1.5)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontLabel = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 11.5, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Vertices
    # Q at top-left (80, 60)
    # R at bottom-left (80, 310)
    # S at bottom-right (380, 310)
    $qx = 80.0;  $qy = 60.0
    $rx = 80.0;  $ry = 310.0
    $sx = 380.0; $sy = 310.0

    # Draw triangle
    $g.DrawLine($penTri, [float]$qx, [float]$qy, [float]$rx, [float]$ry)
    $g.DrawLine($penTri, [float]$rx, [float]$ry, [float]$sx, [float]$sy)
    $g.DrawLine($penTri, [float]$sx, [float]$sy, [float]$qx, [float]$qy)

    # Right angle marker at R
    $sq = 20.0
    $g.DrawLine($penBox, [float]$rx, [float]($ry - $sq), [float]($rx + $sq), [float]($ry - $sq))
    $g.DrawLine($penBox, [float]($rx + $sq), [float]($ry - $sq), [float]($rx + $sq), [float]$ry)

    # Vertex labels Q, R, S
    $g.DrawString("Q", $fontLabel, $brushDark, [float]($qx - 18), [float]($qy - 24))
    $g.DrawString("R", $fontLabel, $brushDark, [float]($rx - 22), [float]($ry + 4))
    $g.DrawString("S", $fontLabel, $brushDark, [float]($sx + 6), [float]($sy + 4))

    # Side lengths
    # Vertical side 4 (left of QR)
    $g.DrawString("4", $fontVal, $brushDark, [float]($rx - 26), [float](($qy + $ry)/2 - 10))
    # Horizontal side 9 (below RS)
    $g.DrawString("9", $fontVal, $brushDark, [float](($rx + $sx)/2 - 6), [float]($ry + 10))
    # Hypotenuse c (above QS)
    $g.DrawString("c", $fontLabel, $brushDark, [float](($qx + $sx)/2 + 8), [float](($qy + $sy)/2 - 18))

    # Angle y deg at S
    $g.DrawString("y$deg", $fontVal, $brushDark, [float]($sx - 52), [float]($sy - 26))

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushDark, [float]($w / 2), [float]($h - 25), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

Render-M1Q2
Render-M1Q3
Render-M1Q13
