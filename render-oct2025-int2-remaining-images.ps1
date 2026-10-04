Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "oct2025_int2_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cLine = [System.Drawing.Color]::FromArgb(37, 99, 235)
$cPoint = [System.Drawing.Color]::FromArgb(30, 41, 59)
$cPointFill = [System.Drawing.Color]::FromArgb(59, 130, 246)

# ==============================================================================
# M1 Q21: Scatterplot
# ==============================================================================
function Render-M1Q21 {
    $outPath = Join-Path $imgDir "m1_q21_light.png"
    $w = 460; $h = 500
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    # Plot area margins
    $xLeft = 65.0; $xRight = 425.0
    $yTop = 60.0; $yBottom = 460.0
    $plotW = $xRight - $xLeft # 360 px for 0..10
    $plotH = $yBottom - $yTop # 400 px for 0..110

    function MapX([double]$val) { return $xLeft + ($val / 10.0) * $plotW }
    function MapY([double]$val) { return $yBottom - ($val / 110.0) * $plotH }

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penBestFit = New-Object System.Drawing.Pen($cLine, 2.6)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushPt = New-Object System.Drawing.SolidBrush($cPoint)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Bold)
    $fontAxis = New-Object System.Drawing.Font("Arial", 11.5, [System.Drawing.FontStyle]::Italic)
    $sfRight = New-Object System.Drawing.StringFormat
    $sfRight.Alignment = [System.Drawing.StringAlignment]::Far
    $sfRight.LineAlignment = [System.Drawing.StringAlignment]::Center
    $sfCenter = New-Object System.Drawing.StringFormat
    $sfCenter.Alignment = [System.Drawing.StringAlignment]::Center

    # Horizontal grid lines (every 10 units from 0 to 110)
    for ($yVal = 0; $yVal -le 110; $yVal += 10) {
        $py = MapY $yVal
        $g.DrawLine($penGrid, [float]$xLeft, [float]$py, [float]$xRight, [float]$py)
        # Label (skip 0 to avoid collision with origin)
        if ($yVal -gt 0) {
            $g.DrawString($yVal.ToString(), $fontLabel, $brushDark, [float]($xLeft - 8), [float]$py, $sfRight)
        }
    }

    # Vertical grid lines (every 1 unit from 0 to 10)
    for ($xVal = 0; $xVal -le 10; $xVal += 1) {
        $px = MapX $xVal
        $g.DrawLine($penGrid, [float]$px, [float]$yTop, [float]$px, [float]$yBottom)
        if ($xVal -gt 0 -and $xVal % 2 -eq 0) {
            $g.DrawString($xVal.ToString(), $fontLabel, $brushDark, [float]$px, [float]($yBottom + 8), $sfCenter)
        }
    }

    # Origin label 'O'
    $g.DrawString("O", $fontAxis, $brushDark, [float]($xLeft - 18), [float]($yBottom + 4))

    # Axes
    $g.DrawLine($penAxis, [float]$xLeft, [float]$yBottom, [float]($xRight + 20), [float]$yBottom)
    $g.DrawLine($penAxis, [float]$xLeft, [float]$yBottom, [float]$xLeft, [float]($yTop - 25))

    # Axis arrows
    $g.DrawLine($penAxis, [float]($xRight + 20), [float]$yBottom, [float]($xRight + 12), [float]($yBottom - 4))
    $g.DrawLine($penAxis, [float]($xRight + 20), [float]$yBottom, [float]($xRight + 12), [float]($yBottom + 4))
    $g.DrawLine($penAxis, [float]$xLeft, [float]($yTop - 25), [float]($xLeft - 4), [float]($yTop - 17))
    $g.DrawLine($penAxis, [float]$xLeft, [float]($yTop - 25), [float]($xLeft + 4), [float]($yTop - 17))

    # Axis labels x and y
    $g.DrawString("x", $fontAxis, $brushDark, [float]($xRight + 24), [float]($yBottom - 10))
    $g.DrawString("y", $fontAxis, $brushDark, [float]($xLeft - 7), [float]($yTop - 48))

    # Line of best fit (0, 81.5) to (10, 96.5)
    $p1x = MapX 0.0; $p1y = MapY 81.5
    $p2x = MapX 10.0; $p2y = MapY 96.5
    $g.DrawLine($penBestFit, [float]$p1x, [float]$p1y, [float]$p2x, [float]$p2y)

    # 9 Scatter points
    $points = @(
        @{ x = 3.5; y = 90.0 }, # above
        @{ x = 5.5; y = 87.0 }, # below
        @{ x = 6.0; y = 93.0 }, # above
        @{ x = 6.5; y = 94.0 }, # above
        @{ x = 7.0; y = 89.0 }, # below
        @{ x = 7.3; y = 90.0 }, # below
        @{ x = 8.5; y = 97.0 }, # above
        @{ x = 9.3; y = 93.0 }, # below
        @{ x = 9.8; y = 99.0 }  # above
    )

    $rPt = 5.0
    $penPtBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 1.5)
    foreach ($pt in $points) {
        $px = MapX $pt.x
        $py = MapY $pt.y
        $g.FillEllipse($brushPt, [float]($px - $rPt), [float]($py - $rPt), [float]($rPt * 2), [float]($rPt * 2))
        $g.DrawEllipse($penPtBorder, [float]($px - $rPt), [float]($py - $rPt), [float]($rPt * 2), [float]($rPt * 2))
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
    Write-Host "Generated $outPath"
}

# ==============================================================================
# M2 Q14: Bald Eagles Count Table
# ==============================================================================
function Render-M2Q14 {
    $outPath = Join-Path $imgDir "m2_q14_light.png"
    $w = 380; $h = 340
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $tableX = 25.0; $tableY = 20.0
    $tableW = 330.0; $rowH = 36.0
    $col1W = 190.0; $col2W = 140.0

    $penBorder = New-Object System.Drawing.Pen($cDark, 1.5)
    $penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(203, 213, 225), 1.0)
    $brushHdrBg = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(248, 250, 252))
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontHdr = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Bold)
    $fontBody = New-Object System.Drawing.Font("Arial", 10.5, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfC.LineAlignment = [System.Drawing.StringAlignment]::Center

    # Header background
    $g.FillRectangle($brushHdrBg, [float]$tableX, [float]$tableY, [float]$tableW, [float]$rowH)

    # Outer border
    $totalH = $rowH * 8
    $g.DrawRectangle($penBorder, [float]$tableX, [float]$tableY, [float]$tableW, [float]$totalH)

    # Vertical column separator
    $g.DrawLine($penBorder, [float]($tableX + $col1W), [float]$tableY, [float]($tableX + $col1W), [float]($tableY + $totalH))

    # Header text
    $rectHdr1 = New-Object System.Drawing.RectangleF($tableX, $tableY, $col1W, $rowH)
    $rectHdr2 = New-Object System.Drawing.RectangleF(($tableX + $col1W), $tableY, $col2W, $rowH)
    $g.DrawString("Number of bald eagles", $fontHdr, $brushDark, $rectHdr1, $sfC)
    $g.DrawString("Number of days", $fontHdr, $brushDark, $rectHdr2, $sfC)
    $g.DrawLine($penBorder, [float]$tableX, [float]($tableY + $rowH), [float]($tableX + $tableW), [float]($tableY + $rowH))

    # Data rows
    $rows = @(
        @("0", "1"),
        @("1", "3"),
        @("2", "4"),
        @("3", "5"),
        @("4", "4"),
        @("5", "3"),
        @("19", "1")
    )

    for ($i = 0; $i -lt $rows.Length; $i++) {
        $curY = $tableY + ($i + 1) * $rowH
        $rectRow1 = New-Object System.Drawing.RectangleF($tableX, $curY, $col1W, $rowH)
        $rectRow2 = New-Object System.Drawing.RectangleF(($tableX + $col1W), $curY, $col2W, $rowH)
        $g.DrawString($rows[$i][0], $fontBody, $brushDark, $rectRow1, $sfC)
        $g.DrawString($rows[$i][1], $fontBody, $brushDark, $rectRow2, $sfC)
        if ($i -lt $rows.Length - 1) {
            $g.DrawLine($penGrid, [float]$tableX, [float]($curY + $rowH), [float]($tableX + $tableW), [float]($curY + $rowH))
        }
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
    Write-Host "Generated $outPath"
}

Render-M1Q21
Render-M2Q14
