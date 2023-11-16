﻿#
# This script just calls the Add-AppDevPackage.ps1 script that lives next to it.
#

param(
    [switch]$Force = $false,
    [switch]$SkipLoggingTelemetry = $false
)

$scriptArgs = ""
if ($Force)
{
    $scriptArgs = '-Force'
}

if ($SkipLoggingTelemetry)
{
    if ($Force)
    {
        $scriptArgs += ' '
    }

    $scriptArgs += '-SkipLoggingTelemetry'
}

try
{
    # Log telemetry data regarding the use of the script if possible.
    # There are three ways that this can be disabled:
    #   1. If the "TelemetryDependencies" folder isn't present.  This can be excluded at build time by setting the MSBuild property AppxLogTelemetryFromSideloadingScript to false
    #   2. If the SkipLoggingTelemetry switch is passed to this script.
    #   3. If Visual Studio telemetry is disabled via the registry.
    $TelemetryAssembliesFolder = (Join-Path $PSScriptRoot "TelemetryDependencies")
    if (!$SkipLoggingTelemetry -And (Test-Path $TelemetryAssembliesFolder))
    {
        $job = Start-Job -FilePath (Join-Path $TelemetryAssembliesFolder "LogSideloadingTelemetry.ps1") -ArgumentList $TelemetryAssembliesFolder, "VS/DesignTools/SideLoadingScript/Install", $null, $null
        Wait-Job -Job $job -Timeout 60 | Out-Null
    }
}
catch
{
    # Ignore telemetry errors
}

$currLocation = Get-Location
Set-Location $PSScriptRoot
Invoke-Expression ".\Add-AppDevPackage.ps1 $scriptArgs"
Set-Location $currLocation
# SIG # Begin signature block
# MIImHgYJKoZIhvcNAQcCoIImDzCCJgsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC7kxV/l3biwCGH
# VuAKUAkPVeCZ2LSQIMJf+ROzV3B37KCCC2cwggTvMIID16ADAgECAhMzAAAFACfW
# Mm9Dc3uHAAAAAAUAMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTAwHhcNMjMwMjE2MjAxMTExWhcNMjQwMTMxMjAxMTExWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDFkbktTPAJwujWqeAF9Ei9qjEcHHhgDOcCGXKPZFsect6P72/fGD6iv9vq96xQ
# LkSI0PhfXnBwBGLUltZwi5PJaA7IFyaQPjLb5TB9EG0R78McIuMgyRweI3jDce54
# WPOaJCFdfi3hBvH/AoW7tQH0Ua+2QycxbHZgg8/EplcBaLWM/PrXIT3N0ZmDbSCW
# x/mZu/zJEDTS7Z37Sc5avkBdObK4H1XVNLh74iop34yBziFNXhQ8fR2usy6B2uf3
# jckPogHwykdvh0PibY8Lgq55IltjvV9KlHd6QHxeRJ6M0EZKgIUfcAF0w5XWFJZz
# eOHWB6E5NmdyU5sE6nQuGpGhAgMBAAGjggFuMIIBajAfBgNVHSUEGDAWBgorBgEE
# AYI3PQYBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnQrZdzAcYTWhzLarYgjDOio1KSMw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwODY1KzUwMDIzMTAfBgNVHSMEGDAWgBTm/F97uyIAWORyTrX0
# IXQjMubvrDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5j
# b20vcGtpL2NybC9wcm9kdWN0cy9NaWNDb2RTaWdQQ0FfMjAxMC0wNy0wNi5jcmww
# WgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpL2NlcnRzL01pY0NvZFNpZ1BDQV8yMDEwLTA3LTA2LmNydDAMBgNV
# HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQDh0kPUjUYtzlPEvMoFNXHo4aX5
# RPpdZ4rbyrU3Ur4LK4hXLXoMinXxgSnSxusJylXdemovg38RlxiZlgYYc0Yc7Ygd
# BWRl9zmeA+rgQ0srfR6F1ztgobrYxtHOjoThiWvBeLmZOjUVtrmvJgGu2ehfFeD2
# rmDz9CgLOkw2eG492vJ0poAFRIRZ8BtpgCDwzZgmuhAp7hKowwRyMk/pEROCtA04
# RLMShlIkT4NJBDE2OVD5TP0/DzNr3I8jEGBVzqb/QAlJf1MMBStHzYxTQ/UeH9PL
# /gr2iyLUER3m48izBli14+xyviBVC7cCKXAAv17c8+QR3NKfL5x5Ajo18YdFMIIG
# cDCCBFigAwIBAgIKYQxSTAAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzA2MjA0MDE3
# WhcNMjUwNzA2MjA1MDE3WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDEw
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6Q5kUHlntcTj/QkATJ6U
# rPdWaOpE2M/FWE+ppXZ8bUW60zmStKQe+fllguQX0o/9RJwI6GWTzixVhL99COMu
# K6hBKxi3oktuSUxrFQfe0dLCiR5xlM21f0u0rwjYzIjWaxeUOpPOJj/s5v40mFfV
# HV1J9rIqLtWFu1k/+JC0K4N0yiuzO0bj8EZJwRdmVMkcvR3EVWJXcvhnuSUgNN5d
# pqWVXqsogM3Vsp7lA7Vj07IUyMHIiiYKWX8H7P8O7YASNUwSpr5SW/Wm2uCLC0h3
# 1oVH1RC5xuiq7otqLQVcYMa0KlucIxxfReMaFB5vN8sZM4BqiU2jamZjeJPVMM+V
# HwIDAQABo4IB4zCCAd8wEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFOb8X3u7
# IgBY5HJOtfQhdCMy5u+sMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjR
# PZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNy
# bDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGd
# BgNVHSAEgZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggr
# BgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQA
# ZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAGnTvV08pe8QWhXi4UNMi
# /AmdrIKX+DT/KiyXlRLl5L/Pv5PI4zSp24G43B4AvtI1b6/lf3mVd+UC1PHr2M1O
# HhthosJaIxrwjKhiUUVnCOM/PB6T+DCFF8g5QKbXDrMhKeWloWmMIpPMdJjnoUdD
# 8lOswA8waX/+0iUgbW9h098H1dlyACxphnY9UdumOUjJN2FtB91TGcun1mHCv+KD
# qw/ga5uV1n0oUbCJSlGkmmzItx9KGg5pqdfcwX7RSXCqtq27ckdjF/qm1qKmhuyo
# EESbY7ayaYkGx0aGehg/6MUdIdV7+QIjLcVBy78dTMgW77Gcf/wiS0mKbhXjpn92
# W9FTeZGFndXS2z1zNfM8rlSyUkdqwKoTldKOEdqZZ14yjPs3hdHcdYWch8ZaV4XC
# v90Nj4ybLeu07s8n07VeafqkFgQBpyRnc89NT7beBVaXevfpUk30dwVPhcbYC/GO
# 7UIJ0Q124yNWeCImNr7KsYxuqh3khdpHM2KPpMmRM19xHkCvmGXJIuhCISWKHC1g
# 2TeJQYkqFg/XYTyUaGBS79ZHmaCAQO4VgXc+nOBTGBpQHTiVmx5mMxMnORd4hzbO
# TsNfsvU9R1O24OXbC2E9KteSLM43Wj5AQjGkHxAIwlacvyRdUQKdannSF9PawZSO
# B3slcUSrBmrm1MbfI5qWdcUxghoNMIIaCQIBATCBlTB+MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBT
# aWduaW5nIFBDQSAyMDEwAhMzAAAFACfWMm9Dc3uHAAAAAAUAMA0GCWCGSAFlAwQC
# AQUAoIGuMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC55sfwy7JnuBF0jRtZGRnr
# FzHJ1nC8iR8tv9OzWMo65TBCBgorBgEEAYI3AgEMMTQwMqAUgBIATQBpAGMAcgBv
# AHMAbwBmAHShGoAYaHR0cDovL3d3dy5taWNyb3NvZnQuY29tMA0GCSqGSIb3DQEB
# AQUABIIBAE+u+GyyPIguEXVLMQexJ+l52U/WaBPZlWl8b0XfbiyIphAPNmjRmiAn
# U3iY4retyOinLpm48g2Sm6SgZgO1iWPl46w164ExtBApcsGqwelcuLFnZtHoOCgP
# mfL2vHiOwG8hRHSU3l6b7ilE2MwjP77C9FRdObXdw98/cfFG525E6H2Yj92xGwM6
# jzL/7iUFOcxbDh9IWRtUC5R20RA5EZ8G2Lo3+Ebcmv05wR+qI6k/jmbU5oYId8VU
# JaTOcx2DwLmMqE1HBGkZ9RR5kaOp2SAxXWwrE42W7gQkyG+kf/cBWsTbVvREUrfU
# Rch5jczgEA+FlOi4tA4j3ASyfrdBNGShgheXMIIXkwYKKwYBBAGCNwMDATGCF4Mw
# ghd/BgkqhkiG9w0BBwKgghdwMIIXbAIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBUgYL
# KoZIhvcNAQkQAQSgggFBBIIBPTCCATkCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgVDGQ/j8y7tsqS5V6TfA94kCV7VqYtKn7tKzaf/n4iMYCBmUocLG4
# 9hgTMjAyMzExMDkxODA4MjAuMTU2WjAEgAIB9KCB0aSBzjCByzELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkEwMDAt
# MDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIR7TCCByAwggUIoAMCAQICEzMAAAHQdwiq76MXxt0AAQAAAdAwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjMwNTI1MTkx
# MjE0WhcNMjQwMjAxMTkxMjE0WjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkEwMDAtMDVFMC1EOTQ3MSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA3zJX59+X7zNFwFEpiOaohtFMT4tuR5EsgYM5N86W
# Dt9dXdThBBc9EKQCtt7NXSRa4weYA/kjMOc+hMMQuAq11PSmkOFjR6h64Vn7aYKN
# zJCXsfX65jvTJXVH41BuerCFumFRemI1/va09SQ3Qgx26OZ2YmrDIoBimsBm9h6g
# +/5I0Ueu0b1Ye0OJ2rQFbuOmX+TC74kdMTeXDRttMcAcILbWmBJOV5VC2gR+Tp18
# 9nlqCMfkowzuwbeQbgAVmPEr5kUHwck9nKaRM047f37NMaeAdXAB1Q8JRsGbr/UX
# 3N53XcYBaygPDFh2yRdPmllFGCAUfBctoLhVR6B3js3uyLG8r0a2sf//N4GKqPHO
# Wf9f7u5Iy3E4IqYsmfFxEbCxBAieaMdQQS2OgI5m4AMw3TZdi3no/qiG3Qa/0lLy
# hAvl8OMYxTDk1FVilnprdpIcJ3VHwTUezc7tc/S9Fr+0wGP7/r+qTYQHqITzAhSX
# PmpOrjA/Eyks1hY8OWgA5Jg/ZhrgvOsr0ipCCODGss6FHbHk9J35PGNHz47XcNlp
# 3o5esyx7mF8HA2rtjtQzLqInnTVY0xd+1BJmE/qMQvzhV1BjwxELfbc4G0fYPBy7
# VHxHljrDhA+cYG+a8Mn7yLLOx/3HRxXCIiHM80IGJ7C8hBnqaGQ5CoUjEeXggein
# L/0CAwEAAaOCAUkwggFFMB0GA1UdDgQWBBQz4QGFktKAPpTrSE34ybcpdJJ0UTAf
# BgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQ
# hk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBe
# MFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Nl
# cnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQE
# AwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAl4fnJApGWgNOkjVvqsbUvYB0KeMexvoH
# YpJ4CiLRK/KLZFyK5lj2K2q0VgZWPdZahoopR8iJWd4jQVG2jRJmigBjGeWHEuyG
# VCj2qtY1NJrMpfvKINLfQv2duvmrcd77IR6xULkoMEx2Vac7+5PAmJwWKMXYSNbh
# oah+feZqi77TLMRDf9bKO1Pm91Oiwq8ubsMHM+fo/Do9BlF92/omYPgLNMUzek9E
# GvATXnPy8HMqmDRGjJFtlQCq5ob1h/Dgg03F4DjZ5wAUBwX1yv3ywGxxRktVzTra
# +tv4mhwRgJKwhpegYvD38LOn7PsPrBPa94V/VYNILETKB0bjGol7KxphrLmJy59w
# ME4LjGrcPUfFObybVkpbtQhTuT9CxL0EIjGddrEErEAJDQ07Pa041TY4yFIKGelz
# zMZXDyA3I8cPG33m+MuMAMTNkUaFnMaZMfuiCH9i/m+4Cx7QcVwlieWzFu1sFAti
# 5bW7q1MAb9EoI6Q7WxKsP7g4FgXqwk/mbctzXPeu4hmkI8mEB+h/4fV3PLJptp+l
# Y8kkcdrMJ1t4a+kMet1P8WPRy+hTYaxohRA+2USq58L717zFUFCBJAexlBHjeoXm
# PIBy7dIy1d8sw4kAPEfKeWBoBgFbfTBMIACTWNYh7x//L84SUmRTZB/LL0c7Tv4t
# 07yq42/GccIwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqG
# SIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
# MjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4X
# YDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTz
# xXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7
# uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlw
# aQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedG
# bsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXN
# xF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03
# dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9
# ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5
# UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReT
# wDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZ
# MBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8
# RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAE
# VTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAww
# CgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQD
# AgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb
# 186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29t
# L3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoG
# CCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9
# MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2Lpyp
# glYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OO
# PcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8
# DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA
# 0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1Rt
# nWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjc
# ZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq7
# 7EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJ
# C4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328
# y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYID
# UDCCAjgCAQEwgfmhgdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBMDAwLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# vLfIU/CilF/dZVORakT/Qn7vTImggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQsFAAIFAOj3LqEwIhgPMjAyMzExMDkxMDEw
# NDFaGA8yMDIzMTExMDEwMTA0MVowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA6Pcu
# oQIBADAKAgEAAgIB5wIB/zAHAgEAAgITSjAKAgUA6PiAIQIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBCwUAA4IBAQCXVT29b5/ayOwRIBmgtFGLja1lqpXtU2GEzke3m94x
# wjDr3px/OxrBOdgjwsjPg4e981Du7fFxim1k7r5v3qw2ajGQhEhBiRpOMKWEZtbO
# qZmUKWecN6KCaNAC0mHHWyjCzkccyqJn9XhEBP51D4sjNf2LEEp25cLHHpdebSPu
# UjgWzTlw42rd0TjuqS6jpM4TKMaIVjna+jGYLnjmvc6HJvh4P7XAg9mqzNunZytO
# GdbjT5vuUFZETKDtyMNJY/xpXQF/MmNYzYQNi7sdhGGGfMg9WkIWbsL67HzyyIXi
# nPwWLgf/RjmmpEafgGm9IuZc0hC68tWRlfxbwEfyJlhYMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHQdwiq76MXxt0AAQAA
# AdAwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgse55bpym+PNjtJu8II9AXvHBEzG07ihsoOLZD3rY
# PpYwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAIlUAGX7TT/zHdRNmMPnwV
# 2vcOn45k2eVgHq600j8J1zCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAAB0HcIqu+jF8bdAAEAAAHQMCIEIOy0EsGQeepj0/UwP7k/vMsK
# SZUiflQrwoQtoJ1Sp01xMA0GCSqGSIb3DQEBCwUABIICANB3xAh1Ou0+kU5OKstP
# 1klkj66ekY+URHMhMVo4xniG44q5I1KPKBJ9xssaTPWgOKwP95VEVp/8STS4Tu9B
# MPWRL5AxGDscwrpfw6MayUO/5NNQw1nKXQwSZIHnCXzhUQJOPQSix2btpfujqPCa
# p1086ZJClDtUsGF5ZtSCy/mIqHgvRAm+iciUrJr9Icip1GUkst79bUY+h0hg7p1K
# Ni+8zS43i4qf+wt/92bPHf6sEvB3lkMaQkFv1DzRPhVQ6U6y2cU+msbvWSTSvG9a
# doN6AfpFGU0ofbwrSooP7q8qXJCOYnKW9aBC8KoQFF6lDV3EdXH0F9wYXJlB0v5m
# foEGQWyb/ja9ph1tGy/J34qHZGhY12ZQ4BukgOE9GlLeg74AqeYsawMdOvhFfuxA
# zUA7qXbp/ryC4Rcd4wDthrq9OmN3wFOOHgheCGBuSIykcmi10G/bpgYSE8Vhk4oM
# cJ5r46Izq8z6oxbLOOX4qcoZ3r1kdRWGUAnmzqZe8cIjC6EO2bL0pU3Tt1lpAnMu
# Ow+Q8OmVzV5zNc07P4U+RHFeLmNCuhUQzIt2OhSatP78Dq1sykvm3cmugH2aI+cY
# tvItnqPuxwOp+/tbGnxri7SKMNXhC/TCa/p+c9MM6kmhfIym29gmIsLdAPzsj23i
# bzzu6SDA0F+k5aDf7oHl8tis
# SIG # End signature block
