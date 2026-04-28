$ErrorActionPreference = "Stop"

$libraryProject = ".\Ucp\UcpLibrary.csproj"
$testProject = ".\Ucp.Tests\UcpTest.csproj"
$reportDir = ".\Ucp.Tests\bin\Debug\net8.0\reports"
if (Test-Path $reportDir) {
    Remove-Item -Recurse -Force $reportDir
}

[void][System.IO.Directory]::CreateDirectory($reportDir)

Write-Host "[1/2] build"
dotnet build $libraryProject
dotnet build $testProject --no-dependencies

Write-Host "[2/2] test"
dotnet test $testProject --no-build

Write-Host "[report] formatted summary"
dotnet run --project $testProject --no-build -- ".\Ucp.Tests\bin\Debug\net8.0\reports\test_report.txt"
