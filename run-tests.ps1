$ErrorActionPreference = "Stop"

$reportDir = "E:\dd\ucp\Ucp.Tests\bin\Debug\net8.0\reports"
if (Test-Path $reportDir) {
    Remove-Item -Recurse -Force $reportDir
}

Write-Host "[1/2] build"
dotnet build "E:\dd\ucp\Ucp.slnx"

Write-Host "[2/2] test"
dotnet test "E:\dd\ucp\Ucp.slnx" --no-build

Write-Host "[report] formatted summary"
dotnet run --project "E:\dd\ucp\Ucp.Tests\UcpTest.csproj" --no-build -- "E:\dd\ucp\Ucp.Tests\bin\Debug\net8.0\reports\test_report.txt"
