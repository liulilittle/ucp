using System;

namespace UcpTest
{

    internal static class ReportPrinter
    {

        public static int Run(string[] args)
        {

            string reportPath = null != args && args.Length > 0 ? args[0] : UcpTestHelpers.TestReportPath;
            Console.WriteLine("[report] " + reportPath);
            string errorMessage;

            if (!UcpPerformanceReport.ValidateReportFile(reportPath, out errorMessage))
            {
                Console.WriteLine("[report-error] " + errorMessage);
                return 1;
            }

            Console.WriteLine(UcpPerformanceReport.FormatReportFileForConsole(reportPath));
            return 0;
        }
    }
}
