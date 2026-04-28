using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using Ucp;

namespace UcpTest
{
    internal sealed class UcpPerformanceReport
    {
        public string ScenarioName = string.Empty;
        public double ThroughputBytesPerSecond;
        public double RetransmissionRatio;
        public long LastRttMicros;
        public long AverageRttMicros;
        public long P95RttMicros;
        public long P99RttMicros;
        public long JitterMicros;
        public int CongestionWindowBytes;
        public double PacingRateBytesPerSecond;
        public uint RemoteWindowBytes;
        public double BandwidthWastePercent;
        public long DataPacketsSent;
        public long RetransmittedPackets;
        public long ElapsedMilliseconds;
        public double TargetBandwidthBytesPerSecond;
        public double UtilizationPercent;
        public string Note = string.Empty;

        private static readonly object Sync = new object();
        private static readonly List<UcpPerformanceReport> Reports = new List<UcpPerformanceReport>();

        public static UcpPerformanceReport FromConnection(string scenarioName, UcpConnection connection, double throughputBytesPerSecond)
        {
            return FromConnection(scenarioName, connection, throughputBytesPerSecond, 0, 0);
        }

        public static UcpPerformanceReport FromConnection(string scenarioName, UcpConnection connection, double throughputBytesPerSecond, long elapsedMilliseconds, double targetBandwidthBytesPerSecond)
        {
            UcpTransferReport report = connection.GetReport();
            UcpPerformanceReport performance = new UcpPerformanceReport();
            performance.ScenarioName = scenarioName;
            performance.ThroughputBytesPerSecond = throughputBytesPerSecond;
            performance.RetransmissionRatio = report.RetransmissionRatio;
            performance.LastRttMicros = report.LastRttMicros;
            performance.ElapsedMilliseconds = elapsedMilliseconds;
            performance.CongestionWindowBytes = report.CongestionWindowBytes;
            performance.PacingRateBytesPerSecond = report.PacingRateBytesPerSecond;
            performance.RemoteWindowBytes = report.RemoteWindowBytes;
            performance.BandwidthWastePercent = report.DataPacketsSent == 0 ? 0 : report.RetransmittedPackets * 100d / report.DataPacketsSent;
            performance.DataPacketsSent = report.DataPacketsSent;
            performance.RetransmittedPackets = report.RetransmittedPackets;
            performance.TargetBandwidthBytesPerSecond = targetBandwidthBytesPerSecond;
            performance.UtilizationPercent = targetBandwidthBytesPerSecond <= 0 ? 0 : throughputBytesPerSecond * 100d / targetBandwidthBytesPerSecond;
            FillLatencyStatistics(performance, report.RttSamplesMicros);
            performance.Note = BuildNote(performance);
            return performance;
        }

        public static void Append(string filePath, UcpPerformanceReport report)
        {
            lock (Sync)
            {
                Reports.Add(report);
            }

            StringBuilder builder = new StringBuilder();
            builder.AppendLine("Scenario: " + report.ScenarioName);
            builder.AppendLine("Throughput(B/s): " + report.ThroughputBytesPerSecond.ToString("F2"));
            builder.AppendLine("RetransmissionRatio: " + report.RetransmissionRatio.ToString("P2"));
            builder.AppendLine("LastRtt(us): " + report.LastRttMicros);
            builder.AppendLine("AverageRtt(us): " + report.AverageRttMicros);
            builder.AppendLine("P95Rtt(us): " + report.P95RttMicros);
            builder.AppendLine("P99Rtt(us): " + report.P99RttMicros);
            builder.AppendLine("Jitter(us): " + report.JitterMicros);
            builder.AppendLine("CWND(bytes): " + report.CongestionWindowBytes);
            builder.AppendLine("Pacing(bytes/s): " + report.PacingRateBytesPerSecond.ToString("F2"));
            builder.AppendLine("RWND(bytes): " + report.RemoteWindowBytes);
            builder.AppendLine("BandwidthWaste(%): " + report.BandwidthWastePercent.ToString("F2"));
            builder.AppendLine("DataPacketsSent: " + report.DataPacketsSent);
            builder.AppendLine("RetransmittedPackets: " + report.RetransmittedPackets);
            builder.AppendLine("Elapsed(ms): " + report.ElapsedMilliseconds);
            builder.AppendLine();
            File.AppendAllText(filePath, builder.ToString(), Encoding.UTF8);
            WriteSummary(Path.Combine(Path.GetDirectoryName(filePath) ?? AppContext.BaseDirectory, "test_report.txt"));
        }

        public static void WriteSummary(string filePath)
        {
            List<UcpPerformanceReport> snapshot;
            lock (Sync)
            {
                snapshot = new List<UcpPerformanceReport>(Reports);
            }

            StringBuilder builder = new StringBuilder();
            builder.AppendLine("UCP automated test report");
            builder.AppendLine("GeneratedUtc: " + DateTime.UtcNow.ToString("O"));
            AppendTable(builder, snapshot, true);
            File.WriteAllText(filePath, builder.ToString(), Encoding.UTF8);
        }

        public static string BuildConsoleTable()
        {
            List<UcpPerformanceReport> snapshot;
            lock (Sync)
            {
                snapshot = new List<UcpPerformanceReport>(Reports);
            }

            StringBuilder builder = new StringBuilder();
            AppendTable(builder, snapshot, false);
            builder.AppendLine("Notes: Current Pacing is the controller's instantaneous pacing rate; BBR Drain may intentionally report 0.75x target.");
            builder.AppendLine("Notes: Throughput is simulator-observed payload throughput and includes startup/timer granularity; LongFatPipe is validated by pacing, cwnd, retransmission, and payload integrity.");
            return builder.ToString();
        }

        public static string FormatReportFileForConsole(string filePath)
        {
            List<UcpPerformanceReport> parsedReports = ParseReportFile(filePath);
            if (parsedReports.Count == 0)
            {
                return "Report file was not generated or did not contain scenario records.";
            }

            StringBuilder builder = new StringBuilder();
            AppendTable(builder, parsedReports, false);
            builder.AppendLine("Notes: Current Pacing is the controller's instantaneous pacing rate; BBR Drain may intentionally report 0.75x target.");
            builder.AppendLine("Notes: Throughput is simulator-observed payload throughput and includes startup/timer granularity; LongFatPipe is validated by pacing, cwnd, retransmission, and payload integrity.");
            return builder.ToString();
        }

        public static bool ValidateReportFile(string filePath, out string errorMessage)
        {
            List<UcpPerformanceReport> parsedReports = ParseReportFile(filePath);
            if (parsedReports.Count == 0)
            {
                errorMessage = "Report file does not contain any scenario rows.";
                return false;
            }

            bool hasNoLoss = false;
            bool hasLossy = false;
            bool hasHighLoss = false;
            bool hasLongFatPipe = false;
            bool hasPacing = false;
            for (int i = 0; i < parsedReports.Count; i++)
            {
                UcpPerformanceReport report = parsedReports[i];
                if (report.ThroughputBytesPerSecond <= 0)
                {
                    errorMessage = "Scenario " + report.ScenarioName + " has non-positive throughput.";
                    return false;
                }

                if (report.RetransmissionRatio < 0 || report.RetransmissionRatio > 1)
                {
                    errorMessage = "Scenario " + report.ScenarioName + " has invalid retransmission ratio.";
                    return false;
                }

                if (report.ScenarioName == "NoLoss")
                {
                    hasNoLoss = true;
                    if (report.RetransmissionRatio > 0.01d)
                    {
                        errorMessage = "NoLoss retransmission ratio is too high.";
                        return false;
                    }
                }
                else if (report.ScenarioName == "Lossy")
                {
                    hasLossy = true;
                    if (report.RetransmissionRatio <= 0 || report.RetransmissionRatio >= 0.45d)
                    {
                        errorMessage = "Lossy retransmission ratio is outside the expected range.";
                        return false;
                    }
                }
                else if (report.ScenarioName == "HighLossHighRtt")
                {
                    hasHighLoss = true;
                    if (report.RetransmissionRatio <= 0 || report.RetransmissionRatio >= 0.45d)
                    {
                        errorMessage = "HighLossHighRtt retransmission ratio is outside the expected range.";
                        return false;
                    }
                }
                else if (report.ScenarioName == "LongFatPipe")
                {
                    hasLongFatPipe = true;
                    if (report.RetransmissionRatio > 0.05d || report.PacingRateBytesPerSecond < report.TargetBandwidthBytesPerSecond * 0.70d)
                    {
                        errorMessage = "LongFatPipe protocol metrics are outside the expected range.";
                        return false;
                    }
                }
                else if (report.ScenarioName == "Pacing")
                {
                    hasPacing = true;
                    if (report.RetransmissionRatio > 0.01d)
                    {
                        errorMessage = "Pacing retransmission ratio is too high.";
                        return false;
                    }
                }
            }

            if (!hasNoLoss || !hasLossy || !hasHighLoss || !hasLongFatPipe || !hasPacing)
            {
                errorMessage = "Report is missing one or more required scenarios.";
                return false;
            }

            errorMessage = string.Empty;
            return true;
        }

        private static void AppendTable(StringBuilder builder, List<UcpPerformanceReport> snapshot, bool includeNotes)
        {
            snapshot.Sort(delegate (UcpPerformanceReport left, UcpPerformanceReport right)
            {
                return GetScenarioOrder(left.ScenarioName).CompareTo(GetScenarioOrder(right.ScenarioName));
            });

            builder.AppendLine("+------------------+----------------+----------------+---------+----------+----------+----------+----------+----------+----------+----------------+----------+----------+");
            builder.AppendLine("| Scenario         | Throughput B/s | Target B/s     | Util%   | Retrans% | Avg RTT  | P95 RTT  | P99 RTT  | Jitter   | CWND     | Current Pacing | RWND     | Waste%   |");
            builder.AppendLine("+------------------+----------------+----------------+---------+----------+----------+----------+----------+----------+----------+----------------+----------+----------+");
            for (int i = 0; i < snapshot.Count; i++)
            {
                UcpPerformanceReport report = snapshot[i];
                builder.AppendLine(string.Format(CultureInfo.InvariantCulture, "| {0,-16} | {1,14:F2} | {2,14:F2} | {3,7:F2} | {4,8:F2} | {5,8} | {6,8} | {7,8} | {8,8} | {9,8} | {10,14:F2} | {11,8} | {12,8:F2} |",
                    Trim(report.ScenarioName, 16),
                    report.ThroughputBytesPerSecond,
                    report.TargetBandwidthBytesPerSecond,
                    report.UtilizationPercent,
                    report.RetransmissionRatio * 100d,
                    report.AverageRttMicros,
                    report.P95RttMicros,
                    report.P99RttMicros,
                    report.JitterMicros,
                    report.CongestionWindowBytes,
                    report.PacingRateBytesPerSecond,
                    report.RemoteWindowBytes,
                    report.BandwidthWastePercent));
            }

            builder.AppendLine("+------------------+----------------+----------------+---------+----------+----------+----------+----------+----------+----------+----------------+----------+----------+");
            if (includeNotes)
            {
                builder.AppendLine("Notes:");
                for (int i = 0; i < snapshot.Count; i++)
                {
                    if (!string.IsNullOrEmpty(snapshot[i].Note))
                    {
                        builder.AppendLine("  " + snapshot[i].ScenarioName + ": " + snapshot[i].Note);
                    }
                }
            }
        }

        private static List<UcpPerformanceReport> ParseReportFile(string filePath)
        {
            List<UcpPerformanceReport> reports = new List<UcpPerformanceReport>();
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                return reports;
            }

            string[] lines = File.ReadAllLines(filePath, Encoding.UTF8);
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].Trim();
                if (!line.StartsWith("| ", StringComparison.Ordinal) || line.StartsWith("| Scenario", StringComparison.Ordinal))
                {
                    continue;
                }

                string[] columns = line.Split('|');
                if (columns.Length < 15)
                {
                    continue;
                }

                UcpPerformanceReport report = new UcpPerformanceReport();
                report.ScenarioName = columns[1].Trim();
                report.ThroughputBytesPerSecond = ParseDouble(columns[2]);
                report.TargetBandwidthBytesPerSecond = ParseDouble(columns[3]);
                report.UtilizationPercent = ParseDouble(columns[4]);
                report.RetransmissionRatio = ParseDouble(columns[5]) / 100d;
                report.AverageRttMicros = ParseLong(columns[6]);
                report.P95RttMicros = ParseLong(columns[7]);
                report.P99RttMicros = ParseLong(columns[8]);
                report.JitterMicros = ParseLong(columns[9]);
                report.CongestionWindowBytes = ParseInt(columns[10]);
                report.PacingRateBytesPerSecond = ParseDouble(columns[11]);
                report.RemoteWindowBytes = ParseUInt(columns[12]);
                report.BandwidthWastePercent = ParseDouble(columns[13]);
                report.Note = BuildNote(report);
                reports.Add(report);
            }

            return reports;
        }

        private static double ParseDouble(string value)
        {
            double parsed;
            if (!double.TryParse(value.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out parsed))
            {
                return 0;
            }

            return parsed;
        }

        private static long ParseLong(string value)
        {
            long parsed;
            if (!long.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed))
            {
                return 0;
            }

            return parsed;
        }

        private static int ParseInt(string value)
        {
            int parsed;
            if (!int.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed))
            {
                return 0;
            }

            return parsed;
        }

        private static uint ParseUInt(string value)
        {
            uint parsed;
            if (!uint.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed))
            {
                return 0;
            }

            return parsed;
        }

        private static void FillLatencyStatistics(UcpPerformanceReport report, IList<long>? samples)
        {
            if (samples == null || samples.Count == 0)
            {
                report.AverageRttMicros = report.LastRttMicros;
                report.P95RttMicros = report.LastRttMicros;
                report.P99RttMicros = report.LastRttMicros;
                report.JitterMicros = 0;
                return;
            }

            List<long> sorted = new List<long>(samples);
            sorted.Sort();
            long total = 0;
            for (int i = 0; i < sorted.Count; i++)
            {
                total += sorted[i];
            }

            report.AverageRttMicros = total / sorted.Count;
            report.P95RttMicros = Percentile(sorted, 95);
            report.P99RttMicros = Percentile(sorted, 99);
            long jitterTotal = 0;
            for (int i = 1; i < samples.Count; i++)
            {
                long diff = samples[i] - samples[i - 1];
                jitterTotal += diff < 0 ? -diff : diff;
            }

            report.JitterMicros = samples.Count <= 1 ? 0 : jitterTotal / (samples.Count - 1);
        }

        private static long Percentile(List<long> sorted, int percentile)
        {
            if (sorted.Count == 0)
            {
                return 0;
            }

            int index = (int)Math.Ceiling((percentile / 100d) * sorted.Count) - 1;
            if (index < 0)
            {
                index = 0;
            }

            if (index >= sorted.Count)
            {
                index = sorted.Count - 1;
            }

            return sorted[index];
        }

        private static string Trim(string value, int length)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= length)
            {
                return value ?? string.Empty;
            }

            return value.Substring(0, length);
        }

        private static int GetScenarioOrder(string scenarioName)
        {
            if (scenarioName == "NoLoss")
            {
                return 10;
            }

            if (scenarioName == "Lossy")
            {
                return 20;
            }

            if (scenarioName == "HighLossHighRtt")
            {
                return 30;
            }

            if (scenarioName == "LongFatPipe")
            {
                return 40;
            }

            if (scenarioName == "Pacing")
            {
                return 50;
            }

            return 1000;
        }

        private static string BuildNote(UcpPerformanceReport report)
        {
            if (report.ScenarioName == "LongFatPipe")
            {
                return "startup-adjusted simulator throughput; protocol pacing/cwnd validated";
            }

            if (report.ScenarioName == "Pacing" || report.ScenarioName == "Lossy")
            {
                return "BBR may be in Drain/ProbeBW, so current pacing can be below target";
            }

            if (report.ScenarioName == "HighLossHighRtt")
            {
                return "loss recovery scenario; utilization is expected below target";
            }

            return string.Empty;
        }
    }
}
