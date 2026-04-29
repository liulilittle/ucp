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
        public long AckPacketsSent;
        public long NakPacketsSent;
        public long FastRetransmissions;
        public long TimeoutRetransmissions;
        public long ElapsedMilliseconds;
        public double TargetBandwidthBytesPerSecond;
        public double UtilizationPercent;
        public double EstimatedLossPercent;
        public long ConvergenceMilliseconds;
        public long ForwardDelayMicros;
        public long ReverseDelayMicros;
        public string Note = string.Empty;

        public double ThroughputMbps
        {
            get { return ToMbps(ThroughputBytesPerSecond); }
        }

        public double TargetMbps
        {
            get { return ToMbps(TargetBandwidthBytesPerSecond); }
        }

        public double PacingMbps
        {
            get { return ToMbps(PacingRateBytesPerSecond); }
        }

        public double RetransmissionPercent
        {
            get { return RetransmissionRatio * 100d; }
        }

        public double AverageRttMilliseconds
        {
            get { return ToMilliseconds(AverageRttMicros); }
        }

        public double P95RttMilliseconds
        {
            get { return ToMilliseconds(P95RttMicros); }
        }

        public double P99RttMilliseconds
        {
            get { return ToMilliseconds(P99RttMicros); }
        }

        public double JitterMilliseconds
        {
            get { return ToMilliseconds(JitterMicros); }
        }

        public double ForwardDelayMilliseconds
        {
            get { return ToMilliseconds(ForwardDelayMicros); }
        }

        public double ReverseDelayMilliseconds
        {
            get { return ToMilliseconds(ReverseDelayMicros); }
        }

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
            performance.AckPacketsSent = report.AckPacketsSent;
            performance.NakPacketsSent = report.NakPacketsSent;
            performance.FastRetransmissions = report.FastRetransmissions;
            performance.TimeoutRetransmissions = report.TimeoutRetransmissions;
            performance.TargetBandwidthBytesPerSecond = targetBandwidthBytesPerSecond;
            performance.UtilizationPercent = targetBandwidthBytesPerSecond <= 0 ? 0 : throughputBytesPerSecond * 100d / targetBandwidthBytesPerSecond;
            performance.EstimatedLossPercent = performance.RetransmissionPercent;
            FillLatencyStatistics(performance, report.RttSamplesMicros);
            performance.Note = BuildNote(performance);
            return performance;
        }

        public static UcpPerformanceReport FromConnection(string scenarioName, UcpConnection connection, double throughputBytesPerSecond, long elapsedMilliseconds, double targetBandwidthBytesPerSecond, long forwardDelayMicros, long reverseDelayMicros)
        {
            UcpPerformanceReport performance = FromConnection(scenarioName, connection, throughputBytesPerSecond, elapsedMilliseconds, targetBandwidthBytesPerSecond);
            performance.ForwardDelayMicros = forwardDelayMicros;
            performance.ReverseDelayMicros = reverseDelayMicros;
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
            builder.AppendLine("Throughput(Mbps): " + report.ThroughputMbps.ToString("F2"));
            builder.AppendLine("Target(Mbps): " + report.TargetMbps.ToString("F2"));
            builder.AppendLine("Retransmission(%): " + report.RetransmissionPercent.ToString("F2"));
            builder.AppendLine("LastRtt(ms): " + ToMilliseconds(report.LastRttMicros).ToString("F2"));
            builder.AppendLine("AverageRtt(ms): " + report.AverageRttMilliseconds.ToString("F2"));
            builder.AppendLine("P95Rtt(ms): " + report.P95RttMilliseconds.ToString("F2"));
            builder.AppendLine("P99Rtt(ms): " + report.P99RttMilliseconds.ToString("F2"));
            builder.AppendLine("Jitter(ms): " + report.JitterMilliseconds.ToString("F2"));
            builder.AppendLine("CWND(bytes): " + report.CongestionWindowBytes);
            builder.AppendLine("Pacing(Mbps): " + report.PacingMbps.ToString("F2"));
            builder.AppendLine("RWND(bytes): " + report.RemoteWindowBytes);
            builder.AppendLine("BandwidthWaste(%): " + report.BandwidthWastePercent.ToString("F2"));
            builder.AppendLine("EstimatedLoss(%): " + report.EstimatedLossPercent.ToString("F2"));
            builder.AppendLine("ForwardDelay(ms): " + report.ForwardDelayMilliseconds.ToString("F2"));
            builder.AppendLine("ReverseDelay(ms): " + report.ReverseDelayMilliseconds.ToString("F2"));
            builder.AppendLine("DataPacketsSent: " + report.DataPacketsSent);
            builder.AppendLine("RetransmittedPackets: " + report.RetransmittedPackets);
            builder.AppendLine("AckPacketsSent: " + report.AckPacketsSent);
            builder.AppendLine("NakPacketsSent: " + report.NakPacketsSent);
            builder.AppendLine("FastRetransmissions: " + report.FastRetransmissions);
            builder.AppendLine("TimeoutRetransmissions: " + report.TimeoutRetransmissions);
            builder.AppendLine("Elapsed(ms): " + report.ElapsedMilliseconds);
            builder.AppendLine("Convergence(ms): " + report.ConvergenceMilliseconds);
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
            bool hasGigabitLoss = false;
            bool hasBurstLoss = false;
            bool hasAsymRoute = false;
            bool hasHighJitter = false;
            bool hasWeak4G = false;
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
                else if (report.ScenarioName == "Gigabit_Loss5")
                {
                    hasGigabitLoss = true;
                    if (report.EstimatedLossPercent > UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT)
                    {
                        errorMessage = "Gigabit_Loss5 exceeded the configured loss budget.";
                        return false;
                    }
                }
                else if (report.ScenarioName == "BurstLoss")
                {
                    hasBurstLoss = true;
                    if (report.RetransmissionRatio <= 0 || report.RetransmissionRatio >= 0.45d)
                    {
                        errorMessage = "BurstLoss retransmission ratio is outside the expected range.";
                        return false;
                    }
                }
                else if (report.ScenarioName == "AsymRoute")
                {
                    hasAsymRoute = true;
                    if (report.RetransmissionRatio > UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT / 100d || report.ForwardDelayMicros <= report.ReverseDelayMicros)
                    {
                        errorMessage = "AsymRoute metrics are outside the expected range.";
                        return false;
                    }
                }
                else if (report.ScenarioName == "HighJitter")
                {
                    hasHighJitter = true;
                    if (report.UtilizationPercent <= 40d || report.RetransmissionRatio > UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT / 100d)
                    {
                        errorMessage = "HighJitter metrics are outside the expected range.";
                        return false;
                    }
                }
                else if (report.ScenarioName == "Weak4G")
                {
                    hasWeak4G = true;
                    if (report.UtilizationPercent <= 25d)
                    {
                        errorMessage = "Weak4G metrics are outside the expected range.";
                        return false;
                    }
                }
            }

            if (!hasNoLoss || !hasLossy || !hasHighLoss || !hasLongFatPipe || !hasPacing)
            {
                errorMessage = "Report is missing one or more required scenarios.";
                return false;
            }

            if (!hasGigabitLoss || !hasBurstLoss || !hasAsymRoute)
            {
                errorMessage = "Report is missing one or more production benchmark scenarios.";
                return false;
            }

            if (!hasHighJitter || !hasWeak4G)
            {
                errorMessage = "Report is missing one or more weak-network scenarios.";
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

            builder.AppendLine("+------------------+----------------+----------------+---------+----------+--------+----------+----------+----------+----------+----------+----------+----------+----------------+----------+----------+----------+");
            builder.AppendLine("| Scenario         | Throughput Mbps| Target Mbps    | Util%   | Retrans% | Loss%  | A->B ms  | B->A ms  | Avg ms   | P95 ms   | P99 ms   | Jit ms   | CWND KB  | Current Mbps   | RWND KB  | Waste%   | Conv ms  |");
            builder.AppendLine("+------------------+----------------+----------------+---------+----------+--------+----------+----------+----------+----------+----------+----------+----------+----------------+----------+----------+----------+");
            for (int i = 0; i < snapshot.Count; i++)
            {
                UcpPerformanceReport report = snapshot[i];
                builder.AppendLine(string.Format(CultureInfo.InvariantCulture, "| {0,-16} | {1,14:F2} | {2,14:F2} | {3,7:F2} | {4,8:F2} | {5,6:F2} | {6,8:F2} | {7,8:F2} | {8,8:F2} | {9,8:F2} | {10,8:F2} | {11,8:F2} | {12,8:F2} | {13,14:F2} | {14,8:F2} | {15,8:F2} | {16,8} |",
                    Trim(report.ScenarioName, 16),
                    report.ThroughputMbps,
                    report.TargetMbps,
                    report.UtilizationPercent,
                    report.RetransmissionPercent,
                    report.EstimatedLossPercent,
                    report.ForwardDelayMilliseconds,
                    report.ReverseDelayMilliseconds,
                    report.AverageRttMilliseconds,
                    report.P95RttMilliseconds,
                    report.P99RttMilliseconds,
                    report.JitterMilliseconds,
                    report.CongestionWindowBytes / 1024d,
                    report.PacingMbps,
                    report.RemoteWindowBytes / 1024d,
                    report.BandwidthWastePercent,
                    report.ConvergenceMilliseconds));
            }

            builder.AppendLine("+------------------+----------------+----------------+---------+----------+--------+----------+----------+----------+----------+----------+----------+----------+----------------+----------+----------+----------+");
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
                if (columns.Length < 17)
                {
                    continue;
                }

                UcpPerformanceReport report = new UcpPerformanceReport();
                report.ScenarioName = columns[1].Trim();
                report.ThroughputBytesPerSecond = FromMbps(ParseDouble(columns[2]));
                report.TargetBandwidthBytesPerSecond = FromMbps(ParseDouble(columns[3]));
                report.UtilizationPercent = ParseDouble(columns[4]);
                report.RetransmissionRatio = ParseDouble(columns[5]) / 100d;
                report.EstimatedLossPercent = ParseDouble(columns[6]);
                if (columns.Length >= 19)
                {
                    report.ForwardDelayMicros = FromMilliseconds(ParseDouble(columns[7]));
                    report.ReverseDelayMicros = FromMilliseconds(ParseDouble(columns[8]));
                    report.AverageRttMicros = FromMilliseconds(ParseDouble(columns[9]));
                    report.P95RttMicros = FromMilliseconds(ParseDouble(columns[10]));
                    report.P99RttMicros = FromMilliseconds(ParseDouble(columns[11]));
                    report.JitterMicros = FromMilliseconds(ParseDouble(columns[12]));
                    report.CongestionWindowBytes = (int)Math.Round(ParseDouble(columns[13]) * 1024d);
                    report.PacingRateBytesPerSecond = FromMbps(ParseDouble(columns[14]));
                    report.RemoteWindowBytes = (uint)Math.Round(ParseDouble(columns[15]) * 1024d);
                    report.BandwidthWastePercent = ParseDouble(columns[16]);
                    report.ConvergenceMilliseconds = ParseLong(columns[17]);
                }
                else
                {
                    report.AverageRttMicros = FromMilliseconds(ParseDouble(columns[7]));
                    report.P95RttMicros = FromMilliseconds(ParseDouble(columns[8]));
                    report.P99RttMicros = FromMilliseconds(ParseDouble(columns[9]));
                    report.JitterMicros = FromMilliseconds(ParseDouble(columns[10]));
                    report.CongestionWindowBytes = (int)Math.Round(ParseDouble(columns[11]) * 1024d);
                    report.PacingRateBytesPerSecond = FromMbps(ParseDouble(columns[12]));
                    report.RemoteWindowBytes = (uint)Math.Round(ParseDouble(columns[13]) * 1024d);
                    report.BandwidthWastePercent = ParseDouble(columns[14]);
                    report.ConvergenceMilliseconds = ParseLong(columns[15]);
                }
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

        private static double ToMbps(double bytesPerSecond)
        {
            return bytesPerSecond * UcpConstants.BITS_PER_BYTE / UcpConstants.BITS_PER_MEGABIT;
        }

        private static double FromMbps(double megabitsPerSecond)
        {
            return megabitsPerSecond * UcpConstants.BITS_PER_MEGABIT / UcpConstants.BITS_PER_BYTE;
        }

        private static double ToMilliseconds(long micros)
        {
            return micros / (double)UcpConstants.MICROS_PER_MILLI;
        }

        private static long FromMilliseconds(double milliseconds)
        {
            return (long)Math.Round(milliseconds * UcpConstants.MICROS_PER_MILLI);
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

            if (scenarioName == "Benchmark100M")
            {
                return 60;
            }

            if (scenarioName == "Gigabit_Ideal")
            {
                return 70;
            }

            if (scenarioName == "Gigabit_Loss1")
            {
                return 80;
            }

            if (scenarioName == "Gigabit_Loss5")
            {
                return 90;
            }

            if (scenarioName == "LongFat_100M")
            {
                return 100;
            }

            if (scenarioName == "Benchmark10G")
            {
                return 110;
            }

            if (scenarioName == "BurstLoss")
            {
                return 120;
            }

            if (scenarioName == "AsymRoute")
            {
                return 130;
            }

            if (scenarioName == "HighJitter")
            {
                return 140;
            }

            if (scenarioName == "Weak4G")
            {
                return 150;
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

            if (report.ConvergenceMilliseconds > 0)
            {
                return "auto-probe benchmark; convergence is the time until pacing reached the stable target band";
            }

            return string.Empty;
        }
    }
}
