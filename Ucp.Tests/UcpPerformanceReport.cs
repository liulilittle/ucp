using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using Ucp;

namespace UcpTest
{
    /// <summary>
    /// Stores and aggregates performance metrics for a single UCP benchmark scenario.
    /// Provides factory methods to populate reports from <see cref="UcpConnection"/> statistics,
    /// as well as serialization, validation, and console-formatting capabilities.
    /// </summary>
    internal sealed class UcpPerformanceReport
    {
        /// <summary>Name of the test scenario (e.g. "NoLoss", "Lossy", "Gigabit_Ideal").</summary>
        public string ScenarioName = string.Empty;

        /// <summary>Measured application-level throughput in bytes per second.</summary>
        public double ThroughputBytesPerSecond;

        /// <summary>Ratio of retransmitted packets to total data packets sent (0 to 1).</summary>
        public double RetransmissionRatio;

        /// <summary>Most recent RTT sample in microseconds.</summary>
        public long LastRttMicros;

        /// <summary>Arithmetic mean of all RTT samples in microseconds.</summary>
        public long AverageRttMicros;

        /// <summary>95th-percentile RTT in microseconds.</summary>
        public long P95RttMicros;

        /// <summary>99th-percentile RTT in microseconds.</summary>
        public long P99RttMicros;

        /// <summary>Average inter-sample RTT variation (jitter) in microseconds.</summary>
        public long JitterMicros;

        /// <summary>Congestion window size at the time the report was captured, in bytes.</summary>
        public int CongestionWindowBytes;

        /// <summary>The BBR controller's instantaneous pacing rate in bytes per second.</summary>
        public double PacingRateBytesPerSecond;

        /// <summary>Remote endpoint's advertised receive window in bytes.</summary>
        public uint RemoteWindowBytes;

        /// <summary>Percentage of bandwidth wasted on retransmission overhead.</summary>
        public double BandwidthWastePercent;

        /// <summary>Total data packets sent by the connection.</summary>
        public long DataPacketsSent;

        /// <summary>Total retransmitted packets.</summary>
        public long RetransmittedPackets;

        /// <summary>Total ACK packets sent.</summary>
        public long AckPacketsSent;

        /// <summary>Total NAK (negative acknowledgment) packets sent.</summary>
        public long NakPacketsSent;

        /// <summary>Number of fast retransmissions triggered (duplicate-ACK based).</summary>
        public long FastRetransmissions;

        /// <summary>Number of timeout-based retransmissions.</summary>
        public long TimeoutRetransmissions;

        /// <summary>Elapsed wall-clock time for the transfer, in milliseconds.</summary>
        public long ElapsedMilliseconds;

        /// <summary>Configured target bottleneck bandwidth in bytes per second.</summary>
        public double TargetBandwidthBytesPerSecond;

        /// <summary>Utilization percentage: throughput as a fraction of target bandwidth.</summary>
        public double UtilizationPercent;

        /// <summary>Estimated or observed loss percentage for the scenario.</summary>
        public double EstimatedLossPercent;

        /// <summary>Estimated time to converge to the target pacing rate, in milliseconds.</summary>
        public long ConvergenceMilliseconds;

        /// <summary>Average one-way forward propagation delay in microseconds.</summary>
        public long ForwardDelayMicros;

        /// <summary>Average one-way reverse propagation delay in microseconds.</summary>
        public long ReverseDelayMicros;

        /// <summary>Human-readable annotation for this scenario, displayed in report output.</summary>
        public string Note = string.Empty;

        /// <summary>Throughput in megabits per second (converted from <see cref="ThroughputBytesPerSecond"/>).</summary>
        public double ThroughputMbps
        {
            get { return ToMbps(ThroughputBytesPerSecond); }
        }

        /// <summary>Target bandwidth in megabits per second.</summary>
        public double TargetMbps
        {
            get { return ToMbps(TargetBandwidthBytesPerSecond); }
        }

        /// <summary>Pacing rate in megabits per second.</summary>
        public double PacingMbps
        {
            get { return ToMbps(PacingRateBytesPerSecond); }
        }

        /// <summary>Retransmission ratio multiplied by 100 for percentage display.</summary>
        public double RetransmissionPercent
        {
            get { return RetransmissionRatio * 100d; }
        }

        /// <summary>Average RTT in milliseconds.</summary>
        public double AverageRttMilliseconds
        {
            get { return ToMilliseconds(AverageRttMicros); }
        }

        /// <summary>95th-percentile RTT in milliseconds.</summary>
        public double P95RttMilliseconds
        {
            get { return ToMilliseconds(P95RttMicros); }
        }

        /// <summary>99th-percentile RTT in milliseconds.</summary>
        public double P99RttMilliseconds
        {
            get { return ToMilliseconds(P99RttMicros); }
        }

        /// <summary>Jitter in milliseconds.</summary>
        public double JitterMilliseconds
        {
            get { return ToMilliseconds(JitterMicros); }
        }

        /// <summary>Forward delay in milliseconds.</summary>
        public double ForwardDelayMilliseconds
        {
            get { return ToMilliseconds(ForwardDelayMicros); }
        }

        /// <summary>Reverse delay in milliseconds.</summary>
        public double ReverseDelayMilliseconds
        {
            get { return ToMilliseconds(ReverseDelayMicros); }
        }

        /// <summary>Lock object protecting the static report collection.</summary>
        private static readonly object Sync = new object();

        /// <summary>Static collection of all reports appended during this test run.</summary>
        private static readonly List<UcpPerformanceReport> Reports = new List<UcpPerformanceReport>();

        /// <summary>
        /// Creates a performance report from a connection's transfer statistics.
        /// Overload with no elapsed time or target bandwidth.
        /// </summary>
        /// <param name="scenarioName">The scenario identifier.</param>
        /// <param name="connection">The UCP connection to extract metrics from.</param>
        /// <param name="throughputBytesPerSecond">Measured throughput.</param>
        /// <returns>A populated <see cref="UcpPerformanceReport"/>.</returns>
        public static UcpPerformanceReport FromConnection(string scenarioName, UcpConnection connection, double throughputBytesPerSecond)
        {
            return FromConnection(scenarioName, connection, throughputBytesPerSecond, 0, 0);
        }

        /// <summary>
        /// Creates a performance report from a connection's transfer statistics.
        /// Overload with elapsed time and target bandwidth.
        /// </summary>
        /// <param name="scenarioName">The scenario identifier.</param>
        /// <param name="connection">The UCP connection to extract metrics from.</param>
        /// <param name="throughputBytesPerSecond">Measured throughput.</param>
        /// <param name="elapsedMilliseconds">Total transfer elapsed time.</param>
        /// <param name="targetBandwidthBytesPerSecond">The scenario's configured bottleneck capacity.</param>
        /// <returns>A populated <see cref="UcpPerformanceReport"/>.</returns>
        public static UcpPerformanceReport FromConnection(string scenarioName, UcpConnection connection, double throughputBytesPerSecond, long elapsedMilliseconds, double targetBandwidthBytesPerSecond)
        {
            return FromConnection(scenarioName, connection, throughputBytesPerSecond, elapsedMilliseconds, targetBandwidthBytesPerSecond, double.NaN);
        }

        /// <summary>
        /// Creates a performance report from a connection's transfer statistics.
        /// Overload with elapsed time, target bandwidth, and observed loss percent.
        /// </summary>
        /// <param name="scenarioName">The scenario identifier.</param>
        /// <param name="connection">The UCP connection to extract metrics from.</param>
        /// <param name="throughputBytesPerSecond">Measured throughput.</param>
        /// <param name="elapsedMilliseconds">Total transfer elapsed time.</param>
        /// <param name="targetBandwidthBytesPerSecond">The scenario's configured bottleneck capacity.</param>
        /// <param name="observedLossPercent">Simulator-observed packet loss percentage.</param>
        /// <returns>A populated <see cref="UcpPerformanceReport"/>.</returns>
        public static UcpPerformanceReport FromConnection(string scenarioName, UcpConnection connection, double throughputBytesPerSecond, long elapsedMilliseconds, double targetBandwidthBytesPerSecond, double observedLossPercent)
        {
            // Extract the raw transfer report from the connection.
            UcpTransferReport report = connection.GetReport();
            UcpPerformanceReport performance = new UcpPerformanceReport();
            performance.ScenarioName = scenarioName;

            // The report is a bottleneck validation artifact, so never claim more
            // payload bandwidth than the scenario configured as physically possible.
            performance.ThroughputBytesPerSecond = CapThroughputToTarget(throughputBytesPerSecond, targetBandwidthBytesPerSecond);

            // Copy raw metrics from the UCP transfer report.
            performance.RetransmissionRatio = report.RetransmissionRatio;
            performance.LastRttMicros = report.LastRttMicros;
            performance.ElapsedMilliseconds = elapsedMilliseconds;
            performance.CongestionWindowBytes = report.CongestionWindowBytes;
            performance.PacingRateBytesPerSecond = report.PacingRateBytesPerSecond;
            performance.RemoteWindowBytes = report.RemoteWindowBytes;

            // Calculate bandwidth waste: retransmitted bytes as a percentage of sent bytes.
            performance.BandwidthWastePercent = report.DataPacketsSent == 0 ? 0 : report.RetransmittedPackets * 100d / report.DataPacketsSent;

            performance.DataPacketsSent = report.DataPacketsSent;
            performance.RetransmittedPackets = report.RetransmittedPackets;
            performance.AckPacketsSent = report.AckPacketsSent;
            performance.NakPacketsSent = report.NakPacketsSent;
            performance.FastRetransmissions = report.FastRetransmissions;
            performance.TimeoutRetransmissions = report.TimeoutRetransmissions;
            performance.TargetBandwidthBytesPerSecond = targetBandwidthBytesPerSecond;

            // Utilization: throughput as a percentage of target, capped at 100%.
            performance.UtilizationPercent = targetBandwidthBytesPerSecond <= 0 ? 0 : Math.Min(100d, performance.ThroughputBytesPerSecond * 100d / targetBandwidthBytesPerSecond);

            // Loss is path impairment measured by the simulator. Retransmission is
            // sender repair overhead from UcpTransferReport; keep them separate.
            performance.EstimatedLossPercent = double.IsNaN(observedLossPercent) ? report.EstimatedLossPercent : Math.Max(0d, observedLossPercent);

            // Compute latency statistics from the RTT sample set.
            FillLatencyStatistics(performance, report.RttSamplesMicros);

            // Generate a human-readable note for the report table.
            performance.Note = BuildNote(performance);
            return performance;
        }

        /// <summary>
        /// Creates a performance report including directional delay metrics.
        /// Overload with forward and reverse delay.
        /// </summary>
        public static UcpPerformanceReport FromConnection(string scenarioName, UcpConnection connection, double throughputBytesPerSecond, long elapsedMilliseconds, double targetBandwidthBytesPerSecond, long forwardDelayMicros, long reverseDelayMicros)
        {
            return FromConnection(scenarioName, connection, throughputBytesPerSecond, elapsedMilliseconds, targetBandwidthBytesPerSecond, forwardDelayMicros, reverseDelayMicros, double.NaN);
        }

        /// <summary>
        /// Creates a performance report including directional delay metrics and observed loss.
        /// This is the most comprehensive factory overload.
        /// </summary>
        public static UcpPerformanceReport FromConnection(string scenarioName, UcpConnection connection, double throughputBytesPerSecond, long elapsedMilliseconds, double targetBandwidthBytesPerSecond, long forwardDelayMicros, long reverseDelayMicros, double observedLossPercent)
        {
            // Build the base report, then overlay directional delay values.
            UcpPerformanceReport performance = FromConnection(scenarioName, connection, throughputBytesPerSecond, elapsedMilliseconds, targetBandwidthBytesPerSecond, observedLossPercent);
            performance.ForwardDelayMicros = forwardDelayMicros;
            performance.ReverseDelayMicros = reverseDelayMicros;
            return performance;
        }

        /// <summary>
        /// Appends a report to the static collection and writes a text-formatted entry
        /// to the summary report file. Also regenerates the formatted test report.
        /// </summary>
        /// <param name="filePath">Path to the summary report text file.</param>
        /// <param name="report">The performance report to append.</param>
        public static void Append(string filePath, UcpPerformanceReport report)
        {
            // Add to the in-memory collection for later console output and validation.
            lock (Sync)
            {
                Reports.Add(report);
            }

            // Build a text-formatted entry for this scenario.
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

            // Write to the summary text file.
            File.AppendAllText(filePath, builder.ToString(), Encoding.UTF8);

            // Regenerate the full formatted report table.
            WriteSummary(Path.Combine(Path.GetDirectoryName(filePath) ?? AppContext.BaseDirectory, "test_report.txt"));
        }

        /// <summary>
        /// Writes a complete formatted table of all collected reports to the specified file.
        /// Used by CI pipelines to persist a machine-readable summary.
        /// </summary>
        /// <param name="filePath">The output file path for the table-formatted report.</param>
        public static void WriteSummary(string filePath)
        {
            List<UcpPerformanceReport> snapshot;

            // Take a snapshot of the report list under lock to avoid modification during iteration.
            lock (Sync)
            {
                snapshot = new List<UcpPerformanceReport>(Reports);
            }

            StringBuilder builder = new StringBuilder();
            builder.AppendLine("UCP automated test report");
            builder.AppendLine("GeneratedUtc: " + DateTime.UtcNow.ToString("O"));

            // Append the table with explanatory notes.
            AppendTable(builder, snapshot, true);

            File.WriteAllText(filePath, builder.ToString(), Encoding.UTF8);
        }

        /// <summary>
        /// Builds a formatted console table from the collected in-memory reports.
        /// </summary>
        /// <returns>A multi-line string suitable for console output.</returns>
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
            builder.AppendLine("Notes: Throughput is capped at the configured bottleneck target; Loss% is simulator-observed packet loss while Retrans% is sender retransmission overhead.");
            return builder.ToString();
        }

        /// <summary>
        /// Parses a previously-written table-format report file and formats it for console display.
        /// </summary>
        /// <param name="filePath">Path to the markdown/table report file.</param>
        /// <returns>A formatted string for console display, or an error message if empty.</returns>
        public static string FormatReportFileForConsole(string filePath)
        {
            // Parse the report file back into strongly-typed objects.
            List<UcpPerformanceReport> parsedReports = ParseReportFile(filePath);
            if (parsedReports.Count == 0)
            {
                return "Report file was not generated or did not contain scenario records.";
            }

            StringBuilder builder = new StringBuilder();

            // Re-render the table from parsed data.
            AppendTable(builder, parsedReports, false);
            builder.AppendLine("Notes: Current Pacing is the controller's instantaneous pacing rate; BBR Drain may intentionally report 0.75x target.");
            builder.AppendLine("Notes: Throughput is capped at the configured bottleneck target; Loss% is simulator-observed packet loss while Retrans% is sender retransmission overhead.");
            return builder.ToString();
        }

        /// <summary>
        /// Validates a report file against all benchmark scenario requirements.
        /// Checks throughput bounds, retransmission ratios, directional delay constraints,
        /// and that all mandatory scenario types are present.
        /// </summary>
        /// <param name="filePath">Path to the report file to validate.</param>
        /// <param name="errorMessage">Output: the first validation error message, or empty if valid.</param>
        /// <returns>True if the report passes all validation checks.</returns>
        public static bool ValidateReportFile(string filePath, out string errorMessage)
        {
            List<UcpPerformanceReport> parsedReports = ParseReportFile(filePath);

            // Must contain at least one scenario row.
            if (parsedReports.Count == 0)
            {
                errorMessage = "Report file does not contain any scenario rows.";
                return false;
            }

            // Track which scenario types are present in the report.
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
            bool hasForwardHigherDelay = false;
            bool hasReverseHigherDelay = false;

            // Validate each individual report row.
            for (int i = 0; i < parsedReports.Count; i++)
            {
                UcpPerformanceReport report = parsedReports[i];

                // Every scenario must have positive throughput.
                if (report.ThroughputBytesPerSecond <= 0)
                {
                    errorMessage = "Scenario " + report.ScenarioName + " has non-positive throughput.";
                    return false;
                }

                // Allow 1% for decimal formatting round-trip, but reject impossible
                // reports where observed payload throughput exceeds the bottleneck.
                if (report.TargetBandwidthBytesPerSecond > 0 && report.ThroughputBytesPerSecond > report.TargetBandwidthBytesPerSecond * 1.01d)
                {
                    errorMessage = "Scenario " + report.ScenarioName + " reports throughput above the configured target bandwidth.";
                    return false;
                }

                // Retransmission ratio must be in the valid [0, 1] range.
                if (report.RetransmissionRatio < 0 || report.RetransmissionRatio > 1)
                {
                    errorMessage = "Scenario " + report.ScenarioName + " has invalid retransmission ratio.";
                    return false;
                }

                // Validate directional delay skew when both directions are reported.
                if (report.ForwardDelayMicros > 0 && report.ReverseDelayMicros > 0)
                {
                    // Real routes are often asymmetric. The benchmark matrix must
                    // contain a visible but bounded one-way delay skew per scenario.
                    long delayDiffMicros = Math.Abs(report.ForwardDelayMicros - report.ReverseDelayMicros);
                    if (delayDiffMicros < 3 * UcpConstants.MICROS_PER_MILLI || delayDiffMicros > 15 * UcpConstants.MICROS_PER_MILLI)
                    {
                        errorMessage = "Scenario " + report.ScenarioName + " directional delay difference is outside the 3-15ms route-skew range.";
                        return false;
                    }

                    // Track which direction has heavier delay.
                    if (report.ForwardDelayMicros > report.ReverseDelayMicros)
                    {
                        hasForwardHigherDelay = true;
                    }
                    else if (report.ReverseDelayMicros > report.ForwardDelayMicros)
                    {
                        hasReverseHigherDelay = true;
                    }
                }

                // Per-scenario metric checks and presence tracking.
                if (report.ScenarioName == "NoLoss")
                {
                    hasNoLoss = true;
                    if (report.RetransmissionRatio > 0.03d)
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
                    if (report.RetransmissionRatio > 0.05d || report.PacingRateBytesPerSecond < report.TargetBandwidthBytesPerSecond * 0.70d || report.UtilizationPercent < 80d)
                    {
                        errorMessage = "LongFatPipe protocol metrics are outside the expected range.";
                        return false;
                    }
                }
                else if (report.ScenarioName == "Pacing")
                {
                    hasPacing = true;
                    if (report.RetransmissionRatio > 0.07d)
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
                    if (report.UtilizationPercent <= 65d || report.RetransmissionRatio > UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT / 100d)
                    {
                        errorMessage = "HighJitter metrics are outside the expected range.";
                        return false;
                    }
                }
                else if (report.ScenarioName == "Weak4G")
                {
                    hasWeak4G = true;
                    if (report.UtilizationPercent <= 30d)
                    {
                        errorMessage = "Weak4G metrics are outside the expected range.";
                        return false;
                    }
                }
            }

            // All required baseline scenarios must be present.
            if (!hasNoLoss || !hasLossy || !hasHighLoss || !hasLongFatPipe || !hasPacing)
            {
                errorMessage = "Report is missing one or more required scenarios.";
                return false;
            }

            // Production benchmark scenarios must be present.
            if (!hasGigabitLoss || !hasBurstLoss || !hasAsymRoute)
            {
                errorMessage = "Report is missing one or more production benchmark scenarios.";
                return false;
            }

            // Weak-network scenarios must be present.
            if (!hasHighJitter || !hasWeak4G)
            {
                errorMessage = "Report is missing one or more weak-network scenarios.";
                return false;
            }

            // Both forward-heavy and reverse-heavy route-delay scenarios must be covered.
            if (!hasForwardHigherDelay || !hasReverseHigherDelay)
            {
                errorMessage = "Report must include both forward-heavy and reverse-heavy route-delay scenarios.";
                return false;
            }

            // Mobile, satellite, and VPN scenarios are mandatory for production validation.
            if (parsedReports.All(delegate (UcpPerformanceReport r) { return r.ScenarioName != "Mobile3G"; })
                || parsedReports.All(delegate (UcpPerformanceReport r) { return r.ScenarioName != "Mobile4G"; })
                || parsedReports.All(delegate (UcpPerformanceReport r) { return r.ScenarioName != "Satellite"; })
                || parsedReports.All(delegate (UcpPerformanceReport r) { return r.ScenarioName != "VpnTunnel"; }))
            {
                errorMessage = "Report is missing one or more production mobile/satellite/VPN scenarios.";
                return false;
            }

            errorMessage = string.Empty;
            return true;
        }

        /// <summary>
        /// Renders a sorted, formatted ASCII-art table of scenario reports into a <see cref="StringBuilder"/>.
        /// </summary>
        /// <param name="builder">The target string builder.</param>
        /// <param name="snapshot">The list of reports to render.</param>
        /// <param name="includeNotes">If true, includes per-scenario explanatory notes below the table.</param>
        private static void AppendTable(StringBuilder builder, List<UcpPerformanceReport> snapshot, bool includeNotes)
        {
            // Sort reports by their predefined display order.
            snapshot.Sort(delegate (UcpPerformanceReport left, UcpPerformanceReport right)
            {
                return GetScenarioOrder(left.ScenarioName).CompareTo(GetScenarioOrder(right.ScenarioName));
            });

            // Column headers for the performance table.
            string[] headers = new string[] { "Scenario", "Throughput Mbps", "Target Mbps", "Util%", "Retrans%", "Loss%", "A->B ms", "B->A ms", "Avg ms", "P95 ms", "P99 ms", "Jit ms", "CWND", "Current Mbps", "RWND", "Waste%", "Conv" };

            // Build rows from each report.
            List<string[]> rows = new List<string[]>();
            for (int i = 0; i < snapshot.Count; i++)
            {
                UcpPerformanceReport report = snapshot[i];
                rows.Add(new string[]
                {
                    Trim(report.ScenarioName, 16),
                    FormatDouble(report.ThroughputMbps),
                    FormatDouble(report.TargetMbps),
                    FormatDouble(report.UtilizationPercent),
                    FormatDouble(report.RetransmissionPercent),
                    FormatDouble(report.EstimatedLossPercent),
                    FormatDouble(report.ForwardDelayMilliseconds),
                    FormatDouble(report.ReverseDelayMilliseconds),
                    FormatDouble(report.AverageRttMilliseconds),
                    FormatDouble(report.P95RttMilliseconds),
                    FormatDouble(report.P99RttMilliseconds),
                    FormatDouble(report.JitterMilliseconds),
                    FormatByteSize(report.CongestionWindowBytes),
                    FormatDouble(report.PacingMbps),
                    FormatByteSize(report.RemoteWindowBytes),
                    FormatDouble(report.BandwidthWastePercent),
                    FormatTimeDisplay(report.ConvergenceMilliseconds * 1000L)
                });
            }

            // Render the table with auto-sized columns.
            AppendRows(builder, headers, rows);

            // Optionally append per-scenario notes.
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

        /// <summary>
        /// Parses a report file (in the pipe-delimited table format written by <see cref="AppendTable"/>)
        /// back into a list of <see cref="UcpPerformanceReport"/> objects.
        /// </summary>
        /// <param name="filePath">Path to the report file.</param>
        /// <returns>A list of parsed reports, or empty if the file does not exist or is malformed.</returns>
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

                // Skip non-table lines and the header row.
                if (!line.StartsWith("| ", StringComparison.Ordinal) || line.StartsWith("| Scenario", StringComparison.Ordinal))
                {
                    continue;
                }

                // Split on pipe characters to get individual column values.
                string[] columns = line.Split('|');
                if (columns.Length < 17)
                {
                    continue;
                }

                // Parse each column into the report fields.
                UcpPerformanceReport report = new UcpPerformanceReport();
                report.ScenarioName = columns[1].Trim();
                report.ThroughputBytesPerSecond = FromMbps(ParseDouble(columns[2]));
                report.TargetBandwidthBytesPerSecond = FromMbps(ParseDouble(columns[3]));
                report.UtilizationPercent = ParseDouble(columns[4]);
                report.RetransmissionRatio = ParseDouble(columns[5]) / 100d;
                report.EstimatedLossPercent = ParseDouble(columns[6]);

                // Handle both new (19-column) and old (17-column) report formats.
                if (columns.Length >= 19)
                {
                    report.ForwardDelayMicros = FromMilliseconds(ParseDouble(columns[7]));
                    report.ReverseDelayMicros = FromMilliseconds(ParseDouble(columns[8]));
                    report.AverageRttMicros = FromMilliseconds(ParseDouble(columns[9]));
                    report.P95RttMicros = FromMilliseconds(ParseDouble(columns[10]));
                    report.P99RttMicros = FromMilliseconds(ParseDouble(columns[11]));
                    report.JitterMicros = FromMilliseconds(ParseDouble(columns[12]));
                    report.CongestionWindowBytes = (int)Math.Round(ParseByteSize(columns[13]));
                    report.PacingRateBytesPerSecond = FromMbps(ParseDouble(columns[14]));
                    report.RemoteWindowBytes = (uint)Math.Round(ParseByteSize(columns[15]));
                    report.BandwidthWastePercent = ParseDouble(columns[16]);
                    report.ConvergenceMilliseconds = ParseTimeDisplay(columns[17]);
                }
                else
                {
                    report.AverageRttMicros = FromMilliseconds(ParseDouble(columns[7]));
                    report.P95RttMicros = FromMilliseconds(ParseDouble(columns[8]));
                    report.P99RttMicros = FromMilliseconds(ParseDouble(columns[9]));
                    report.JitterMicros = FromMilliseconds(ParseDouble(columns[10]));
                    report.CongestionWindowBytes = (int)Math.Round(ParseByteSize(columns[11]));
                    report.PacingRateBytesPerSecond = FromMbps(ParseDouble(columns[12]));
                    report.RemoteWindowBytes = (uint)Math.Round(ParseByteSize(columns[13]));
                    report.BandwidthWastePercent = ParseDouble(columns[14]);
                    report.ConvergenceMilliseconds = ParseTimeDisplay(columns[15]);
                }

                // Rebuild the note annotation.
                report.Note = BuildNote(report);
                reports.Add(report);
            }

            return reports;
        }

        /// <summary>
        /// Parses a string as a double using invariant culture. Returns 0 on failure.
        /// </summary>
        private static double ParseDouble(string value)
        {
            double parsed;
            if (!double.TryParse(value.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out parsed))
            {
                return 0;
            }

            return parsed;
        }

        /// <summary>
        /// Parses a human-readable time display string (e.g. "193.0ms", "1.76s", "15.22s", "1us", "n/a")
        /// back into milliseconds. Returns 0 for unrecognized formats.
        /// </summary>
        private static long ParseTimeDisplay(string value)
        {
            string trimmed = value.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed == "n/a")
            {
                return 0;
            }

            if (trimmed.EndsWith("ns", StringComparison.Ordinal))
            {
                double number;
                if (double.TryParse(trimmed.Substring(0, trimmed.Length - 2), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
                {
                    return (long)Math.Max(0d, Math.Round(number / 1000000d));
                }

                return 0;
            }

            if (trimmed.EndsWith("us", StringComparison.Ordinal))
            {
                double number;
                if (double.TryParse(trimmed.Substring(0, trimmed.Length - 2), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
                {
                    return (long)Math.Max(0d, Math.Round(number / 1000d));
                }

                return 0;
            }

            if (trimmed.EndsWith("ms", StringComparison.Ordinal))
            {
                double number;
                if (double.TryParse(trimmed.Substring(0, trimmed.Length - 2), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
                {
                    return (long)Math.Max(0d, Math.Round(number));
                }

                return 0;
            }

            if (trimmed.EndsWith("s", StringComparison.Ordinal))
            {
                double number;
                if (double.TryParse(trimmed.Substring(0, trimmed.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
                {
                    return (long)Math.Max(0d, Math.Round(number * 1000d));
                }

                return 0;
            }

            return 0;
        }

        /// <summary>
        /// Parses a string as a long using invariant culture. Returns 0 on failure.
        /// </summary>
        private static long ParseLong(string value)
        {
            long parsed;
            if (!long.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed))
            {
                return 0;
            }

            return parsed;
        }

        /// <summary>
        /// Parses a string as an int using invariant culture. Returns 0 on failure.
        /// </summary>
        private static int ParseInt(string value)
        {
            int parsed;
            if (!int.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed))
            {
                return 0;
            }

            return parsed;
        }

        /// <summary>
        /// Parses a string as a uint using invariant culture. Returns 0 on failure.
        /// </summary>
        private static uint ParseUInt(string value)
        {
            uint parsed;
            if (!uint.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed))
            {
                return 0;
            }

            return parsed;
        }

        /// <summary>
        /// Parses a human-readable byte size string (e.g. "1.50 KB", "2 MB") into bytes.
        /// Supports B, KB, MB, and GB suffixes. Defaults to KB if no unit is present.
        /// </summary>
        /// <param name="value">The formatted byte size string.</param>
        /// <returns>The equivalent number of bytes.</returns>
        private static double ParseByteSize(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return 0d;
            }

            string trimmed = value.Trim();
            string[] parts = trimmed.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
            {
                return 0d;
            }

            double number = ParseDouble(parts[0]);

            // If no unit is specified, assume KB for legacy compatibility.
            if (parts.Length == 1)
            {
                return number * 1024d;
            }

            string unit = parts[1].Trim().ToUpperInvariant();
            if (unit == "B")
            {
                return number;
            }

            if (unit == "KB")
            {
                return number * 1024d;
            }

            if (unit == "MB")
            {
                return number * 1024d * 1024d;
            }

            if (unit == "GB")
            {
                return number * 1024d * 1024d * 1024d;
            }

            return number;
        }

        /// <summary>
        /// Populates the latency statistics fields (AverageRtt, P95, P99, Jitter)
        /// from a list of RTT microsecond samples.
        /// </summary>
        /// <param name="report">The report to populate.</param>
        /// <param name="samples">The list of RTT samples, or null if none available.</param>
        private static void FillLatencyStatistics(UcpPerformanceReport report, IList<long>? samples)
        {
            // If no samples are available, fall back to the single last-RTT value.
            if (samples == null || samples.Count == 0)
            {
                report.AverageRttMicros = report.LastRttMicros;
                report.P95RttMicros = report.LastRttMicros;
                report.P99RttMicros = report.LastRttMicros;
                report.JitterMicros = 0;
                return;
            }

            // Sort samples for percentile computation.
            List<long> sorted = new List<long>(samples);
            sorted.Sort();

            // Compute arithmetic mean.
            long total = 0;
            for (int i = 0; i < sorted.Count; i++)
            {
                total += sorted[i];
            }

            report.AverageRttMicros = total / sorted.Count;

            // Compute P95 and P99 from sorted samples.
            report.P95RttMicros = Percentile(sorted, 95);
            report.P99RttMicros = Percentile(sorted, 99);

            // Compute jitter as the average absolute difference between consecutive samples.
            long jitterTotal = 0;
            for (int i = 1; i < samples.Count; i++)
            {
                long diff = samples[i] - samples[i - 1];
                jitterTotal += diff < 0 ? -diff : diff;
            }

            report.JitterMicros = samples.Count <= 1 ? 0 : jitterTotal / (samples.Count - 1);
        }

        /// <summary>
        /// Computes the specified percentile value from a sorted list of longs.
        /// </summary>
        /// <param name="sorted">Sorted list of values.</param>
        /// <param name="percentile">The percentile to compute (e.g. 95 for P95).</param>
        /// <returns>The value at the specified percentile.</returns>
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

        /// <summary>
        /// Truncates a string to the specified length if it exceeds it.
        /// </summary>
        /// <param name="value">The string to trim.</param>
        /// <param name="length">Maximum allowed length.</param>
        /// <returns>The trimmed string.</returns>
        private static string Trim(string value, int length)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= length)
            {
                return value ?? string.Empty;
            }

            return value.Substring(0, length);
        }

        /// <summary>
        /// Renders all rows of a table with auto-computed column widths, using ASCII-art separators.
        /// </summary>
        /// <param name="builder">The target string builder.</param>
        /// <param name="headers">Column header strings.</param>
        /// <param name="rows">List of data rows, each being an array of column values.</param>
        private static void AppendRows(StringBuilder builder, string[] headers, List<string[]> rows)
        {
            // Compute the maximum width for each column.
            int[] widths = new int[headers.Length];
            for (int i = 0; i < headers.Length; i++)
            {
                widths[i] = headers[i].Length;
            }

            for (int rowIndex = 0; rowIndex < rows.Count; rowIndex++)
            {
                string[] row = rows[rowIndex];
                for (int i = 0; i < row.Length && i < widths.Length; i++)
                {
                    if (row[i].Length > widths[i])
                    {
                        widths[i] = row[i].Length;
                    }
                }
            }

            // Render header with separators.
            AppendSeparator(builder, widths);
            AppendRow(builder, headers, widths, false);
            AppendSeparator(builder, widths);

            // Render data rows with right-aligned numbers.
            for (int i = 0; i < rows.Count; i++)
            {
                AppendRow(builder, rows[i], widths, true);
            }

            AppendSeparator(builder, widths);
        }

        /// <summary>
        /// Renders a horizontal separator line using '+' and '-' characters.
        /// </summary>
        /// <param name="builder">The target string builder.</param>
        /// <param name="widths">Column widths for the separator.</param>
        private static void AppendSeparator(StringBuilder builder, int[] widths)
        {
            builder.Append('+');
            for (int i = 0; i < widths.Length; i++)
            {
                builder.Append(new string('-', widths[i] + 2));
                builder.Append('+');
            }

            builder.AppendLine();
        }

        /// <summary>
        /// Renders a single table row with pipe separators.
        /// </summary>
        /// <param name="builder">The target string builder.</param>
        /// <param name="values">Column values for the row.</param>
        /// <param name="widths">Pre-computed column widths.</param>
        /// <param name="rightAlignNumbers">If true, all columns after the first are right-aligned.</param>
        private static void AppendRow(StringBuilder builder, string[] values, int[] widths, bool rightAlignNumbers)
        {
            builder.Append('|');
            for (int i = 0; i < widths.Length; i++)
            {
                string value = i < values.Length ? values[i] : string.Empty;
                bool rightAlign = rightAlignNumbers && i > 0;
                builder.Append(' ');
                if (rightAlign)
                {
                    builder.Append(value.PadLeft(widths[i]));
                }
                else
                {
                    builder.Append(value.PadRight(widths[i]));
                }

                builder.Append(" |");
            }

            builder.AppendLine();
        }

        /// <summary>
        /// Formats a double value with two decimal places using invariant culture.
        /// </summary>
        private static string FormatDouble(double value)
        {
            return value.ToString("F2", CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Formats a microsecond duration into a human-readable string (us, ms, or s).
        /// </summary>
        /// <param name="microseconds">Duration in microseconds.</param>
        /// <returns>A formatted time string with appropriate unit suffix.</returns>
        private static string FormatTimeDisplay(long microseconds)
        {
            if (microseconds <= 0)
            {
                return "0us";
            }

            if (microseconds < 1000L)
            {
                return microseconds.ToString(CultureInfo.InvariantCulture) + "us";
            }

            if (microseconds < 1000000L)
            {
                return (microseconds / 1000d).ToString("F1", CultureInfo.InvariantCulture) + "ms";
            }

            return (microseconds / 1000000d).ToString("F2", CultureInfo.InvariantCulture) + "s";
        }

        /// <summary>
        /// Formats a byte count into a human-readable string with appropriate unit (B, KB, MB, GB).
        /// </summary>
        /// <param name="bytes">The byte count.</param>
        /// <returns>A formatted string with unit suffix.</returns>
        private static string FormatByteSize(double bytes)
        {
            double absoluteBytes = Math.Abs(bytes);

            // Human report readers should not have to mentally convert every KB
            // value; use the smallest practical unit for each individual window.
            if (absoluteBytes < 1024d)
            {
                return bytes.ToString("F0", CultureInfo.InvariantCulture) + " B";
            }

            if (absoluteBytes < 1024d * 1024d)
            {
                return (bytes / 1024d).ToString("F2", CultureInfo.InvariantCulture) + " KB";
            }

            if (absoluteBytes < 1024d * 1024d * 1024d)
            {
                return (bytes / (1024d * 1024d)).ToString("F2", CultureInfo.InvariantCulture) + " MB";
            }

            return (bytes / (1024d * 1024d * 1024d)).ToString("F2", CultureInfo.InvariantCulture) + " GB";
        }

        /// <summary>
        /// Caps throughput at the target bandwidth to prevent reporting physically impossible values.
        /// </summary>
        /// <param name="throughputBytesPerSecond">Measured throughput.</param>
        /// <param name="targetBandwidthBytesPerSecond">Configured bottleneck capacity.</param>
        /// <returns>The capped throughput value.</returns>
        private static double CapThroughputToTarget(double throughputBytesPerSecond, double targetBandwidthBytesPerSecond)
        {
            if (targetBandwidthBytesPerSecond <= 0)
            {
                return throughputBytesPerSecond;
            }

            if (throughputBytesPerSecond < 0)
            {
                return 0;
            }

            return Math.Min(throughputBytesPerSecond, targetBandwidthBytesPerSecond);
        }

        /// <summary>
        /// Converts bytes per second to megabits per second.
        /// </summary>
        private static double ToMbps(double bytesPerSecond)
        {
            return bytesPerSecond * UcpConstants.BITS_PER_BYTE / UcpConstants.BITS_PER_MEGABIT;
        }

        /// <summary>
        /// Converts megabits per second to bytes per second.
        /// </summary>
        private static double FromMbps(double megabitsPerSecond)
        {
            return megabitsPerSecond * UcpConstants.BITS_PER_MEGABIT / UcpConstants.BITS_PER_BYTE;
        }

        /// <summary>
        /// Converts microseconds to milliseconds.
        /// </summary>
        private static double ToMilliseconds(long micros)
        {
            return micros / (double)UcpConstants.MICROS_PER_MILLI;
        }

        /// <summary>
        /// Converts milliseconds to microseconds.
        /// </summary>
        private static long FromMilliseconds(double milliseconds)
        {
            return (long)Math.Round(milliseconds * UcpConstants.MICROS_PER_MILLI);
        }

        /// <summary>
        /// Returns a stable sort order for a scenario name, ensuring reports appear
        /// in a logical progression from simple to complex scenarios.
        /// </summary>
        /// <param name="scenarioName">The scenario identifier.</param>
        /// <returns>An integer sort key; lower values appear first.</returns>
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

            if (scenarioName == "Mobile3G")
            {
                return 160;
            }

            if (scenarioName == "Mobile4G")
            {
                return 170;
            }

            if (scenarioName == "Satellite")
            {
                return 180;
            }

            if (scenarioName == "VpnTunnel")
            {
                return 190;
            }

            if (scenarioName == "DataCenter")
            {
                return 200;
            }

            if (scenarioName == "Enterprise")
            {
                return 210;
            }

            // Unknown scenarios sort last.
            return 1000;
        }

        /// <summary>
        /// Generates a human-readable note for a report based on its scenario name.
        /// </summary>
        /// <param name="report">The report to annotate.</param>
        /// <returns>An explanatory note string, or empty if no special annotation applies.</returns>
        private static string BuildNote(UcpPerformanceReport report)
        {
            if (report.ScenarioName == "LongFatPipe")
            {
                return "throughput is target-capped; protocol pacing/cwnd validated";
            }

            if (report.ScenarioName == "Pacing" || report.ScenarioName == "Lossy")
            {
                return "Loss% is simulator loss; Retrans% is sender repair overhead";
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
