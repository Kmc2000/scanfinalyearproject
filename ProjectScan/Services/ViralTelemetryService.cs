using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using libyaraNET;

namespace ProjectScan.Services
{
    /// <summary>
    /// Detection results following a scan.
    /// </summary>
    public enum ViralTelemetryCategorisation
    {
        /// <summary>
        /// Unknown. The scan either failed, or the system cannot determine anything about the file.
        /// </summary>
        Unknown=0x0,
        /// <summary>
        /// The file did not trigger any detection rules.
        /// </summary>
        Negative=0x1,
        /// <summary>
        /// The file appears "potentially unwanted".
        /// The user may wish to keep the file.
        /// </summary>
        PUA=0x2,
        /// <summary>
        /// The file appears to be malware, and has triggered multiple detection heuristics.
        /// </summary>
        Malware=0x3
    }
    [Flags]
    public enum ViralTelemetryErrorFlags
    {
        None=0x0,
        FileAccessError=0x1,
        Unauthorised=0x2,
        GenericError=0x3
    }

    public struct ViralTelemetryResult
    {
        public ViralTelemetryCategorisation Categorisation;
        public decimal Confidence;
        public ViralTelemetryErrorFlags ErrorFlags;

        public ViralTelemetryResult(ViralTelemetryCategorisation categorisation, decimal confidence, ViralTelemetryErrorFlags flags)
        {
            this.Categorisation = categorisation;
            this.Confidence = confidence;
            this.ErrorFlags = flags;
        }
        /// <summary>
        /// Builds a standard result hinting at an error.
        /// </summary>
        /// <param name="flags"></param>
        /// <returns></returns>
        internal static ViralTelemetryResult ErrorResult(ViralTelemetryErrorFlags flags) => new ViralTelemetryResult(ViralTelemetryCategorisation.Unknown, -1.0m, flags);
        /// <summary>
        /// Returns a result signalling that the operation was OK.
        /// </summary>
        /// <returns></returns>
        internal static ViralTelemetryResult OkResult() => new ViralTelemetryResult(ViralTelemetryCategorisation.Negative, 0.0m, ViralTelemetryErrorFlags.None);

    }

    public interface IViralTelemetryService
    {
        /// <summary>
        /// Perform a scan of the specified file, and return the results.
        /// </summary>
        /// <returns></returns>
        public ViralTelemetryResult Scan(string FileName, out ViralTelemetryErrorFlags flags);
    }

    /// <summary>
    /// Viral telemetry acquisition service.
    /// Provides utilities for scanning files.
    /// </summary>
    internal class ViralTelemetryService : IViralTelemetryService
    {
        public ViralTelemetryResult Scan(string FileName, out ViralTelemetryErrorFlags flags)
        {
            flags = ViralTelemetryErrorFlags.None;
            try
            {
                using (var ctx = new YaraContext())
                {
                    Rules rules= null;

                    try
                    {
                        // Rules and Compiler objects must be disposed.
                        using (var compiler = new Compiler())
                        {
                            // Temporarily loading files from project directory until it's moved into sqlite database.
                            string dir = System.IO.Directory.GetCurrentDirectory().Replace("\\bin\\Debug\\net6.0-windows", "");
                            foreach (string file in Directory.EnumerateFiles(dir + "\\Rules", "*.yar", SearchOption.AllDirectories))
                            {
                                compiler.AddRuleFile(file);
                            }
                           rules = compiler.GetRules();
                        }

                        // Scanner and ScanResults do not need to be disposed.
                        var scanner = new Scanner();
                        var results = scanner.ScanFile(FileName, rules);

                        var categorisation = results.Count > 0 ? ViralTelemetryCategorisation.Malware : ViralTelemetryCategorisation.Negative;
                        return new ViralTelemetryResult(categorisation, 1, flags);
                    }
                    finally
                    {
                        // Rules and Compiler objects must be disposed.
                        if (rules != null) rules.Dispose();
                    }
                }
            }
            catch (IOException)
            {
                flags |= ViralTelemetryErrorFlags.FileAccessError;
            }
            catch (UnauthorizedAccessException)
            {
                flags |= ViralTelemetryErrorFlags.Unauthorised;
            }
            catch (Exception)
            {
                flags |= ViralTelemetryErrorFlags.GenericError;
            }
            return ViralTelemetryResult.ErrorResult(flags);

        }
    }
}
