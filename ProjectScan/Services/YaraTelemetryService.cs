using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using libyaraNET;
using ProjectScan.Models;

namespace ProjectScan.Services
{
    internal class YaraTelemetryService : IViralTelemetryService
    {
        /// <summary>
        /// Return the number of rules known to this heuristic.
        /// </summary>
        /// <returns></returns>
        public int GetRuleCount()
        {
            using (MalwareScannerContext dbContext = new MalwareScannerContext())
            {
                return dbContext.KnownBadYaraRules.Count();
            }
        }

        public ViralTelemetryResult Scan(string FileName, out ViralTelemetryErrorFlags flags, MainWindow src)
        {
            flags = ViralTelemetryErrorFlags.None;
            try
            {
                using (YaraContext ctx = new YaraContext())
                using(Compiler compiler = new Compiler())
                using (MalwareScannerContext dbContext = new MalwareScannerContext())
                {
                      
                    List<YaraRuleset> rulesList = dbContext.KnownBadYaraRules.ToList();
                    
                    foreach (YaraRuleset rule in rulesList)
                    {
                        compiler.AddRuleString(rule.YaraRule);
                        //Mark a completed heuristic.
                        Interlocked.Increment(ref IViralTelemetryService.ExecutionCount);
                        src.RenderProgress();
                    }

                    using (Rules? rules = compiler.GetRules())
                    {
                        // Scanner and ScanResults do not need to be disposed.
                        var scanner = new Scanner();
                        var results = scanner.ScanFile(FileName, rules);

                        var categorisation = results.Count > 0 ? ViralTelemetryCategorisation.Malware : ViralTelemetryCategorisation.Negative;
                        return new ViralTelemetryResult(categorisation, 1, flags);
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
            catch (CompilationException)
            {
                flags |= ViralTelemetryErrorFlags.YaraCompilationError;
            }
            catch (Exception)
            {
                flags |= ViralTelemetryErrorFlags.GenericError;
            }

            return ViralTelemetryResult.ErrorResult(flags);
        }
    }
}
