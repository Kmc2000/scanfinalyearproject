using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using libyaraNET;
using Microsoft.EntityFrameworkCore;
using ProjectScan.Models;

namespace ProjectScan.Services
{
    public class YaraTelemetryService : IViralTelemetryService
    {
        // db context
        private MalwareScannerContext context { get; set; }

        // default constructor using normal db context
        public YaraTelemetryService()
        {
            context = new MalwareScannerContext();
        }

        // overloaded constructor for using custom db contexts for testing purposes
        public YaraTelemetryService(MalwareScannerContext ctx)
        {
            this.context = ctx;
        }


        /// <summary>
        /// Return the number of rules known to this heuristic.
        /// </summary>
        /// <returns></returns>
        public int GetRuleCount()
        {
            return context.KnownBadYaraRules.Count();
        }

        public ViralTelemetryResult Scan(string FileName, out ViralTelemetryErrorFlags flags, MainWindow src)
        {
            flags = ViralTelemetryErrorFlags.None;
            try
            {
                using (YaraContext ctx = new YaraContext())
                using(Compiler compiler = new Compiler())
                {
                      
                    List<YaraRuleset> rulesList = context.KnownBadYaraRules.ToList();
                    
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
