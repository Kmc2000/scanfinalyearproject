using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using libyaraNET;

namespace ProjectScan.Services
{
    internal class YaraTelemetryService : IViralTelemetryService
    {
        public ViralTelemetryResult Scan(string FileName, out ViralTelemetryErrorFlags flags)
        {
            flags = ViralTelemetryErrorFlags.None;
            try
            {
                using (YaraContext ctx = new YaraContext())
                using(Compiler compiler = new Compiler())       
                {
           
                    // Temporarily loading files from project directory until it's moved into sqlite database.
                    string dir = System.IO.Directory.GetCurrentDirectory().Replace("\\bin\\Debug\\net6.0-windows", "");
                    foreach (string file in Directory.EnumerateFiles(dir + "\\Rules", "*.yar", SearchOption.AllDirectories))
                    {
                        compiler.AddRuleFile(file);
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
