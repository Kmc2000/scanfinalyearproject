using Microsoft.VisualStudio.TestTools.UnitTesting;
using ProjectScan.Services;
using ProjectScanTests1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProjectScan.Services.Tests
{
    [TestClass()]
    public class YaraTelemetryServiceTests
    {

        [TestMethod()]
        public void GetRuleCountTest()
        {
            // Setup test db
            using var controller = new InMemoryDBController();
            MalwareScannerContext context = controller.GetContext();
            YaraTelemetryService service = new YaraTelemetryService(context);

            // add test data
            context.KnownBadYaraRules.Add(new Models.YaraRuleset() { YaraRule = "test1", Categorisation = ViralTelemetryCategorisation.Malware });
            context.KnownBadYaraRules.Add(new Models.YaraRuleset() { YaraRule = "test2", Categorisation = ViralTelemetryCategorisation.Malware });
            context.KnownBadYaraRules.Add(new Models.YaraRuleset() { YaraRule = "test3", Categorisation = ViralTelemetryCategorisation.Malware });
            context.SaveChanges();

            Assert.AreEqual(service.GetRuleCount(), 3);
        }
    }
}