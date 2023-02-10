using ProjectScan.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProjectScan.Models
{
    /// <summary>
    /// A YARA ruleset entity stored in the database
    /// </summary>
    public class YaraRuleset
    {
        /// <summary>
        /// The PK Id for this rule in the DB, autoincrementing
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// The YARA rule generated to match a pattern for a known sample
        /// </summary>
        public string? YaraRule { get; set; }

        /// <summary>
        /// The categorisation of the software the YARA rule is matching
        /// </summary>
        public ViralTelemetryCategorisation Categorisation { get; set; }
    }
}
