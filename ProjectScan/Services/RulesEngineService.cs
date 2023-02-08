using ProjectScan.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProjectScan.Services
{
#if DEBUG
    /// <summary>
    /// Internal rules engine for updating the database.
    /// This is, predictably, NOT present in production!
    /// If you leave any references to this interface hanging around in prod, it will break.
    /// For more information, please re-read.
    /// </summary>
    internal class RulesEngineService
    {
        internal void ClearDatabase()
        {
            using (MalwareScannerContext ctx = new())
            {
                //Dump the hashes table.
                ctx.KnownBadHashes.RemoveRange(ctx.KnownBadHashes);
            }
        }

        /// <summary>
        /// TODO: Generate all rules from a file.
        /// This could be json, CSV, or something else entirely.
        /// This should be used by project maintainers to pull new rules from whatever sources
        /// we decide on, and insert the values into the database.
        /// </summary>
        /// <param name="filePath"></param>
        /// <exception cref="NotImplementedException"></exception>
        internal async void GenerateRules(string filePath)
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// Register a new known "bad" hash into the database.
        /// </summary>
        /// <param name="Hash">The hash of the sample file.</param>
        /// <param name="category">The categorisation of the sample. PUA, malware, etc.</param>
        /// <exception cref="InvalidOperationException"></exception>
        internal async void RegisterHash(byte[] Hash, ViralTelemetryCategorisation category)
        {
            if (Hash == null || Hash.Length <= 0)
            {
                throw new InvalidOperationException();
            }
            KnownMalwareHash ToInsert = new()
            {
                Categorisation = category,
                MalwareHash=Hash
            };
            using(MalwareScannerContext ctx = new())
            {
                ctx.KnownBadHashes.Add(ToInsert);
                await ctx.SaveChangesAsync();
            }
        }

    }
#endif
}
