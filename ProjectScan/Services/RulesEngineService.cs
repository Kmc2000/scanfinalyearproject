using ProjectScan.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Policy;
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
    internal static class RulesEngineService
    {
        internal static void ClearDatabase()
        {
            using (MalwareScannerContext ctx = new())
            {
                //Dump the hashes table.
                ctx.KnownBadHashes.RemoveRange(ctx.KnownBadHashes);
                ctx.SaveChanges();
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
        internal static async void GenerateRules(string filePath)
        {
            try
            {
                //Stream hashes in chunks of 16 to optimise queries.
                int max_records = 128;
                List<KnownMalwareHash> Block = new List<KnownMalwareHash>();
                int i = -1;
                int record = 0;
                string[] buff = System.IO.File.ReadAllLines(filePath);
                foreach (string rawHash in buff)
                {
                    record++;
                    if(++i < max_records)
                    {
                        Block.Add(new KnownMalwareHash()
                        {
                            Categorisation = ViralTelemetryCategorisation.Malware,
                            MalwareHash = System.Text.Encoding.UTF8.GetBytes(rawHash),
                        });
                        if (record >= buff.Length)
                        {
                            goto update;
                        }
                        continue;
                    }
                    update:
                    //string s = System.Text.Encoding.UTF8.GetString(Block[0].MalwareHash);
                    //Insert block.
                    await RegisterBlock(Block);
                    //Reset block index.
                    i = -1;
                    Block.Clear();
                }
            }
            catch (IOException e)
            {
                Console.WriteLine("DBG: Err: " + e);
            }

        }

        internal static async Task RegisterBlock(List<KnownMalwareHash> Block)
        {
            if (Block == null)
            {
                throw new InvalidOperationException();
            }
            using (MalwareScannerContext ctx = new())
            {
                await ctx.KnownBadHashes.AddRangeAsync(Block);
                await ctx.SaveChangesAsync();
            }
        }

        /// <summary>
        /// Register a new known "bad" hash into the database.
        /// </summary>
        /// <param name="Hash">The hash of the sample file.</param>
        /// <param name="category">The categorisation of the sample. PUA, malware, etc.</param>
        /// <exception cref="InvalidOperationException"></exception>
        internal static async void RegisterHash(byte[] Hash, ViralTelemetryCategorisation category)
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
