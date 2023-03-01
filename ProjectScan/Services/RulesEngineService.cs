using Microsoft.EntityFrameworkCore.Internal;
using Microsoft.EntityFrameworkCore.Migrations;
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
        /// TODO: Read all rules from a directory of files.
        /// This should be used by project maintainers to pull new rules from whatever sources
        /// we decide on
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

        internal static List<string> LoadRulesFromDirectory(string filePath)
        {
            
            List<string> rules = new List<string>();

            try
            {
                var files = Directory.GetFiles(filePath);

                foreach (var file in files)
                {
                    rules.Add(File.ReadAllText(file));
                }

                var directories = Directory.GetDirectories(filePath);

                foreach (var directory in directories)
                {
                    rules.AddRange(LoadRulesFromDirectory(directory));
                }

                
            }
            catch (Exception e)
            {
                Console.WriteLine("DBG: Err: " + e);
            }

            return rules;
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

        /// <summary>
        /// Register a list of YARA rule into the database.
        /// </summary>
        /// <param name="rule">A string representation of a YARA rule.</param>
        /// <param name="category">The classification category assigned to the rule. PUA, malware, etc.</param>
        internal static async Task RegisterYaraRules(List<string> rules)
        {
            // Prevent empty rules being added to the database.
            if (rules == null || rules.Count == 0)
            {
                throw new InvalidOperationException();
            }

            List<YaraRuleset> rulesList = new List<YaraRuleset>();


            foreach (var rule in rules)
            {
                // Create rule object for entry, Id autogenerated, and add to batch list
                rulesList.Add(new YaraRuleset() 
                {
                    YaraRule = rule,
                    Categorisation = ViralTelemetryCategorisation.Malware
                });   
            }
           
            

            using(MalwareScannerContext context = new())
            {
                // Reset YARA rules table
                context.RemoveRange(context.KnownBadYaraRules);
                await context.KnownBadYaraRules.AddRangeAsync(rulesList);
                await context.SaveChangesAsync();
            }
        }
    }
#endif
}
