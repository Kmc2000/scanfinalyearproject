using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProjectScan.Services
{
    interface IHashEqualityComparer
    {
        /// <summary>
        /// Compare two hashes, passed in as byte arrays.
        /// </summary>
        /// <param name="x">The first hash to compare.</param>
        /// <param name="y">The second hash to compare.</param>
        /// <returns>True if the hashes match.</returns>
        bool Compare(byte[] x, byte[] y);
    }

    public class SHA256HashEqualityComparer : IHashEqualityComparer
    {
        public bool Compare(byte[] x, byte[] y)
        {
            //We perform less computationally expensive preconditions first to save time.
            #region CHEAP_CHECKS
            if (x == null || y == null)
            {
                return false;
            }
            //This would cause a read-access violation otherwise.
            //But two arrays of different lengths can never be equal.
            if(x.Length != y.Length)
            {
                return false;
            }
            #endregion
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] != y[i])
                {
                    return false;
                }
            }
            return true;
        }
    }

    /// <summary>
    /// 
    /// </summary>
    internal class HashTelemetryService : IViralTelemetryService
    {
        #region DUMMY_CODE
        byte[] Example = System.Text.Encoding.UTF8.GetBytes("Hello, world!");

        #endregion
        /// <summary>
        /// The comparison engine which we'll be using to compare the hashes of the two files.
        /// </summary>
        protected virtual IHashEqualityComparer Instance { get; set; }

        public ViralTelemetryResult Scan(string FileName, out ViralTelemetryErrorFlags flags)
        {
            flags = ViralTelemetryErrorFlags.None;
            try
            {
                using (FileStream fs = new(FileName, FileMode.Open, FileAccess.Read))
                {
                    using (SHA256 sha256Hash = SHA256.Create())
                    {
                        byte[] fileHash = sha256Hash.ComputeHash(fs);
                        
                        ViralTelemetryResult result = ViralTelemetryResult.OkResult();
                        try
                        {
                            //Stream all known bad hashes from the DB.
                            using (var ctx = new MalwareScannerContext()) {

                                foreach(var hash in ctx.KnownBadHashes)
                                {
                                    //And compare the file's hash value to the known bad hash.
                                    if (Instance.Compare(fileHash, hash.MalwareHash))
                                    {
                                        result = new(hash.Categorisation, 1.0m, ViralTelemetryErrorFlags.None);
                                        break;
                                    }
                                }
                            }


                        }
                        catch (OperationCanceledException)
                        {
                            Console.WriteLine("Detection cancelled due to a positive match.");
                        }
                        return result;

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
    internal class SHA256HashTelemetryService : HashTelemetryService
    {
        protected override IHashEqualityComparer Instance { get; set; } = new SHA256HashEqualityComparer();
    }
}
