using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using NSec.Cryptography;

namespace PowershellEd25519
{
    /// <summary>
    ///     A simple Cmdlet that outputs a greeting to the pipeline.
    /// </summary>
    [Cmdlet("Sign", "Ed25519", DefaultParameterSetName = ParamSetPath)]
    public class SignEd25519 : PSCmdlet
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = ParamSetPath)]
        public string[] Path { get; set; }

        [Alias("PSPath")]
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = ParamSetLiteral)]
        public string[] LiteralPath { get; set; }

        [ValidateNotNullOrEmpty]
        [Parameter(Mandatory = true)]
        public string KeyFile { get; set; }

        /// <summary>
        ///     Perform Cmdlet processing.
        /// </summary>
        protected override void ProcessRecord()
        {
            var toProcess = new List<string>();
            switch (ParameterSetName)
            {
                case ParamSetLiteral:
                {
                    toProcess.AddRange(LiteralPath.Select(GetUnresolvedProviderPathFromPSPath));
                    break;
                }
                case ParamSetPath:
                {
                    foreach (var p in Path)
                    {
                        toProcess.AddRange(GetResolvedProviderPathFromPSPath(p, out _));
                    }

                    break;
                }
            }

            var key = Key.Import(SignatureAlgorithm.Ed25519, File.ReadAllBytes(KeyFile), KeyBlobFormat.PkixPrivateKeyText);

            foreach (var p in toProcess)
            {
                var sig = SignFile(key, p);
                WriteObject(new FileSignatureInfo
                {
                    Path = p,
                    Signature = sig
                });
            }
        }

        private static string SignFile(Key key, string path)
        {
            var bytes = File.ReadAllBytes(path);

            var sig = SignatureAlgorithm.Ed25519.Sign(key, bytes);
            return BitConverter.ToString(sig).Replace("-", string.Empty);
        }

        private const string ParamSetLiteral = "LiteralPath";
        private const string ParamSetPath = "Path";
    }

    public sealed class FileSignatureInfo
    {
        public string Path { get; set; }
        public string Signature { get; set; }
    }
}
