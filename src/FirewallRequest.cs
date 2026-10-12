using System.Collections.Generic;

namespace AgentVpnGuard
{
    internal sealed class FirewallRequest
    {
        private const string VerifyKey = "verify";
        private const string RemoveAllKey = "removeAll";
        private const string TraceKey = "trace";
        private const string ExecutableKey = "exe";
        private const string InterfaceKey = "interface";
        private const string AppliedInterfaceKey = "appliedInterface";

        public bool VerifyOnly;
        public bool RemoveAll;
        public bool Trace;
        public readonly List<string> Executables = new List<string>();
        public readonly List<string> Interfaces = new List<string>();
        public readonly List<string> AppliedInterfaces = new List<string>();

        public void Save(string path)
        {
            var file = new KeyValueFile();
            file.Add(VerifyKey, VerifyOnly);
            file.Add(RemoveAllKey, RemoveAll);
            file.Add(TraceKey, Trace);
            file.AddAll(ExecutableKey, Executables);
            file.AddAll(InterfaceKey, Interfaces);
            file.AddAll(AppliedInterfaceKey, AppliedInterfaces);
            file.Save(path);
        }

        public static FirewallRequest Load(string path)
        {
            KeyValueFile file = KeyValueFile.Load(path);
            var request = new FirewallRequest
            {
                VerifyOnly = file.Flag(VerifyKey),
                RemoveAll = file.Flag(RemoveAllKey),
                Trace = file.Flag(TraceKey)
            };
            request.Executables.AddRange(file.All(ExecutableKey));
            request.Interfaces.AddRange(file.All(InterfaceKey));
            request.AppliedInterfaces.AddRange(file.All(AppliedInterfaceKey));
            return request;
        }
    }
}
