using System.Collections.Generic;

namespace AgentVpnGuard
{
    internal sealed class FirewallSyncResult
    {
        private const string AddedKey = "added";
        private const string RepairedKey = "repaired";
        private const string RemovedKey = "removed";
        private const string ErrorKey = "error";
        private const string DriftKey = "drift";
        private const string PolicyKey = "policy";
        private const string AppliedInterfaceKey = "appliedInterface";

        public int Added;
        public int Repaired;
        public int Removed;
        public readonly List<string> Errors = new List<string>();
        public readonly List<string> Drift = new List<string>();
        public readonly List<string> PolicyProblems = new List<string>();
        public readonly List<string> AppliedInterfaces = new List<string>();

        public void Save(string path)
        {
            var file = new KeyValueFile();
            file.Add(AddedKey, Added.ToString());
            file.Add(RepairedKey, Repaired.ToString());
            file.Add(RemovedKey, Removed.ToString());
            file.AddAll(ErrorKey, Errors);
            file.AddAll(DriftKey, Drift);
            file.AddAll(PolicyKey, PolicyProblems);
            file.AddAll(AppliedInterfaceKey, AppliedInterfaces);
            file.Save(path);
        }

        public static FirewallSyncResult Load(string path)
        {
            KeyValueFile file = KeyValueFile.Load(path);
            var result = new FirewallSyncResult
            {
                Added = file.Number(AddedKey),
                Repaired = file.Number(RepairedKey),
                Removed = file.Number(RemovedKey)
            };
            result.Errors.AddRange(file.All(ErrorKey));
            result.Drift.AddRange(file.All(DriftKey));
            result.PolicyProblems.AddRange(file.All(PolicyKey));
            result.AppliedInterfaces.AddRange(file.All(AppliedInterfaceKey));
            return result;
        }
    }
}
