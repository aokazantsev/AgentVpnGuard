using System.Collections.Generic;

namespace AgentVpnGuard
{
    internal sealed class GuardReport
    {
        public GuardStatus Status;
        public string Headline;
        public bool Settling;
        public readonly List<string> Details = new List<string>();
        public readonly List<string> Problems = new List<string>();
        public readonly List<string> Events = new List<string>();
        public readonly List<string> Executables = new List<string>();
    }
}
