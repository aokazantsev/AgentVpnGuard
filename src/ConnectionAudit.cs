using System.Collections.Generic;

namespace AgentVpnGuard
{
    internal sealed class ConnectionAudit
    {
        public readonly List<string> Leaks = new List<string>();
        public int Closed;
    }
}
