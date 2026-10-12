using System;

namespace AgentVpnGuard
{
    internal sealed class JournalEntry
    {
        public DateTime Time;
        public GuardStatus? Status;
        public string Text;
    }
}
