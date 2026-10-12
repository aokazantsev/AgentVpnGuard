using System.Runtime.InteropServices;

namespace AgentVpnGuard
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct TcpRow
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
    }
}
