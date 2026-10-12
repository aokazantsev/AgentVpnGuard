using System.Collections.Generic;
using System.Net;

namespace AgentVpnGuard
{
    internal sealed class NetworkAdapter
    {
        public string Name;
        public string Description;
        public bool IsPresent;
        public bool IsUp;
        public bool IsVpn;
        public int Ipv4Index = -1;
        public readonly List<IPAddress> Addresses = new List<IPAddress>();
        public readonly List<IPAddress> DnsServers = new List<IPAddress>();

        public IPAddress Ipv4Address
        {
            get { return Addresses.Find(address => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork); }
        }
    }
}
