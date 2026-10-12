using System;
using System.Collections.Generic;
using System.Net;

namespace AgentVpnGuard
{
    internal sealed class AdapterSnapshot
    {
        public readonly List<NetworkAdapter> Adapters = new List<NetworkAdapter>();

        public bool HasVpnAdapter
        {
            get { return Adapters.Exists(adapter => adapter.IsVpn); }
        }

        public NetworkAdapter ActiveVpn
        {
            get { return Adapters.Find(adapter => adapter.IsVpn && adapter.IsUp && adapter.Addresses.Count > 0); }
        }

        public List<string> BlockedInterfaceNames(bool includeVpn)
        {
            var names = new List<string>();
            foreach (NetworkAdapter adapter in Adapters)
            {
                if ((adapter.IsVpn && !includeVpn) || !adapter.IsPresent) continue;
                if (!names.Exists(name => string.Equals(name, adapter.Name, StringComparison.OrdinalIgnoreCase))) names.Add(adapter.Name);
            }
            names.Sort(StringComparer.OrdinalIgnoreCase);
            return names;
        }

        public bool IsVpnAddress(IPAddress address)
        {
            foreach (NetworkAdapter adapter in Adapters)
            {
                if (adapter.IsVpn && adapter.Addresses.Contains(address)) return true;
            }
            return false;
        }

        public bool IsVpnInterface(int ipv4Index)
        {
            return Adapters.Exists(adapter => adapter.IsVpn && adapter.Ipv4Index == ipv4Index);
        }
    }
}
