using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace AgentVpnGuard
{
    internal static class RouteInspector
    {
        private const uint NoError = 0;

        public static int BestInterfaceIndex(IPAddress destination)
        {
            if (destination.AddressFamily != AddressFamily.InterNetwork) return -1;
            uint index;
            uint address = BitConverter.ToUInt32(destination.GetAddressBytes(), 0);
            return GetBestInterface(address, out index) == NoError ? (int)index : -1;
        }

        [DllImport("iphlpapi.dll")]
        private static extern uint GetBestInterface(uint destinationAddress, out uint bestInterfaceIndex);
    }
}
