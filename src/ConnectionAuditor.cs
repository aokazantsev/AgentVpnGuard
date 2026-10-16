using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;

namespace AgentVpnGuard
{
    internal static class ConnectionAuditor
    {
        private const int AddressFamilyInet = 2;
        private const int AddressFamilyInet6 = 23;
        private const int TableOwnerPidConnections = 4;
        private const uint NoError = 0;
        private const uint InsufficientBuffer = 122;
        private const int Row4Size = 24;
        private const int Row6Size = 56;
        private const int StateEstablished = 5;
        private const int StateDeleteTcb = 12;

        public static ConnectionAudit Audit(Dictionary<int, string> claudeProcesses, AdapterSnapshot adapters)
        {
            var audit = new ConnectionAudit();
            if (claudeProcesses.Count == 0) return audit;
            AuditIpv4(claudeProcesses, adapters, audit);
            AuditIpv6(claudeProcesses, adapters, audit);
            return audit;
        }

        private static void AuditIpv4(Dictionary<int, string> claudeProcesses, AdapterSnapshot adapters, ConnectionAudit audit)
        {
            ReadTable(AddressFamilyInet, Row4Size, row =>
            {
                int state = Marshal.ReadInt32(row, 0);
                int pid = Marshal.ReadInt32(row, 20);
                string path;
                if (state != StateEstablished || !claudeProcesses.TryGetValue(pid, out path)) return;
                var local = new IPAddress((uint)Marshal.ReadInt32(row, 4));
                var remote = new IPAddress((uint)Marshal.ReadInt32(row, 12));
                if (IPAddress.IsLoopback(remote) || adapters.IsVpnAddress(local)) return;
                audit.Leaks.Add(Path.GetFileName(path) + " → " + remote + ":" + Port(Marshal.ReadInt32(row, 16)));
                if (Close(row)) audit.Closed++;
            });
        }

        private static void AuditIpv6(Dictionary<int, string> claudeProcesses, AdapterSnapshot adapters, ConnectionAudit audit)
        {
            ReadTable(AddressFamilyInet6, Row6Size, row =>
            {
                int state = Marshal.ReadInt32(row, 48);
                int pid = Marshal.ReadInt32(row, 52);
                string path;
                if (state != StateEstablished || !claudeProcesses.TryGetValue(pid, out path)) return;
                var local = new IPAddress(ReadBytes(row, 0, 16));
                var remote = new IPAddress(ReadBytes(row, 24, 16));
                if (IPAddress.IsLoopback(remote) || adapters.IsVpnAddress(local)) return;
                audit.Leaks.Add(Path.GetFileName(path) + " → [" + remote + "]:" + Port(Marshal.ReadInt32(row, 44)));
            });
        }

        private static bool Close(IntPtr row)
        {
            var entry = new TcpRow
            {
                State = StateDeleteTcb,
                LocalAddress = (uint)Marshal.ReadInt32(row, 4),
                LocalPort = (uint)Marshal.ReadInt32(row, 8),
                RemoteAddress = (uint)Marshal.ReadInt32(row, 12),
                RemotePort = (uint)Marshal.ReadInt32(row, 16)
            };
            return SetTcpEntry(ref entry) == NoError;
        }

        private static void ReadTable(int addressFamily, int rowSize, Action<IntPtr> visit)
        {
            int size = 0;
            if (GetExtendedTcpTable(IntPtr.Zero, ref size, false, addressFamily, TableOwnerPidConnections, 0) != InsufficientBuffer) return;
            size += 4096;
            IntPtr table = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(table, ref size, false, addressFamily, TableOwnerPidConnections, 0) != NoError) return;
                int rowCount = Marshal.ReadInt32(table);
                for (int i = 0; i < rowCount; i++) visit(IntPtr.Add(table, 4 + i * rowSize));
            }
            finally
            {
                Marshal.FreeHGlobal(table);
            }
        }

        private static byte[] ReadBytes(IntPtr pointer, int offset, int count)
        {
            var bytes = new byte[count];
            Marshal.Copy(IntPtr.Add(pointer, offset), bytes, 0, count);
            return bytes;
        }

        private static int Port(int raw)
        {
            return IPAddress.NetworkToHostOrder((short)(raw & 0xFFFF)) & 0xFFFF;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int addressFamily, int tableClass, uint reserved);

        [DllImport("iphlpapi.dll")]
        private static extern uint SetTcpEntry(ref TcpRow row);
    }
}
