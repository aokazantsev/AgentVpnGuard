using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace AgentVpnGuard
{
    internal static class DnsResolver
    {
        private const int HeaderSize = 12;
        private const int TypeA = 1;
        private const int ClassInternet = 1;
        private const int ResponseCodeMask = 0x0F;
        private static readonly Random Ids = new Random();

        public static List<IPAddress> QueryA(IPAddress server, string host, int timeoutMs)
        {
            var addresses = new List<IPAddress>();
            ushort id;
            lock (Ids)
            {
                id = (ushort)Ids.Next(ushort.MaxValue);
            }
            byte[] query = BuildQuery(id, host);
            using (var client = new UdpClient(server.AddressFamily))
            {
                client.Client.ReceiveTimeout = timeoutMs;
                client.Send(query, query.Length, new IPEndPoint(server, 53));
                IPEndPoint remote = null;
                byte[] response;
                try
                {
                    response = client.Receive(ref remote);
                }
                catch (SocketException)
                {
                    return addresses;
                }
                Parse(response, id, addresses);
            }
            return addresses;
        }

        private static byte[] BuildQuery(ushort id, string host)
        {
            var packet = new List<byte>
            {
                (byte)(id >> 8), (byte)id,
                0x01, 0x00,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00
            };
            foreach (string label in host.TrimEnd('.').Split('.'))
            {
                byte[] bytes = Encoding.ASCII.GetBytes(label);
                packet.Add((byte)bytes.Length);
                packet.AddRange(bytes);
            }
            packet.Add(0);
            packet.AddRange(new byte[] { 0x00, TypeA, 0x00, ClassInternet });
            return packet.ToArray();
        }

        private static void Parse(byte[] response, ushort id, List<IPAddress> addresses)
        {
            if (response.Length < HeaderSize) return;
            if (((response[0] << 8) | response[1]) != id) return;
            if ((response[3] & ResponseCodeMask) != 0) return;
            int questions = (response[4] << 8) | response[5];
            int answers = (response[6] << 8) | response[7];
            int position = HeaderSize;
            for (int i = 0; i < questions; i++)
            {
                position = SkipName(response, position) + 4;
            }
            for (int i = 0; i < answers && position + 10 <= response.Length; i++)
            {
                position = SkipName(response, position);
                if (position + 10 > response.Length) return;
                int type = (response[position] << 8) | response[position + 1];
                int length = (response[position + 8] << 8) | response[position + 9];
                position += 10;
                if (position + length > response.Length) return;
                if (type == TypeA && length == 4)
                {
                    addresses.Add(new IPAddress(new[] { response[position], response[position + 1], response[position + 2], response[position + 3] }));
                }
                position += length;
            }
        }

        private static int SkipName(byte[] response, int position)
        {
            while (position < response.Length)
            {
                int length = response[position];
                if ((length & 0xC0) == 0xC0) return position + 2;
                if (length == 0) return position + 1;
                position += length + 1;
            }
            return position;
        }
    }
}
