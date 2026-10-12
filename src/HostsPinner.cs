using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace AgentVpnGuard
{
    internal static class HostsPinner
    {
        public const string BlackholeAddress = "0.0.0.0";

        private const string BeginMarker = "# " + AppIdentity.Name + " begin";
        private const string EndMarker = "# " + AppIdentity.Name + " end";
        private const string LegacyBeginMarker = "# " + AppIdentity.LegacyName + " begin";
        private const string LegacyEndMarker = "# " + AppIdentity.LegacyName + " end";
        private const int WriteAttempts = 5;
        private const int WriteRetryMs = 200;

        public static readonly string HostsPath = Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts");

        public static Dictionary<string, string> ReadPins()
        {
            var pins = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            bool inside = false;
            foreach (string line in ReadLines())
            {
                string trimmed = line.Trim();
                if (trimmed == BeginMarker || trimmed == LegacyBeginMarker) inside = true;
                else if (trimmed == EndMarker || trimmed == LegacyEndMarker) inside = false;
                else if (inside && trimmed.Length > 0 && !trimmed.StartsWith("#"))
                {
                    string[] parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2) pins[parts[1]] = parts[0];
                }
            }
            return pins;
        }

        public static Dictionary<string, string> Block(IList<string> hosts, IDictionary<string, string> pins)
        {
            var block = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string host in hosts)
            {
                string address;
                if (!pins.TryGetValue(host, out address)) address = BlackholeAddress;
                block[host] = address;
            }
            return block;
        }

        public static bool Apply(IList<string> hosts, IDictionary<string, string> pins)
        {
            var block = new List<string> { BeginMarker };
            foreach (string host in hosts)
            {
                string address;
                if (!pins.TryGetValue(host, out address)) address = BlackholeAddress;
                block.Add(address + " " + host);
            }
            block.Add(EndMarker);
            return Rewrite(block);
        }

        public static bool Remove()
        {
            return Rewrite(new List<string>());
        }

        private static bool Rewrite(List<string> block)
        {
            byte[] original = File.Exists(HostsPath) ? File.ReadAllBytes(HostsPath) : new byte[0];
            bool hasBom = original.Length >= 3 && original[0] == 0xEF && original[1] == 0xBB && original[2] == 0xBF;
            string text = new UTF8Encoding(false).GetString(original, hasBom ? 3 : 0, original.Length - (hasBom ? 3 : 0));

            var kept = new List<string>();
            bool inside = false;
            foreach (string line in SplitLines(text))
            {
                string trimmed = line.Trim();
                if (trimmed == BeginMarker || trimmed == LegacyBeginMarker) inside = true;
                else if (trimmed == EndMarker || trimmed == LegacyEndMarker) inside = false;
                else if (!inside) kept.Add(line);
            }
            while (kept.Count > 0 && kept[kept.Count - 1].Trim().Length == 0) kept.RemoveAt(kept.Count - 1);
            var result = new StringBuilder();
            foreach (string line in kept) result.Append(line).Append("\r\n");
            if (block.Count > 0)
            {
                result.Append("\r\n");
                foreach (string line in block) result.Append(line).Append("\r\n");
            }
            string updated = result.ToString();
            if (updated == text) return false;

            byte[] body = new UTF8Encoding(false).GetBytes(updated);
            byte[] bytes = hasBom ? Concat(new byte[] { 0xEF, 0xBB, 0xBF }, body) : body;
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    File.WriteAllBytes(HostsPath, bytes);
                    break;
                }
                catch (IOException)
                {
                    if (attempt >= WriteAttempts) throw;
                }
                Thread.Sleep(WriteRetryMs);
            }
            DnsFlushResolverCache();
            return true;
        }

        private static IEnumerable<string> ReadLines()
        {
            if (!File.Exists(HostsPath)) return new string[0];
            return SplitLines(File.ReadAllText(HostsPath, Encoding.UTF8));
        }

        private static string[] SplitLines(string text)
        {
            return text.Replace("\r\n", "\n").Split('\n');
        }

        private static byte[] Concat(byte[] first, byte[] second)
        {
            var bytes = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, bytes, 0, first.Length);
            Buffer.BlockCopy(second, 0, bytes, first.Length, second.Length);
            return bytes;
        }

        [DllImport("dnsapi.dll")]
        private static extern bool DnsFlushResolverCache();
    }
}
