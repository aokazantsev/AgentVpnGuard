using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
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
        private const int WriteAttempts = 2;
        private const int WriteRetryMs = 200;

        public static readonly string HostsPath = Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts");

        public static ICollection<string> OwnHosts;

        public static Dictionary<string, string> ReadPins()
        {
            var pins = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string[] lines = ReadLines();
            bool[] inside = BlockMask(lines);
            for (int index = 0; index < lines.Length; index++)
            {
                string trimmed = lines[index].Trim();
                if (!inside[index] || !IsPinLine(trimmed)) continue;
                string[] parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                IPAddress address;
                if (parts.Length >= 2 && IPAddress.TryParse(parts[0], out address)) pins[parts[1]] = parts[0];
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

        public static bool Apply(Dictionary<string, string> block)
        {
            var lines = new List<string> { BeginMarker };
            foreach (KeyValuePair<string, string> pin in block) lines.Add(pin.Value + " " + pin.Key);
            lines.Add(EndMarker);
            return Rewrite(lines);
        }

        public static void Remove()
        {
            Rewrite(new List<string>());
        }

        private static bool Rewrite(List<string> block)
        {
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    return RewriteOnce(block);
                }
                catch (IOException)
                {
                    if (attempt >= WriteAttempts) throw;
                }
                Thread.Sleep(WriteRetryMs);
            }
        }

        private static bool RewriteOnce(List<string> block)
        {
            byte[] original = File.Exists(HostsPath) ? File.ReadAllBytes(HostsPath) : new byte[0];
            bool hasBom = original.Length >= 3 && original[0] == 0xEF && original[1] == 0xBB && original[2] == 0xBF;
            Encoding encoding = DetectEncoding(original, hasBom);
            string text = encoding.GetString(original, hasBom ? 3 : 0, original.Length - (hasBom ? 3 : 0));

            var kept = new List<string>();
            string[] lines = SplitLines(text);
            bool[] inside = BlockMask(lines);
            for (int index = 0; index < lines.Length; index++)
            {
                string trimmed = lines[index].Trim();
                if (!inside[index] && !IsBeginMarker(trimmed) && !IsEndMarker(trimmed)) kept.Add(lines[index]);
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

            byte[] body = encoding.GetBytes(updated);
            byte[] bytes = hasBom ? Concat(new byte[] { 0xEF, 0xBB, 0xBF }, body) : body;
            File.WriteAllBytes(HostsPath, bytes);
            DnsFlushResolverCache();
            return true;
        }

        private static string[] ReadLines()
        {
            if (!File.Exists(HostsPath)) return new string[0];
            byte[] original = File.ReadAllBytes(HostsPath);
            bool hasBom = original.Length >= 3 && original[0] == 0xEF && original[1] == 0xBB && original[2] == 0xBF;
            return SplitLines(DetectEncoding(original, hasBom).GetString(original, hasBom ? 3 : 0, original.Length - (hasBom ? 3 : 0)));
        }

        private static bool IsBeginMarker(string trimmed)
        {
            return trimmed == BeginMarker || trimmed == LegacyBeginMarker;
        }

        private static bool IsEndMarker(string trimmed)
        {
            return trimmed == EndMarker || trimmed == LegacyEndMarker;
        }

        private static bool[] BlockMask(string[] lines)
        {
            var inside = new bool[lines.Length];
            int index = 0;
            while (index < lines.Length)
            {
                if (!IsBeginMarker(lines[index].Trim()))
                {
                    index++;
                    continue;
                }
                int end = -1;
                for (int next = index + 1; next < lines.Length && end < 0 && !IsBeginMarker(lines[next].Trim()); next++)
                {
                    if (IsEndMarker(lines[next].Trim())) end = next;
                }
                int last = index;
                if (end >= 0) last = end;
                else
                {
                    while (last + 1 < lines.Length && IsPinLine(lines[last + 1].Trim())) last++;
                }
                for (int line = index; line <= last; line++) inside[line] = end >= 0 || line == index || IsOwnPinLine(lines[line].Trim());
                index = last + 1;
            }
            return inside;
        }

        private static bool IsPinLine(string trimmed)
        {
            return trimmed.Length > 0 && !trimmed.StartsWith("#");
        }

        private static bool IsOwnPinLine(string trimmed)
        {
            if (!IsPinLine(trimmed)) return false;
            ICollection<string> own = OwnHosts;
            if (own == null) return true;
            string[] parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2) return false;
            foreach (string host in own)
            {
                if (string.Equals(host, parts[1], StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private static Encoding DetectEncoding(byte[] bytes, bool hasBom)
        {
            if (hasBom) return new UTF8Encoding(false);
            try
            {
                new UTF8Encoding(false, true).GetString(bytes);
                return new UTF8Encoding(false);
            }
            catch (DecoderFallbackException)
            {
                return Encoding.Default;
            }
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
