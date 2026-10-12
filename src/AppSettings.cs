using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AgentVpnGuard
{
    internal sealed class AppSettings
    {
        private const string VpnAdaptersKey = "vpnAdapters";
        private const string PinnedHostsKey = "pinnedHosts";
        private const string CriticalHostsKey = "criticalHosts";
        private const string ProxiedHostsKey = "proxiedHosts";
        private const string ExtraExecutablesKey = "extraExecutables";
        private const string NotificationsKey = "notifications";
        private const string ProtectionEnabledKey = "protectionEnabled";
        private const char KeyValueSeparator = '=';
        private const char ListSeparator = '|';
        private static readonly string[] FirstProxiedDefault = { "challenges.cloudflare.com" };

        public static readonly string FilePath = Path.Combine(AppIdentity.DataDirectory, "settings.txt");

        public List<string> VpnAdapters = new List<string>();
        public List<string> PinnedHosts = new List<string>
        {
            "api.anthropic.com",
            "a-api.anthropic.com",
            "claude.ai",
            "api.claude.ai",
            "claude.com",
            "platform.claude.com",
            "bridge.claudeusercontent.com",
            "console.anthropic.com",
            "statsig.anthropic.com",
            "mcp-proxy.anthropic.com",
            "downloads.claude.ai"
        };
        public List<string> CriticalHosts = new List<string> { "api.anthropic.com", "claude.ai" };
        public List<string> ProxiedHosts = DefaultProxiedHosts();
        public List<string> ExtraExecutables = new List<string>();
        public bool Notifications = true;
        public bool ProtectionEnabled = true;

        public bool HasVpnAdapters
        {
            get { return VpnAdapters.Count > 0; }
        }

        public static bool FileExists
        {
            get { return File.Exists(FilePath); }
        }

        public static AppSettings Load()
        {
            return LoadFrom(FilePath);
        }

        public static AppSettings LoadFrom(string path)
        {
            var settings = new AppSettings();
            if (!File.Exists(path)) return settings;
            try
            {
                foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
                {
                    if (line.TrimStart().StartsWith("#")) continue;
                    int separator = line.IndexOf(KeyValueSeparator);
                    if (separator <= 0) continue;
                    settings.Apply(line.Substring(0, separator).Trim(), line.Substring(separator + 1).Trim());
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
            return settings;
        }

        public bool TrySave()
        {
            var content = new StringBuilder();
            AppendLine(content, VpnAdaptersKey, Join(VpnAdapters));
            AppendLine(content, PinnedHostsKey, Join(PinnedHosts));
            AppendLine(content, CriticalHostsKey, Join(CriticalHosts));
            AppendLine(content, ProxiedHostsKey, Join(ProxiedHosts));
            AppendLine(content, ExtraExecutablesKey, Join(ExtraExecutables));
            AppendLine(content, NotificationsKey, Notifications ? "1" : "0");
            AppendLine(content, ProtectionEnabledKey, ProtectionEnabled ? "1" : "0");
            try
            {
                Directory.CreateDirectory(AppIdentity.DataDirectory);
                File.WriteAllText(FilePath, content.ToString(), new UTF8Encoding(false));
                return true;
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        public bool IsVpnAdapter(string description)
        {
            if (string.IsNullOrEmpty(description)) return false;
            foreach (string match in VpnAdapters)
            {
                if (description.IndexOf(match, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }

        private void Apply(string key, string value)
        {
            if (Is(key, VpnAdaptersKey)) VpnAdapters = ParseList(value);
            else if (Is(key, PinnedHostsKey)) PinnedHosts = ParseList(value);
            else if (Is(key, CriticalHostsKey)) CriticalHosts = ParseList(value);
            else if (Is(key, ProxiedHostsKey)) ProxiedHosts = UpgradeProxiedHosts(ParseList(value));
            else if (Is(key, ExtraExecutablesKey)) ExtraExecutables = ParseList(value);
            else if (Is(key, NotificationsKey)) Notifications = value != "0";
            else if (Is(key, ProtectionEnabledKey)) ProtectionEnabled = value != "0";
        }

        private static List<string> DefaultProxiedHosts()
        {
            return new List<string>
            {
                "hcaptcha.com",
                "js.hcaptcha.com",
                "api.hcaptcha.com",
                "newassets.hcaptcha.com",
                "imgs.hcaptcha.com",
                "api.statsigcdn.com"
            };
        }

        private static List<string> UpgradeProxiedHosts(List<string> saved)
        {
            bool firstDefault = saved.Count == FirstProxiedDefault.Length
                && saved.TrueForAll(host => Array.Exists(FirstProxiedDefault, known => string.Equals(known, host, StringComparison.OrdinalIgnoreCase)));
            return firstDefault ? DefaultProxiedHosts() : saved;
        }

        public static List<string> ParseList(string value)
        {
            var items = new List<string>();
            foreach (string item in value.Split(ListSeparator, '\n', '\r'))
            {
                string trimmed = item.Trim();
                if (trimmed.Length > 0 && !items.Contains(trimmed)) items.Add(trimmed);
            }
            return items;
        }

        private static string Join(List<string> items)
        {
            return string.Join(ListSeparator.ToString(), items);
        }

        private static bool Is(string key, string expected)
        {
            return string.Equals(key, expected, StringComparison.OrdinalIgnoreCase);
        }

        private static void AppendLine(StringBuilder content, string key, string value)
        {
            content.Append(key).Append(KeyValueSeparator).Append(value).Append(Environment.NewLine);
        }
    }
}
