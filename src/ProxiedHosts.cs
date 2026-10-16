using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace AgentVpnGuard
{
    internal sealed class ProxiedHosts
    {
        private const int DnsTimeoutMs = 2000;
        private const int MaxNamesInNotice = 3;
        private const int FailuresBeforeUnpin = 2;
        private const string ThroughVpn = "через VPN";
        private const string ThroughProxy = "через прокси VPN";
        private static readonly TimeSpan RefreshInterval = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(30);

        private Dictionary<string, string> pins = NewMap();
        private Dictionary<string, string> routes = NewMap();
        private Dictionary<string, string> failures = NewMap();
        private Dictionary<string, int> strikes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> notices = new List<string>();
        private DateTime nextRefreshUtc = DateTime.MinValue;
        private bool running;
        private int generation;

        public void Reset()
        {
            generation++;
            running = false;
            pins = NewMap();
            routes = NewMap();
            failures = NewMap();
            strikes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            notices.Clear();
            nextRefreshUtc = DateTime.MinValue;
        }

        public void Seed(List<string> hosts, Dictionary<string, string> known, string proxyPin)
        {
            foreach (string host in hosts)
            {
                string address;
                if (!known.TryGetValue(host, out address) || address == HostsPinner.BlackholeAddress) continue;
                pins[host] = address;
                routes[host] = address == proxyPin ? ThroughProxy : ThroughVpn;
            }
        }

        public void Restart()
        {
            generation++;
            running = false;
            nextRefreshUtc = DateTime.MinValue;
        }

        public void Refresh(List<string> hosts, NetworkAdapter vpn, string proxyPin, DateTime now, Action<Action> post, Action changed)
        {
            if (hosts.Count == 0 || vpn == null || running || now < nextRefreshUtc) return;
            if (vpn.DnsServers.Count == 0 || vpn.Ipv4Address == null) return;
            IPAddress proxy;
            if (proxyPin == null || proxyPin == HostsPinner.BlackholeAddress || !IPAddress.TryParse(proxyPin, out proxy)) proxy = null;
            running = true;
            int started = generation;
            var targets = new List<string>(hosts);
            var servers = new List<IPAddress>(vpn.DnsServers);
            IPAddress vpnAddress = vpn.Ipv4Address;
            int vpnIndex = vpn.Ipv4Index;
            ThreadPool.QueueUserWorkItem(state =>
            {
                var found = NewMap();
                var how = NewMap();
                var problems = NewMap();
                foreach (string host in targets)
                {
                    try
                    {
                        Resolve(host, servers, vpnAddress, vpnIndex, proxy, found, how, problems);
                    }
                    catch (Exception error)
                    {
                        AppLog.Append("proxied " + host + " failed: " + error);
                        problems[host] = error.Message;
                    }
                }
                post(() =>
                {
                    if (started != generation)
                    {
                        changed();
                        return;
                    }
                    running = false;
                    bool kept = KeepAfterSingleFailure(targets, found, how, problems);
                    LogChanges(targets, found, how, problems);
                    pins = found;
                    routes = how;
                    failures = problems;
                    nextRefreshUtc = DateTime.UtcNow + (problems.Count == 0 && !kept ? RefreshInterval : RetryInterval);
                    changed();
                });
            });
        }

        private bool KeepAfterSingleFailure(List<string> hosts, Dictionary<string, string> found, Dictionary<string, string> how, Dictionary<string, string> problems)
        {
            bool kept = false;
            var counted = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (string host in hosts)
            {
                string previous;
                string problem;
                if (found.ContainsKey(host) || !problems.TryGetValue(host, out problem) || !pins.TryGetValue(host, out previous)) continue;
                int count;
                strikes.TryGetValue(host, out count);
                count++;
                if (count >= FailuresBeforeUnpin) continue;
                counted[host] = count;
                found[host] = previous;
                how[host] = routes[host];
                problems.Remove(host);
                AppLog.Append("proxied " + host + " check failed once, kept: " + problem);
                kept = true;
            }
            strikes = counted;
            return kept;
        }

        public void AddTo(List<string> current, List<string> hosts, Dictionary<string, string> addresses)
        {
            foreach (KeyValuePair<string, string> pair in pins)
            {
                if (!current.Exists(host => string.Equals(host, pair.Key, StringComparison.OrdinalIgnoreCase))) continue;
                if (hosts.Exists(host => string.Equals(host, pair.Key, StringComparison.OrdinalIgnoreCase))) continue;
                hosts.Add(pair.Key);
                addresses[pair.Key] = pair.Value;
            }
        }

        public void Describe(List<string> hosts, List<string> details)
        {
            var separate = new List<string>();
            string proxyAddress = null;
            int viaProxy = 0;
            int pending = 0;
            foreach (string host in hosts)
            {
                string address;
                string failure;
                if (pins.TryGetValue(host, out address))
                {
                    if (routes[host] == ThroughProxy)
                    {
                        viaProxy++;
                        proxyAddress = address;
                    }
                    else
                    {
                        separate.Add(host + " → " + address + " (" + routes[host] + ")");
                    }
                }
                else if (failures.TryGetValue(host, out failure))
                {
                    separate.Add(host + ": не идёт через VPN — " + failure);
                }
                else
                {
                    pending++;
                }
            }
            if (viaProxy > 0) details.Add("Через прокси VPN " + proxyAddress + ": имён " + viaProxy + " из " + hosts.Count);
            if (pending > 0) details.Add("Проверяю путь через VPN, имён: " + pending);
            details.AddRange(separate);
        }

        private static void Resolve(string host, List<IPAddress> servers, IPAddress vpnAddress, int vpnIndex, IPAddress proxy,
            Dictionary<string, string> found, Dictionary<string, string> how, Dictionary<string, string> problems)
        {
            foreach (IPAddress server in servers)
            {
                List<IPAddress> answers;
                try
                {
                    answers = DnsResolver.QueryA(server, host, DnsTimeoutMs);
                }
                catch (SocketException)
                {
                    continue;
                }
                if (answers.Count == 0) continue;
                IPAddress routed = answers.Find(address => RouteInspector.BestInterfaceIndex(address) == vpnIndex);
                if (routed != null)
                {
                    found[host] = routed.ToString();
                    how[host] = ThroughVpn;
                    return;
                }
                break;
            }
            if (proxy == null)
            {
                problems[host] = "адрес прокси VPN ещё не известен";
                return;
            }
            string detail;
            if (ProxyProbe.Serves(proxy, vpnAddress, vpnIndex, host, out detail))
            {
                found[host] = proxy.ToString();
                how[host] = ThroughProxy;
                return;
            }
            problems[host] = detail;
        }

        public bool TakeNotices(List<string> events)
        {
            if (notices.Count == 0) return false;
            events.AddRange(notices);
            notices.Clear();
            return true;
        }

        private void LogChanges(List<string> hosts, Dictionary<string, string> found, Dictionary<string, string> how, Dictionary<string, string> problems)
        {
            var recovered = new List<string>();
            var lost = new Dictionary<string, List<string>>();
            foreach (string host in hosts)
            {
                string before;
                string after;
                string problem;
                string previousProblem;
                pins.TryGetValue(host, out before);
                found.TryGetValue(host, out after);
                bool failedBefore = failures.TryGetValue(host, out previousProblem);
                if (after != null)
                {
                    if (after != before) AppLog.Append("proxied " + host + " → " + after + " (" + how[host] + ")");
                    if (failedBefore) recovered.Add(host);
                    continue;
                }
                if (!problems.TryGetValue(host, out problem)) continue;
                bool repeated = before == null && failedBefore && previousProblem == problem;
                if (!repeated) AppLog.Append("proxied " + host + " not pinned: " + problem);
                if (failedBefore) continue;
                string key = (before != null ? "убраны " : "не добавлены ") + "	" + problem;
                List<string> group;
                if (!lost.TryGetValue(key, out group))
                {
                    group = new List<string>();
                    lost[key] = group;
                }
                group.Add(host);
            }
            foreach (KeyValuePair<string, List<string>> pair in lost)
            {
                string[] parts = pair.Key.Split('	');
                notices.Add("Файл hosts: " + parts[0] + NameList(pair.Value) + " — " + parts[1]
                    + ". Пока так, Claude к ним не попадёт, браузеры ходят к ним напрямую");
            }
            if (recovered.Count > 0)
            {
                notices.Add("Файл hosts: " + NameList(recovered) + " — снова через прокси VPN, записи возвращены");
            }
        }

        private static string NameList(List<string> names)
        {
            if (names.Count <= MaxNamesInNotice) return string.Join(", ", names);
            return string.Join(", ", names.GetRange(0, MaxNamesInNotice)) + " и ещё " + (names.Count - MaxNamesInNotice);
        }

        private static Dictionary<string, string> NewMap()
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }
}
