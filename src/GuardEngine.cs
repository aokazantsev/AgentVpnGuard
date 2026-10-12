using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Threading;

namespace AgentVpnGuard
{
    internal sealed class GuardEngine
    {
        private const int DnsTimeoutMs = 2000;
        private const int LeakTicksBeforeAlarm = 2;
        private const int TracedEvaluations = 3;
        private static readonly TimeSpan FullSyncInterval = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan VerifyInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan DnsRefreshInterval = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan DnsRetryInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan ProbeRetryInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan ConnectGrace = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan TeardownRetryInterval = TimeSpan.FromSeconds(30);

        private readonly Action<Action> post;
        private readonly Action changed;
        private AppSettings settings;
        private Dictionary<string, string> pins;
        private Dictionary<string, string> written;
        private string lastSignature;
        private DateTime lastFullSyncUtc = DateTime.MinValue;
        private DateTime nextDnsRefreshUtc = DateTime.MinValue;
        private DateTime lastProbeUtc = DateTime.MinValue;
        private bool dnsRefreshRunning;
        private bool probeRunning;
        private ProbeOutcome? probeOutcome;
        private string probeDetail;
        private bool wasVpnUp;
        private DateTime vpnUpSinceUtc = DateTime.MinValue;
        private bool firstEvaluation = true;
        private int leakTicks;
        private int evaluations;
        private bool firewallRunning;
        private bool firewallFailureReported;
        private bool firewallSynced;
        private bool firewallDrift;
        private DateTime lastVerifyUtc = DateTime.MinValue;
        private List<string> appliedInterfaces = new List<string>();
        private List<string> firewallProblems = new List<string>();
        private readonly List<string> firewallEvents = new List<string>();
        private bool teardownDone;
        private DateTime lastTeardownUtc = DateTime.MinValue;
        private List<string> teardownProblems = new List<string>();
        private readonly ProxiedHosts proxied = new ProxiedHosts();

        public GuardEngine(AppSettings settings, Action<Action> post, Action changed)
        {
            this.settings = settings;
            this.post = post;
            this.changed = changed;
            pins = SafeReadPins();
            written = new Dictionary<string, string>(pins, StringComparer.OrdinalIgnoreCase);
        }

        public void RetryFirewall()
        {
            lastSignature = null;
            lastFullSyncUtc = DateTime.MinValue;
            lastTeardownUtc = DateTime.MinValue;
        }

        public void Reconfigure(AppSettings newSettings)
        {
            settings = newSettings;
            lastSignature = null;
            nextDnsRefreshUtc = DateTime.MinValue;
            lastProbeUtc = DateTime.MinValue;
            probeOutcome = null;
            teardownDone = false;
            lastTeardownUtc = DateTime.MinValue;
            teardownProblems = new List<string>();
            proxied.Reset();
        }

        public GuardReport Evaluate(bool forceFullSync)
        {
            var report = new GuardReport();
            DateTime now = DateTime.UtcNow;
            evaluations++;
            AppLog.TraceEnabled = evaluations <= TracedEvaluations;
            Trace("evaluate #" + evaluations + ", force=" + forceFullSync + ", protection=" + settings.ProtectionEnabled);
            if (!IsElevated())
            {
                report.Status = GuardStatus.Broken;
                report.Headline = "Нет прав администратора — защита не обслуживается";
                report.Problems.Add(report.Headline);
                return report;
            }
            if (!settings.ProtectionEnabled) return EvaluateDisabled(report, now);

            AdapterSnapshot adapters = AdapterInventory.Read(settings);
            foreach (NetworkAdapter adapter in adapters.Adapters)
            {
                Trace("adapter " + adapter.Name + " | " + adapter.Description + " | vpn=" + adapter.IsVpn + ", present=" + adapter.IsPresent
                    + ", up=" + adapter.IsUp + ", addresses=" + adapter.Addresses.Count + ", dns=" + adapter.DnsServers.Count + ", index=" + adapter.Ipv4Index);
            }
            SortedSet<string> executables = ClaudeExecutables.Find(settings);
            Trace("executables: " + executables.Count + (executables.Count > 0 ? " — " + string.Join("; ", executables) : ""));
            Dictionary<int, string> running = ClaudeProcesses.Running(executables);
            Trace("running claude processes: " + running.Count);
            foreach (string path in running.Values)
            {
                if (executables.Add(path)) report.Events.Add("Найден запущенный Claude вне известных папок: " + path);
            }
            report.Executables.AddRange(executables);

            SyncFirewall(report, executables, adapters, forceFullSync, now);
            Trace("firewall done, problems=" + report.Problems.Count);
            NetworkAdapter vpn = adapters.ActiveVpn;
            Trace("active vpn: " + (vpn == null ? "none" : vpn.Name));
            TrackVpn(report, vpn, now);
            RefreshPins(vpn, now);
            Trace("dns refresh: running=" + dnsRefreshRunning);
            RefreshProxied(vpn, now);
            WritePins(report, vpn);
            Trace("hosts done");
            AuditConnections(report, running, adapters);
            Trace("connections audited");
            StartProbe(vpn, now);
            Classify(report, adapters, vpn, now);
            Trace("classified: " + report.Status + " — " + report.Headline);
            firstEvaluation = false;
            return report;
        }

        private void SyncFirewall(GuardReport report, SortedSet<string> executables, AdapterSnapshot adapters, bool forceFullSync, DateTime now)
        {
            bool cutOff = probeOutcome != ProbeOutcome.Reachable;
            List<string> interfaces = adapters.BlockedInterfaceNames(cutOff);
            string signature = string.Join("|", executables) + "#" + string.Join("|", interfaces);
            string serviceProblem = FirewallHealth.ServiceProblem();
            if (serviceProblem != null)
            {
                lastSignature = null;
                firewallSynced = false;
                report.Problems.Add("Защита не работает: " + serviceProblem);
                return;
            }
            foreach (string profile in FirewallHealth.DisabledProfiles()) report.Problems.Add("Защита не работает: " + profile);
            report.Problems.AddRange(firewallProblems);
            report.Events.AddRange(firewallEvents);
            firewallEvents.Clear();
            if (signature != lastSignature) firewallSynced = false;
            if (firewallRunning) return;

            bool inputsChanged = signature != lastSignature;
            bool syncDue = forceFullSync || inputsChanged || firewallDrift || now - lastFullSyncUtc > FullSyncInterval;
            bool verifyDue = firewallSynced && now - lastVerifyUtc > VerifyInterval;
            if (!syncDue && !verifyDue) return;

            var request = new FirewallRequest { VerifyOnly = !syncDue, Trace = AppLog.TraceEnabled };
            request.Executables.AddRange(executables);
            request.Interfaces.AddRange(interfaces);
            request.AppliedInterfaces.AddRange(appliedInterfaces);
            bool announceAdded = !firstEvaluation;
            bool announceRepaired = !inputsChanged;
            firewallRunning = true;
            if (syncDue) lastFullSyncUtc = now;
            lastVerifyUtc = now;
            Trace("fw: worker started, " + (request.VerifyOnly ? "verify" : "sync"));
            FirewallClient.RunAsync(request, (result, failure) => post(() => OnFirewallDone(request, signature, announceAdded, announceRepaired, result, failure)));
        }

        private GuardReport EvaluateDisabled(GuardReport report, DateTime now)
        {
            firstEvaluation = false;
            if (!teardownDone && !firewallRunning && now - lastTeardownUtc > TeardownRetryInterval) StartTeardown(now);
            report.Problems.AddRange(teardownProblems);
            if (report.Problems.Count > 0)
            {
                report.Status = GuardStatus.Broken;
                report.Headline = "Защита выключена, но не снята: " + report.Problems[0];
                return report;
            }
            report.Status = GuardStatus.Offline;
            if (!teardownDone)
            {
                report.Headline = "Снимаю защиту…";
                report.Settling = true;
                return report;
            }
            report.Headline = "Защита выключена — Claude ходит в сеть напрямую";
            return report;
        }

        private void StartTeardown(DateTime now)
        {
            firewallRunning = true;
            lastTeardownUtc = now;
            AppLog.Append("protection off: removing firewall rules and hosts block");
            var request = new FirewallRequest { RemoveAll = true, Trace = AppLog.TraceEnabled };
            FirewallClient.RunAsync(request, (result, failure) => post(() => OnTeardownDone(result, failure)));
        }

        private void OnTeardownDone(FirewallSyncResult result, string failure)
        {
            firewallRunning = false;
            lastSignature = null;
            firewallSynced = false;
            appliedInterfaces = new List<string>();
            if (settings.ProtectionEnabled)
            {
                changed();
                return;
            }
            var problems = new List<string>();
            if (failure != null)
            {
                problems.Add("брандмауэр Windows не снял правила (" + failure + ")");
                ReportFirewallFailure(failure);
            }
            else
            {
                foreach (string error in result.Errors) problems.Add("брандмауэр: " + error);
            }
            string hostsProblem = RemoveHostsBlock();
            if (hostsProblem != null) problems.Add(hostsProblem);
            teardownProblems = problems;
            teardownDone = problems.Count == 0;
            if (teardownDone) AppLog.Append("protection off: rules removed " + result.Removed + ", hosts block cleared");
            else AppLog.Append("protection off failed: " + string.Join("; ", problems));
            changed();
        }

        private static string RemoveHostsBlock()
        {
            try
            {
                HostsPinner.Remove();
                return null;
            }
            catch (IOException error)
            {
                return "файл hosts не записывается: " + error.Message;
            }
            catch (UnauthorizedAccessException error)
            {
                return "файл hosts не записывается: " + error.Message;
            }
        }

        private void ReportFirewallFailure(string failure)
        {
            AppLog.Append("firewall worker failed: " + failure);
            if (firewallFailureReported) return;
            firewallFailureReported = true;
            ThreadPool.QueueUserWorkItem(state => CrashReport.Upload("firewall", failure));
        }

        private void OnFirewallDone(FirewallRequest request, string signature, bool announceAdded, bool announceRepaired, FirewallSyncResult result, string failure)
        {
            firewallRunning = false;
            if (failure != null)
            {
                ReportFirewallFailure(failure);
                firewallSynced = false;
                firewallDrift = false;
                lastSignature = signature;
                firewallProblems = new List<string> { "Брандмауэр Windows не принимает правила (" + failure + ") — защита не работает" };
                changed();
                return;
            }
            var problems = new List<string>();
            foreach (string error in result.Errors) problems.Add("Брандмауэр: " + error);
            problems.AddRange(result.PolicyProblems);
            firewallProblems = problems;
            if (request.VerifyOnly)
            {
                firewallDrift = result.Drift.Count > 0;
                if (firewallDrift) AppLog.Append("firewall drift: " + string.Join("; ", result.Drift));
            }
            else
            {
                firewallDrift = false;
                appliedInterfaces = result.AppliedInterfaces;
                lastSignature = signature;
                firewallSynced = result.Errors.Count == 0;
                if (result.Added > 0 && announceAdded) firewallEvents.Add("Под защиту взято программ: " + result.Added);
                if (result.Repaired > 0 && announceRepaired) firewallEvents.Add("Правила брандмауэра были изменены извне и восстановлены: " + result.Repaired);
            }
            changed();
        }

        private void TrackVpn(GuardReport report, NetworkAdapter vpn, DateTime now)
        {
            bool vpnUp = vpn != null;
            if (vpnUp && !wasVpnUp)
            {
                vpnUpSinceUtc = firstEvaluation ? DateTime.MinValue : now;
                nextDnsRefreshUtc = DateTime.MinValue;
                lastProbeUtc = DateTime.MinValue;
                probeOutcome = null;
                proxied.Reset();
                if (!firstEvaluation) report.Events.Add("VPN подключён");
            }
            if (!vpnUp && wasVpnUp)
            {
                probeOutcome = null;
                proxied.Reset();
                report.Events.Add("VPN отключён — у Claude нет сети");
            }
            wasVpnUp = vpnUp;
        }

        private void RefreshPins(NetworkAdapter vpn, DateTime now)
        {
            if (vpn == null || dnsRefreshRunning || now < nextDnsRefreshUtc || vpn.DnsServers.Count == 0) return;
            dnsRefreshRunning = true;
            var hosts = new List<string>(settings.PinnedHosts);
            if (!hosts.Contains(ClaudeProbe.Host)) hosts.Add(ClaudeProbe.Host);
            var servers = new List<IPAddress>(vpn.DnsServers);
            int vpnIndex = vpn.Ipv4Index;
            bool traced = evaluations <= TracedEvaluations;
            ThreadPool.QueueUserWorkItem(state =>
            {
                Dictionary<string, string> resolved;
                try
                {
                    if (traced) AppLog.Append("dns: asking " + string.Join(", ", servers) + " for " + hosts.Count + " names");
                    resolved = ResolveThroughVpn(hosts, servers, vpnIndex);
                    if (traced) AppLog.Append("dns: resolved " + resolved.Count + " of " + hosts.Count);
                }
                catch (Exception error)
                {
                    AppLog.Append("dns failed: " + error);
                    resolved = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                }
                post(() =>
                {
                    dnsRefreshRunning = false;
                    bool complete = resolved.Count == hosts.Count;
                    nextDnsRefreshUtc = DateTime.UtcNow + (complete ? DnsRefreshInterval : DnsRetryInterval);
                    foreach (KeyValuePair<string, string> pair in resolved) pins[pair.Key] = pair.Value;
                    changed();
                });
            });
        }

        private static Dictionary<string, string> ResolveThroughVpn(List<string> hosts, List<IPAddress> servers, int vpnIndex)
        {
            var resolved = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string host in hosts)
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
                    resolved[host] = routed == null ? HostsPinner.BlackholeAddress : routed.ToString();
                    break;
                }
            }
            return resolved;
        }

        private void RefreshProxied(NetworkAdapter vpn, DateTime now)
        {
            if (dnsRefreshRunning) return;
            string proxyPin;
            pins.TryGetValue(ClaudeProbe.Host, out proxyPin);
            proxied.Refresh(ProxiedOnly(), vpn, proxyPin, now, post, changed);
        }

        private List<string> ProxiedOnly()
        {
            var hosts = new List<string>();
            foreach (string host in settings.ProxiedHosts)
            {
                if (!settings.PinnedHosts.Exists(pinned => string.Equals(pinned, host, StringComparison.OrdinalIgnoreCase))) hosts.Add(host);
            }
            return hosts;
        }

        private void WritePins(GuardReport report, NetworkAdapter vpn)
        {
            var hosts = new List<string>(settings.PinnedHosts);
            var addresses = new Dictionary<string, string>(pins, StringComparer.OrdinalIgnoreCase);
            proxied.AddTo(hosts, addresses);
            bool explained = proxied.TakeNotices(report.Events);
            try
            {
                Dictionary<string, string> block = HostsPinner.Block(hosts, addresses);
                if (HostsPinner.Apply(hosts, addresses) && !firstEvaluation && !explained)
                {
                    report.Events.Add(HostsChange.Describe(written, block, vpn == null));
                }
                written = block;
            }
            catch (IOException error)
            {
                report.Problems.Add("Файл hosts не записывается: " + error.Message);
            }
            catch (UnauthorizedAccessException error)
            {
                report.Problems.Add("Файл hosts не записывается: " + error.Message);
            }
        }

        private void AuditConnections(GuardReport report, Dictionary<int, string> running, AdapterSnapshot adapters)
        {
            ConnectionAudit audit = ConnectionAuditor.Audit(running, adapters, true);
            if (audit.Leaks.Count == 0)
            {
                leakTicks = 0;
                return;
            }
            leakTicks++;
            report.Events.Add("Соединения Claude мимо VPN: " + string.Join(", ", audit.Leaks) + (audit.Closed > 0 ? " — закрыто " + audit.Closed : ""));
            if (leakTicks >= LeakTicksBeforeAlarm) report.Problems.Add("Claude открывает соединения мимо VPN: " + audit.Leaks[0]);
        }

        private void StartProbe(NetworkAdapter vpn, DateTime now)
        {
            TimeSpan interval = probeOutcome == ProbeOutcome.Reachable ? ProbeInterval : ProbeRetryInterval;
            if (vpn == null || probeRunning || now - lastProbeUtc < interval) return;
            string pinned;
            IPAddress target;
            IPAddress vpnAddress = vpn.Ipv4Address;
            if (!pins.TryGetValue(ClaudeProbe.Host, out pinned) || pinned == HostsPinner.BlackholeAddress
                || !IPAddress.TryParse(pinned, out target) || vpnAddress == null) return;
            probeRunning = true;
            lastProbeUtc = now;
            ClaudeProbe.CheckAsync(target, vpnAddress, vpn.Ipv4Index, (outcome, detail) => post(() =>
            {
                probeRunning = false;
                ProbeOutcome? previous = probeOutcome;
                probeOutcome = outcome;
                probeDetail = detail;
                if (previous != outcome)
                {
                    AppLog.Append("probe " + ClaudeProbe.Host + ": " + outcome + " — " + detail);
                    changed();
                }
            }));
        }

        private void Classify(GuardReport report, AdapterSnapshot adapters, NetworkAdapter vpn, DateTime now)
        {
            report.Details.Insert(0, "Программ под защитой: " + report.Executables.Count);
            if (report.Problems.Count > 0)
            {
                report.Status = GuardStatus.Broken;
                report.Headline = report.Problems[0];
                return;
            }
            if (!firewallSynced)
            {
                report.Status = GuardStatus.Offline;
                report.Headline = "Настраиваю брандмауэр…";
                report.Settling = true;
                return;
            }
            if (!settings.HasVpnAdapters || !adapters.HasVpnAdapter)
            {
                report.Status = GuardStatus.Warning;
                report.Headline = "Адаптер VPN не выбран — у Claude нет сети. Открой настройки";
                return;
            }
            if (vpn == null)
            {
                report.Status = GuardStatus.Offline;
                report.Headline = "VPN выключен — у Claude нет сети";
                return;
            }
            report.Details.Add("VPN: " + vpn.Name + " (" + vpn.Description + ")");
            var warnings = new List<string>();
            if (probeOutcome == ProbeOutcome.Bypass)
            {
                report.Details.Add("Проверка Claude: " + probeDetail);
                report.Status = GuardStatus.Broken;
                report.Headline = "Путь к Claude идёт мимо VPN — сеть Claude отключена";
                return;
            }
            if (probeOutcome == ProbeOutcome.Unreachable)
            {
                report.Details.Add("Проверка Claude: " + probeDetail);
                warnings.Add("Claude не отвечает через VPN — сеть Claude отключена");
            }
            else if (probeOutcome == ProbeOutcome.Reachable)
            {
                report.Details.Add("Проверка Claude: " + probeDetail + " отвечает через VPN");
            }
            foreach (string host in settings.CriticalHosts)
            {
                string address;
                bool known = pins.TryGetValue(host, out address);
                if (!known || address == HostsPinner.BlackholeAddress)
                {
                    report.Details.Add(host + ": нет адреса через VPN");
                    warnings.Add(dnsRefreshRunning || !known ? "Узнаю адреса Claude у DNS VPN…" : host + " недоступен через VPN");
                    continue;
                }
                bool routed = adapters.IsVpnInterface(RouteInspector.BestInterfaceIndex(IPAddress.Parse(address)));
                report.Details.Add(host + " → " + address + (routed ? " (через VPN)" : " (мимо VPN)"));
                if (!routed) warnings.Add(host + " идёт мимо VPN и заблокирован");
            }
            proxied.Describe(ProxiedOnly(), report.Details);
            if (warnings.Count > 0 && now - vpnUpSinceUtc < ConnectGrace)
            {
                report.Status = GuardStatus.Offline;
                report.Headline = "VPN подключается…";
                return;
            }
            if (warnings.Count > 0)
            {
                report.Status = GuardStatus.Warning;
                report.Headline = warnings[0];
                return;
            }
            if (probeOutcome == null)
            {
                report.Status = GuardStatus.Offline;
                report.Headline = "Проверяю доступ к Claude через VPN…";
                report.Settling = true;
                return;
            }
            report.Status = GuardStatus.Protected;
            report.Headline = "Claude работает только через VPN";
        }

        private static void Trace(string line)
        {
            AppLog.Trace(line);
        }

        private static Dictionary<string, string> SafeReadPins()
        {
            try
            {
                return HostsPinner.ReadPins();
            }
            catch (IOException)
            {
                return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
            catch (UnauthorizedAccessException)
            {
                return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private static bool IsElevated()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }
}
