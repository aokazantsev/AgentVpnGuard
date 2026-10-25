using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace AgentVpnGuard
{
    internal static class UninstallProfile
    {
        private const int FirewallTimeoutMs = 60 * 1000;

        public const string ConfirmDetails =
            "Снимутся правила брандмауэра и блок в hosts: Claude снова сможет выходить в сеть без VPN.";

        public static void Remove(List<string> problems)
        {
            string firewallProblem = RemoveFirewallRules();
            if (firewallProblem != null)
            {
                problems.Add("правила брандмауэра (группа «" + AppIdentity.FirewallGroup + "») не сняты: " + firewallProblem
                    + ". Пока они стоят, у Claude нет сети вне VPN: удали правила группы в «Брандмауэр Защитника Windows» или установи программу заново и удали ещё раз");
            }
            try
            {
                HostsPinner.OwnHosts = AppSettings.Load().HostsFileHosts();
                HostsPinner.Remove();
            }
            catch (IOException error)
            {
                problems.Add("блок в hosts не снят: " + error.Message);
            }
            catch (UnauthorizedAccessException error)
            {
                problems.Add("блок в hosts не снят: " + error.Message);
            }
        }

        private static string RemoveFirewallRules()
        {
            string script = "$ErrorActionPreference='Stop'; "
                + "Get-NetFirewallRule -Group '" + AppIdentity.FirewallGroup + "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; "
                + "Get-NetFirewallRule -Group '" + AppIdentity.LegacyName + "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
                + "if (Get-NetFirewallRule -Group '" + AppIdentity.FirewallGroup + "' -ErrorAction SilentlyContinue) { exit 3 }";
            var start = new ProcessStartInfo(SystemTools.PowerShell, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + script + "\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            try
            {
                using (Process process = Process.Start(start))
                {
                    if (!process.WaitForExit(FirewallTimeoutMs))
                    {
                        try
                        {
                            process.Kill();
                        }
                        catch (Win32Exception)
                        {
                        }
                        catch (InvalidOperationException)
                        {
                        }
                        return "PowerShell не ответил за " + FirewallTimeoutMs / 1000 + " с";
                    }
                    return process.ExitCode == 0 ? null : "PowerShell завершился с кодом " + process.ExitCode;
                }
            }
            catch (Win32Exception error)
            {
                return error.Message;
            }
            catch (InvalidOperationException error)
            {
                return error.Message;
            }
        }
    }
}
