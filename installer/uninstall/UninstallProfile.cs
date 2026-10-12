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
            if (firewallProblem != null) problems.Add("правила брандмауэра (группа «" + AppIdentity.FirewallGroup + "») не сняты: " + firewallProblem);
            try
            {
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
                + "if (Get-NetFirewallRule -Group '" + AppIdentity.FirewallGroup + "' -ErrorAction SilentlyContinue) { exit 3 }";
            var start = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + script + "\"")
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
                        process.Kill();
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
