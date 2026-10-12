using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Microsoft.Win32;

namespace AgentVpnGuard
{
    internal static class LegacyInstall
    {
        private const string UninstallKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\" + AppIdentity.LegacyName;
        private const string LegacyExecutableName = AppIdentity.LegacyName + ".exe";
        private const int CommandTimeoutMs = 60 * 1000;
        private const int ExitWaitMs = 5000;
        private const int DeleteAttempts = 10;
        private const int DeleteRetryMs = 500;
        private static readonly string[] DataFiles = { "settings.txt", "crash-reports-consent.txt", "log.txt", "log.old.txt" };

        private static string DataDirectory
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AppIdentity.LegacyName); }
        }

        public static void CopyData()
        {
            try
            {
                if (!Directory.Exists(DataDirectory) || File.Exists(Path.Combine(AppIdentity.DataDirectory, "settings.txt"))) return;
                Directory.CreateDirectory(AppIdentity.DataDirectory);
                foreach (string name in DataFiles)
                {
                    string source = Path.Combine(DataDirectory, name);
                    if (File.Exists(source)) File.Copy(source, Path.Combine(AppIdentity.DataDirectory, name), false);
                }
            }
            catch (IOException error)
            {
                SetupLog.Append("legacy data not copied: " + error.Message);
            }
            catch (UnauthorizedAccessException error)
            {
                SetupLog.Append("legacy data not copied: " + error.Message);
            }
        }

        public static void Remove(string target, List<string> notes)
        {
            string installed = InstalledLocation();
            bool present = installed != null || Directory.Exists(DataDirectory) || Process.GetProcessesByName(AppIdentity.LegacyName).Length > 0;
            SetupLog.Append("legacy " + AppIdentity.LegacyName + ": present=" + present + ", installed=" + (installed ?? "none"));
            if (!present) return;

            if (!StopProcesses()) notes.Add(AppIdentity.LegacyName + " не закрылся — закрой его в трее и удали папку " + (installed ?? "программы") + " вручную.");
            CopyData();
            Run("schtasks.exe", "/Delete /TN \"" + AppIdentity.LegacyName + "\" /F", "legacy autostart");
            int firewall = Run("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""
                + "Get-NetFirewallRule -Group '" + AppIdentity.LegacyName + "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\"", "legacy firewall");
            if (firewall != 0) notes.Add("Не сняты правила брандмауэра прежней версии (группа «" + AppIdentity.LegacyName + "»): PowerShell, код " + firewall + ".");
            Registry.LocalMachine.DeleteSubKeyTree(UninstallKeyPath, false);
            Registry.CurrentUser.DeleteSubKeyTree(UninstallKeyPath, false);
            SetupLog.Append("legacy registration removed");

            bool sameFolder = installed != null && string.Equals(Path.GetFullPath(installed).TrimEnd('\\'), Path.GetFullPath(target).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
            if (installed != null && !sameFolder && File.Exists(Path.Combine(installed, LegacyExecutableName)))
            {
                string problem = Delete(installed);
                if (problem != null) notes.Add("Папка прежней версии " + installed + " " + problem + ".");
            }
            string dataProblem = Delete(DataDirectory);
            if (dataProblem != null) notes.Add("Папка данных прежней версии " + DataDirectory + " " + dataProblem + ".");
            SetupLog.Append("legacy removed");
        }

        private static string InstalledLocation()
        {
            foreach (RegistryKey root in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                using (RegistryKey key = root.OpenSubKey(UninstallKeyPath))
                {
                    string location = key == null ? null : key.GetValue("InstallLocation") as string;
                    if (!string.IsNullOrEmpty(location)) return location;
                }
            }
            return null;
        }

        private static bool StopProcesses()
        {
            bool stoppedAll = true;
            foreach (Process process in Process.GetProcessesByName(AppIdentity.LegacyName))
            {
                using (process)
                {
                    try
                    {
                        process.Kill();
                        if (!process.WaitForExit(ExitWaitMs)) stoppedAll = false;
                    }
                    catch (Win32Exception)
                    {
                        stoppedAll = false;
                    }
                    catch (InvalidOperationException)
                    {
                    }
                }
            }
            SetupLog.Append("legacy process stopped: " + stoppedAll);
            return stoppedAll;
        }

        private static int Run(string program, string arguments, string step)
        {
            var start = new ProcessStartInfo(program, arguments) { UseShellExecute = false, CreateNoWindow = true };
            try
            {
                using (Process process = Process.Start(start))
                {
                    if (!process.WaitForExit(CommandTimeoutMs))
                    {
                        process.Kill();
                        SetupLog.Append(step + ": timeout");
                        return -1;
                    }
                    SetupLog.Append(step + ": exit " + process.ExitCode);
                    return process.ExitCode;
                }
            }
            catch (Win32Exception error)
            {
                SetupLog.Append(step + ": " + error.Message);
                return -1;
            }
        }

        private static string Delete(string directory)
        {
            if (!Directory.Exists(directory)) return null;
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    Directory.Delete(directory, true);
                    return null;
                }
                catch (IOException error)
                {
                    if (attempt >= DeleteAttempts) return "удалена не полностью (" + error.Message + ")";
                }
                catch (UnauthorizedAccessException error)
                {
                    if (attempt >= DeleteAttempts) return "удалена не полностью (" + error.Message + ")";
                }
                Thread.Sleep(DeleteRetryMs);
            }
        }
    }
}
