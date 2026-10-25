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
        private const int DeleteAttempts = 10;
        private const int DeleteRetryMs = 500;
        private static readonly string[] LegacyFiles = { LegacyExecutableName, LegacyExecutableName + ".config", AppIdentity.UninstallerName, "README.md", "LICENSE", "CHANGELOG.md" };
        private static readonly string[] DataFiles = { "settings.txt", "crash-reports-consent.txt", "log.txt", "log.old.txt" };

        private static string DataDirectory
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AppIdentity.LegacyName); }
        }

        public static string SettingsPath
        {
            get { return Path.Combine(DataDirectory, "settings.txt"); }
        }

        public static bool ConsentGiven
        {
            get { return File.Exists(Path.Combine(DataDirectory, "crash-reports-consent.txt")); }
        }

        public static void StopAndCopyData(List<string> notes)
        {
            if (!IsPresent(InstalledLocation())) return;
            if (!StopProcesses()) notes.Add(AppIdentity.LegacyName + " не закрылся — закрой его в трее и удали его папку вручную.");
            CopyData();
        }

        public static void DisableAutostart(List<string> notes)
        {
            if (!IsPresent(InstalledLocation())) return;
            if (Run(SystemTools.Schtasks, "/Query /TN \"" + AppIdentity.LegacyName + "\"", "legacy autostart query") != 0) return;
            int exitCode = Run(SystemTools.Schtasks, "/Delete /TN \"" + AppIdentity.LegacyName + "\" /F", "legacy autostart");
            if (exitCode != 0) notes.Add("Не снят автозапуск " + AppIdentity.LegacyName + " (schtasks, код " + exitCode + ") — удали задачу «" + AppIdentity.LegacyName + "» в Планировщике заданий.");
        }

        private static bool IsPresent(string installed)
        {
            return installed != null || Directory.Exists(DataDirectory) || Process.GetProcessesByName(AppIdentity.LegacyName).Length > 0;
        }

        private static void CopyData()
        {
            try
            {
                if (!Directory.Exists(DataDirectory) || File.Exists(AppSettings.FilePath)) return;
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

        public static void Remove(List<string> notes)
        {
            string installed = InstalledLocation();
            bool present = IsPresent(installed);
            SetupLog.Append("legacy " + AppIdentity.LegacyName + ": present=" + present + ", installed=" + (installed ?? "none"));
            if (!present) return;

            int firewall = Run(SystemTools.PowerShell, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""
                + "$ErrorActionPreference='Stop'; "
                + "Get-NetFirewallRule -Group '" + AppIdentity.LegacyName + "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; "
                + "if (Get-NetFirewallRule -Group '" + AppIdentity.LegacyName + "' -ErrorAction SilentlyContinue) { exit 3 }\"", "legacy firewall");
            if (firewall != 0) notes.Add("Не сняты правила брандмауэра прежней версии (группа «" + AppIdentity.LegacyName + "»): PowerShell, код " + firewall + ".");
            Registry.LocalMachine.DeleteSubKeyTree(UninstallKeyPath, false);
            SetupLog.Append("legacy registration removed");

            if (installed != null && Directory.Exists(installed) && !InstallFolder.IsMarked(installed))
            {
                try
                {
                    if (!InstallFolder.RemoveProgramFiles(installed, LegacyExecutableName, LegacyFiles))
                    {
                        notes.Add("Из папки прежней версии " + installed + " убраны файлы " + AppIdentity.LegacyName + ", остальные файлы в ней не тронуты.");
                    }
                }
                catch (IOException error)
                {
                    notes.Add("Папка прежней версии " + installed + " удалена не полностью (" + error.Message + ").");
                }
                catch (UnauthorizedAccessException error)
                {
                    notes.Add("Папка прежней версии " + installed + " удалена не полностью (" + error.Message + ").");
                }
            }
            string dataProblem = Delete(DataDirectory);
            if (dataProblem != null) notes.Add("Папка данных прежней версии " + DataDirectory + " " + dataProblem + ".");
            SetupLog.Append("legacy removed");
        }

        private static string InstalledLocation()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(UninstallKeyPath))
            {
                string location = key == null ? null : key.GetValue("InstallLocation") as string;
                return string.IsNullOrEmpty(location) ? null : location;
            }
        }

        private static bool StopProcesses()
        {
            bool stoppedAll = true;
            foreach (Process process in Process.GetProcessesByName(AppIdentity.LegacyName))
            {
                using (process)
                {
                    if (!RunningApp.Kill(process)) stoppedAll = false;
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
