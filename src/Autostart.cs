using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace AgentVpnGuard
{
    internal static class Autostart
    {
        private const int CommandTimeoutMs = 15000;
        private const int CancelledByUser = 1223;
        private const int TaskNotFound = 1;

        public static bool IsEnabled()
        {
            return QueryTask() == 0;
        }

        public static string Enable(string executablePath)
        {
            string definitionPath = Path.Combine(Path.GetTempPath(), AppIdentity.Name + "-task-" + Guid.NewGuid().ToString("N") + ".xml");
            try
            {
                File.WriteAllText(definitionPath, Definition(executablePath), Encoding.Unicode);
                return Explain(RunSchtasks("/Create /TN \"" + AppIdentity.Name + "\" /XML \"" + definitionPath + "\" /F", !IsElevated()), "включить автозапуск");
            }
            catch (IOException error)
            {
                return "Не удалось включить автозапуск: " + error.Message;
            }
            catch (UnauthorizedAccessException error)
            {
                return "Не удалось включить автозапуск: " + error.Message;
            }
            finally
            {
                try
                {
                    File.Delete(definitionPath);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }

        public static string Disable()
        {
            if (QueryTask() == TaskNotFound) return null;
            return Explain(RunSchtasks("/Delete /TN \"" + AppIdentity.Name + "\" /F", !IsElevated()), "выключить автозапуск");
        }

        private static int QueryTask()
        {
            return RunSchtasks("/Query /TN \"" + AppIdentity.Name + "\"", false);
        }

        private static string Definition(string executablePath)
        {
            string user;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                user = SecurityElement.Escape(identity.Name);
            }
            string command = SecurityElement.Escape(executablePath);
            string directory = SecurityElement.Escape(Path.GetDirectoryName(executablePath));
            return "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
                + "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
                + "  <RegistrationInfo><Description>" + AppIdentity.Name + ": запуск при входе в Windows</Description></RegistrationInfo>\n"
                + "  <Triggers>\n"
                + "    <LogonTrigger><Enabled>true</Enabled><UserId>" + user + "</UserId><Delay>" + AppIdentity.AutostartDelay + "</Delay></LogonTrigger>\n"
                + "  </Triggers>\n"
                + "  <Principals>\n"
                + "    <Principal id=\"Author\"><UserId>" + user + "</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>\n"
                + "  </Principals>\n"
                + "  <Settings>\n"
                + "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
                + "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
                + "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
                + "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
                + "    <AllowHardTerminate>true</AllowHardTerminate>\n"
                + "    <StartWhenAvailable>true</StartWhenAvailable>\n"
                + "    <RestartOnFailure><Interval>PT1M</Interval><Count>10</Count></RestartOnFailure>\n"
                + "    <Enabled>true</Enabled>\n"
                + "  </Settings>\n"
                + "  <Actions Context=\"Author\">\n"
                + "    <Exec><Command>\"" + command + "\"</Command><WorkingDirectory>" + directory + "</WorkingDirectory></Exec>\n"
                + "  </Actions>\n"
                + "</Task>\n";
        }

        private static bool IsElevated()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static int RunSchtasks(string arguments, bool elevate)
        {
            var start = new ProcessStartInfo(SystemTools.Schtasks, arguments) { WindowStyle = ProcessWindowStyle.Hidden };
            if (elevate)
            {
                start.UseShellExecute = true;
                start.Verb = "runas";
            }
            else
            {
                start.UseShellExecute = false;
                start.CreateNoWindow = true;
            }
            try
            {
                using (Process process = Process.Start(start))
                {
                    if (process.WaitForExit(CommandTimeoutMs)) return process.ExitCode;
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
                    return -1;
                }
            }
            catch (Win32Exception error)
            {
                return error.NativeErrorCode == CancelledByUser ? CancelledByUser : -1;
            }
        }

        private static string Explain(int exitCode, string action)
        {
            if (exitCode == 0) return null;
            if (exitCode == CancelledByUser) return "Не удалось " + action + ": окно UAC отклонено.";
            return "Не удалось " + action + " (schtasks, код " + exitCode + ").";
        }
    }
}
