using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace AgentVpnGuard
{
    internal static class FirewallClient
    {
        private const int TimeoutMs = 60 * 1000;
        private static readonly TimeSpan StaleAge = TimeSpan.FromHours(1);

        public static void RemoveStaleFiles()
        {
            try
            {
                if (!Directory.Exists(AppIdentity.DataDirectory)) return;
                DateTime limit = DateTime.UtcNow - StaleAge;
                foreach (string pattern in new[] { "fw-*.request", "fw-*.result" })
                {
                    foreach (string path in Directory.GetFiles(AppIdentity.DataDirectory, pattern))
                    {
                        if (File.GetLastWriteTimeUtc(path) < limit) TryDelete(path);
                    }
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        public static void RunAsync(FirewallRequest request, Action<FirewallSyncResult, string> done)
        {
            ThreadPool.QueueUserWorkItem(state =>
            {
                FirewallSyncResult result = null;
                string failure;
                try
                {
                    failure = Run(request, out result);
                }
                catch (Exception error)
                {
                    failure = "не удалось запустить проверку: " + error.Message;
                }
                done(result, failure);
            });
        }

        private static string Run(FirewallRequest request, out FirewallSyncResult result)
        {
            result = null;
            string id = Guid.NewGuid().ToString("N");
            string requestPath = Path.Combine(AppIdentity.DataDirectory, "fw-" + id + ".request");
            string resultPath = Path.Combine(AppIdentity.DataDirectory, "fw-" + id + ".result");
            try
            {
                Directory.CreateDirectory(AppIdentity.DataDirectory);
                request.Save(requestPath);
                var start = new ProcessStartInfo(Application.ExecutablePath,
                    FirewallWorker.Argument + " \"" + requestPath + "\" \"" + resultPath + "\"")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = Path.GetDirectoryName(Application.ExecutablePath)
                };
                using (Process worker = Process.Start(start))
                {
                    if (!worker.WaitForExit(TimeoutMs))
                    {
                        TryKill(worker);
                        return "работа с брандмауэром зависла дольше " + TimeoutMs / 1000 + " с";
                    }
                    if (worker.ExitCode != FirewallWorker.Succeeded)
                    {
                        return "работа с брандмауэром упала, код 0x" + worker.ExitCode.ToString("X8", CultureInfo.InvariantCulture);
                    }
                }
                if (!File.Exists(resultPath)) return "работа с брандмауэром не вернула результат";
                result = FirewallSyncResult.Load(resultPath);
                return null;
            }
            finally
            {
                TryDelete(requestPath);
                TryDelete(resultPath);
            }
        }

        private static void TryKill(Process process)
        {
            try
            {
                process.Kill();
            }
            catch (InvalidOperationException)
            {
            }
            catch (Win32Exception)
            {
            }
        }

        private static void TryDelete(string path)
        {
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
