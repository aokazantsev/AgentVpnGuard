using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;

namespace AgentVpnGuard
{
    internal static class ClaudeProcesses
    {
        public static Dictionary<int, string> Running(ICollection<string> knownExecutables)
        {
            var names = new HashSet<string>(ClaudeExecutables.ProcessNames, StringComparer.OrdinalIgnoreCase);
            foreach (string executable in knownExecutables) names.Add(System.IO.Path.GetFileNameWithoutExtension(executable));

            var running = new Dictionary<int, string>();
            foreach (Process process in Process.GetProcesses())
            {
                using (process)
                {
                    if (!names.Contains(process.ProcessName)) continue;
                    string path = PathOf(process);
                    if (path == null) continue;
                    if (knownExecutables.Contains(path) || ClaudeExecutables.LooksLikeClaude(path)) running[process.Id] = path;
                }
            }
            return running;
        }

        private static string PathOf(Process process)
        {
            try
            {
                return process.MainModule.FileName;
            }
            catch (Win32Exception)
            {
                return null;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
            catch (NullReferenceException)
            {
                return null;
            }
        }
    }
}
