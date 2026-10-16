using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AgentVpnGuard
{
    internal static class StrayExecutables
    {
        private static readonly string FilePath = Path.Combine(AppIdentity.DataDirectory, "stray-executables.txt");

        public static List<string> Load()
        {
            var paths = new List<string>();
            try
            {
                if (!File.Exists(FilePath)) return paths;
                foreach (string line in File.ReadAllLines(FilePath, Encoding.UTF8))
                {
                    string path = line.Trim();
                    if (path.Length == 0 || path.IndexOfAny(Path.GetInvalidPathChars()) >= 0) continue;
                    if (ClaudeExecutables.LooksLikeClaude(path)) paths.Add(path);
                }
            }
            catch (IOException error)
            {
                AppLog.Append("stray executables not read: " + error.Message);
            }
            catch (UnauthorizedAccessException error)
            {
                AppLog.Append("stray executables not read: " + error.Message);
            }
            return paths;
        }

        public static void Save(IEnumerable<string> paths)
        {
            try
            {
                File.WriteAllLines(FilePath, paths, new UTF8Encoding(false));
            }
            catch (IOException error)
            {
                AppLog.Append("stray executables not saved: " + error.Message);
            }
            catch (UnauthorizedAccessException error)
            {
                AppLog.Append("stray executables not saved: " + error.Message);
            }
        }
    }
}
