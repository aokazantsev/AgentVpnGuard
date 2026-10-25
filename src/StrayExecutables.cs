using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace AgentVpnGuard
{
    internal static class StrayExecutables
    {
        private const int ReadAttempts = 5;
        private const int ReadRetryMs = 200;

        private static readonly string FilePath = Path.Combine(AppIdentity.DataDirectory, "stray-executables.txt");
        private static bool unread;

        public static List<string> Load()
        {
            var paths = new List<string>();
            if (!File.Exists(FilePath)) return paths;
            string[] lines = null;
            for (int attempt = 1; lines == null; attempt++)
            {
                string failure = null;
                try
                {
                    lines = File.ReadAllLines(FilePath, Encoding.UTF8);
                }
                catch (IOException error)
                {
                    failure = error.Message;
                }
                catch (UnauthorizedAccessException error)
                {
                    failure = error.Message;
                }
                if (lines != null) break;
                if (attempt >= ReadAttempts)
                {
                    AppLog.Append("stray executables not read: " + failure);
                    unread = true;
                    return paths;
                }
                Thread.Sleep(ReadRetryMs);
            }
            foreach (string line in lines)
            {
                string path = line.Trim();
                if (path.Length == 0 || path.IndexOfAny(Path.GetInvalidPathChars()) >= 0) continue;
                if (ClaudeExecutables.LooksLikeClaude(path)) paths.Add(path);
            }
            return paths;
        }

        public static void Save(IEnumerable<string> paths)
        {
            if (unread)
            {
                AppLog.Append("stray executables not saved: the list was not read at start");
                return;
            }
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
