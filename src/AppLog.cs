using System;
using System.IO;
using System.Text;

namespace AgentVpnGuard
{
    internal static class AppLog
    {
        private const long MaxBytes = 512 * 1024;

        public static readonly string FilePath = Path.Combine(AppIdentity.DataDirectory, "log.txt");
        private static readonly string PreviousFilePath = Path.Combine(AppIdentity.DataDirectory, "log.old.txt");

        public static bool TraceEnabled;

        public static void Trace(string line)
        {
            if (TraceEnabled) Append("  " + line);
        }

        public static void Append(string line)
        {
            try
            {
                Directory.CreateDirectory(AppIdentity.DataDirectory);
                var info = new FileInfo(FilePath);
                if (info.Exists && info.Length > MaxBytes)
                {
                    File.Copy(FilePath, PreviousFilePath, true);
                    File.Delete(FilePath);
                }
                File.AppendAllText(FilePath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + line + Environment.NewLine,
                    new UTF8Encoding(false));
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
