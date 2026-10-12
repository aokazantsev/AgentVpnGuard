using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace AgentVpnGuard
{
    internal static class UserJournal
    {
        private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";
        private const char Separator = '\t';
        private const long MaxBytes = 256 * 1024;
        private const int KeptAfterTrim = 500;

        public static readonly string FilePath = Path.Combine(AppIdentity.DataDirectory, "events.txt");

        public static event Action<JournalEntry> Added;

        public static void Append(GuardStatus? status, string text)
        {
            var entry = new JournalEntry { Time = DateTime.Now, Status = status, Text = text.Replace('\t', ' ').Replace("\r", "").Replace('\n', ' ') };
            try
            {
                Directory.CreateDirectory(AppIdentity.DataDirectory);
                TrimIfLarge();
                File.AppendAllText(FilePath, Format(entry) + Environment.NewLine, new UTF8Encoding(false));
            }
            catch (IOException error)
            {
                AppLog.Append("journal not written: " + error.Message);
            }
            catch (UnauthorizedAccessException error)
            {
                AppLog.Append("journal not written: " + error.Message);
            }
            if (Added != null) Added(entry);
        }

        public static List<JournalEntry> ReadAll()
        {
            var entries = new List<JournalEntry>();
            try
            {
                if (!File.Exists(FilePath)) return entries;
                foreach (string line in File.ReadAllLines(FilePath, Encoding.UTF8))
                {
                    JournalEntry entry = Parse(line);
                    if (entry != null) entries.Add(entry);
                }
            }
            catch (IOException error)
            {
                AppLog.Append("journal not read: " + error.Message);
            }
            catch (UnauthorizedAccessException error)
            {
                AppLog.Append("journal not read: " + error.Message);
            }
            return entries;
        }

        private static void TrimIfLarge()
        {
            var info = new FileInfo(FilePath);
            if (!info.Exists || info.Length <= MaxBytes) return;
            string[] lines = File.ReadAllLines(FilePath, Encoding.UTF8);
            int skip = Math.Max(0, lines.Length - KeptAfterTrim);
            var kept = new string[lines.Length - skip];
            Array.Copy(lines, skip, kept, 0, kept.Length);
            File.WriteAllLines(FilePath, kept, new UTF8Encoding(false));
        }

        private static string Format(JournalEntry entry)
        {
            return entry.Time.ToString(TimeFormat, CultureInfo.InvariantCulture) + Separator
                + (entry.Status.HasValue ? entry.Status.Value.ToString() : "") + Separator + entry.Text;
        }

        private static JournalEntry Parse(string line)
        {
            string[] parts = line.Split(new[] { Separator }, 3);
            if (parts.Length < 3) return null;
            DateTime time;
            if (!DateTime.TryParseExact(parts[0], TimeFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out time)) return null;
            GuardStatus status;
            GuardStatus? parsed = Enum.TryParse(parts[1], out status) ? status : (GuardStatus?)null;
            return new JournalEntry { Time = time, Status = parsed, Text = parts[2] };
        }
    }
}
