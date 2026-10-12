using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AgentVpnGuard
{
    internal sealed class KeyValueFile
    {
        private const char Separator = '=';

        private readonly List<KeyValuePair<string, string>> entries = new List<KeyValuePair<string, string>>();

        public void Add(string key, string value)
        {
            entries.Add(new KeyValuePair<string, string>(key, (value ?? "").Replace("\r", " ").Replace("\n", " ")));
        }

        public void Add(string key, bool value)
        {
            Add(key, value ? "1" : "0");
        }

        public void AddAll(string key, IEnumerable<string> values)
        {
            foreach (string value in values) Add(key, value);
        }

        public List<string> All(string key)
        {
            var values = new List<string>();
            foreach (KeyValuePair<string, string> entry in entries)
            {
                if (entry.Key == key) values.Add(entry.Value);
            }
            return values;
        }

        public bool Flag(string key)
        {
            List<string> values = All(key);
            return values.Count > 0 && values[0] == "1";
        }

        public int Number(string key)
        {
            List<string> values = All(key);
            int number;
            return values.Count > 0 && int.TryParse(values[0], out number) ? number : 0;
        }

        public void Save(string path)
        {
            var content = new StringBuilder();
            foreach (KeyValuePair<string, string> entry in entries) content.Append(entry.Key).Append(Separator).Append(entry.Value).Append('\n');
            File.WriteAllText(path, content.ToString(), new UTF8Encoding(false));
        }

        public static KeyValueFile Load(string path)
        {
            var file = new KeyValueFile();
            foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
            {
                int separator = line.IndexOf(Separator);
                if (separator <= 0) continue;
                file.entries.Add(new KeyValuePair<string, string>(line.Substring(0, separator), line.Substring(separator + 1)));
            }
            return file;
        }
    }
}
