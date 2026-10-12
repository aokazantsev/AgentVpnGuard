using System;
using System.Collections.Generic;

namespace AgentVpnGuard
{
    internal static class HostsChange
    {
        private const int MaxNames = 3;

        public static string Describe(Dictionary<string, string> before, Dictionary<string, string> after, bool vpnOff)
        {
            var added = new List<string>();
            var removed = new List<string>();
            var blocked = new List<string>();
            var moved = new List<string>();
            foreach (KeyValuePair<string, string> pair in after)
            {
                string previous;
                if (!before.TryGetValue(pair.Key, out previous)) added.Add(pair.Key);
                else if (previous == pair.Value) continue;
                else if (pair.Value == HostsPinner.BlackholeAddress) blocked.Add(pair.Key);
                else moved.Add(pair.Key + " → " + pair.Value);
            }
            foreach (string host in before.Keys)
            {
                if (!after.ContainsKey(host)) removed.Add(host);
            }

            var parts = new List<string>();
            if (added.Count > 0) parts.Add("добавлены " + NameList(added));
            if (removed.Count > 0) parts.Add("убраны " + NameList(removed));
            if (blocked.Count > 0) parts.Add("закрыты (нет адреса через VPN) " + NameList(blocked));
            if (moved.Count > 0) parts.Add("новый адрес через VPN: " + NameList(moved));
            if (parts.Count == 0) return "Файл hosts: восстановлен блок программы — его изменили извне";
            string text = "Файл hosts: " + string.Join("; ", parts);
            return vpnOff && removed.Count > 0 ? text + " — VPN выключен, к этим адресам ходят напрямую" : text;
        }

        private static string NameList(List<string> names)
        {
            if (names.Count <= MaxNames) return string.Join(", ", names);
            return string.Join(", ", names.GetRange(0, MaxNames)) + " и ещё " + (names.Count - MaxNames);
        }
    }
}
