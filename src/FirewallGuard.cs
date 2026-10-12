using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

namespace AgentVpnGuard
{
    internal static class FirewallGuard
    {
        private const int DirectionOut = 2;
        private const int ActionBlock = 0;
        private const int ProtocolAny = 256;
        private const int ProfilesAll = 0x7FFFFFFF;
        private const int ModifyStateGroupPolicyOverride = 1;
        private const int RemovePasses = 3;

        public static string RuleName(string executable)
        {
            return AppIdentity.Name + ": " + executable;
        }

        public static FirewallSyncResult Sync(FirewallRequest request)
        {
            var result = new FirewallSyncResult();
            AppLog.Trace("fw: opening policy");
            dynamic policy = OpenPolicy();
            AppLog.Trace("fw: reading rules");
            dynamic rules = policy.Rules;
            Dictionary<string, dynamic> existing = OwnRules(rules);
            AppLog.Trace("fw: own rules " + existing.Count);

            List<string> interfaces = request.Interfaces;
            var desiredNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (string executable in request.Executables)
            {
                string name = RuleName(executable);
                desiredNames.Add(name);
                dynamic rule;
                bool isNew = !existing.TryGetValue(name, out rule);
                if (!isNew && Matches(rule, executable, interfaces)) continue;
                AppLog.Trace("fw: " + (isNew ? "adding" : "repairing") + " rule for " + executable + ", interfaces " + interfaces.Count);
                try
                {
                    if (isNew)
                    {
                        AppLog.Trace("fw: creating rule object");
                        rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
                        rule.Name = name;
                    }
                    AppLog.Trace("fw: description");
                    rule.Description = "Claude выходит в сеть только через VPN. Создано " + AppIdentity.Name + ", не править вручную.";
                    AppLog.Trace("fw: application");
                    rule.ApplicationName = executable;
                    AppLog.Trace("fw: protocol, direction, action");
                    rule.Protocol = ProtocolAny;
                    rule.Direction = DirectionOut;
                    rule.Action = ActionBlock;
                    AppLog.Trace("fw: profiles");
                    rule.Profiles = ProfilesAll;
                    AppLog.Trace("fw: grouping");
                    rule.Grouping = AppIdentity.FirewallGroup;
                    AppLog.Trace("fw: interfaces " + string.Join(" | ", interfaces));
                    if (!TrySetInterfaces(rule, interfaces))
                    {
                        result.Errors.Add("Windows не принял список адаптеров для " + executable);
                        continue;
                    }
                    AppLog.Trace("fw: enabling");
                    rule.Enabled = true;
                    if (isNew)
                    {
                        AppLog.Trace("fw: rules.Add");
                        rules.Add(rule);
                        result.Added++;
                    }
                    else
                    {
                        result.Repaired++;
                    }
                }
                catch (COMException error)
                {
                    result.Errors.Add(executable + ": " + error.Message);
                }
                catch (UnauthorizedAccessException error)
                {
                    result.Errors.Add(executable + ": " + error.Message);
                }
            }

            foreach (string name in existing.Keys)
            {
                if (desiredNames.Contains(name)) continue;
                AppLog.Trace("fw: removing " + name);
                try
                {
                    rules.Remove(name);
                    result.Removed++;
                }
                catch (COMException error)
                {
                    result.Errors.Add("не удалось убрать устаревшее правило «" + name + "»: " + error.Message);
                }
            }
            result.AppliedInterfaces.AddRange(interfaces);
            AppLog.Trace("fw: sync done, added " + result.Added + ", repaired " + result.Repaired + ", removed " + result.Removed + ", errors " + result.Errors.Count);
            return result;
        }

        public static FirewallSyncResult Verify(FirewallRequest request)
        {
            var result = new FirewallSyncResult();
            result.AppliedInterfaces.AddRange(request.AppliedInterfaces);
            dynamic rules = OpenPolicy().Rules;
            foreach (string executable in request.Executables)
            {
                dynamic rule;
                try
                {
                    rule = rules.Item(RuleName(executable));
                }
                catch (COMException)
                {
                    result.Drift.Add("нет правила для " + executable);
                    continue;
                }
                catch (System.IO.FileNotFoundException)
                {
                    result.Drift.Add("нет правила для " + executable);
                    continue;
                }
                if (!Matches(rule, executable, request.AppliedInterfaces)) result.Drift.Add("правило для " + executable + " изменено");
            }
            return result;
        }

        public static void AddPolicyProblems(FirewallSyncResult result)
        {
            AppLog.Trace("fw: reading policy state");
            object policy = OpenPolicy();
            Type type = policy.GetType();
            object state = type.InvokeMember("LocalPolicyModifyState", BindingFlags.GetProperty, null, policy, null);
            if (state is int && (int)state == ModifyStateGroupPolicyOverride)
            {
                result.PolicyProblems.Add("групповая политика игнорирует локальные правила брандмауэра");
            }
        }

        public static FirewallSyncResult RemoveAll()
        {
            var result = new FirewallSyncResult();
            for (int pass = 1; pass <= RemovePasses; pass++)
            {
                dynamic rules = OpenPolicy().Rules;
                Dictionary<string, dynamic> own = OwnRules(rules);
                AppLog.Trace("fw: remove pass " + pass + ", own rules " + own.Count);
                if (own.Count == 0) return result;
                foreach (string name in own.Keys)
                {
                    try
                    {
                        rules.Remove(name);
                        result.Removed++;
                    }
                    catch (COMException error)
                    {
                        result.Errors.Add("не удалось убрать правило «" + name + "»: " + error.Message);
                        return result;
                    }
                }
            }
            int left = OwnRules(OpenPolicy().Rules).Count;
            if (left > 0) result.Errors.Add("в группе " + AppIdentity.FirewallGroup + " осталось правил: " + left);
            return result;
        }

        private static dynamic OpenPolicy()
        {
            return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
        }

        private static Dictionary<string, dynamic> OwnRules(dynamic rules)
        {
            var own = new Dictionary<string, dynamic>(StringComparer.OrdinalIgnoreCase);
            foreach (dynamic rule in rules)
            {
                string grouping = rule.Grouping;
                if (!string.Equals(grouping, AppIdentity.FirewallGroup, StringComparison.Ordinal)) continue;
                own[(string)rule.Name] = rule;
            }
            return own;
        }

        private static bool Matches(dynamic rule, string executable, List<string> interfaces)
        {
            try
            {
                string application = rule.ApplicationName;
                return (bool)rule.Enabled
                    && (int)rule.Action == ActionBlock
                    && (int)rule.Direction == DirectionOut
                    && (int)rule.Protocol == ProtocolAny
                    && ((int)rule.Profiles & ProfilesAll) == ProfilesAll
                    && string.Equals(application, executable, StringComparison.OrdinalIgnoreCase)
                    && SameInterfaces(rule.Interfaces, interfaces);
            }
            catch (COMException)
            {
                return false;
            }
        }

        private static bool SameInterfaces(object actual, List<string> expected)
        {
            var actualNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var array = actual as Array;
            if (array != null)
            {
                foreach (object item in array)
                {
                    if (item != null) actualNames.Add(item.ToString());
                }
            }
            return actualNames.SetEquals(expected);
        }

        private static bool TrySetInterfaces(dynamic rule, List<string> names)
        {
            try
            {
                object[] values = new object[names.Count];
                for (int i = 0; i < names.Count; i++) values[i] = names[i];
                rule.Interfaces = values;
                return true;
            }
            catch (COMException)
            {
                return false;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }
    }
}
