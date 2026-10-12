using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ServiceProcess;
using Microsoft.Win32;

namespace AgentVpnGuard
{
    internal static class FirewallHealth
    {
        private const string ServiceName = "MpsSvc";
        private const string EnableValue = "EnableFirewall";
        private const string LocalPolicyKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
        private const string GroupPolicyKey = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\";
        private static readonly string[] LocalProfiles = { "DomainProfile", "StandardProfile", "PublicProfile" };
        private static readonly string[] PolicyProfiles = { "DomainProfile", "PrivateProfile", "PublicProfile" };
        private static readonly string[] ProfileNames = { "доменный", "частный", "общий" };

        public static string ServiceProblem()
        {
            try
            {
                using (var service = new ServiceController(ServiceName))
                {
                    ServiceControllerStatus status = service.Status;
                    if (status == ServiceControllerStatus.Running) return null;
                    if (status == ServiceControllerStatus.Stopped) return "служба брандмауэра Windows остановлена";
                    return "служба брандмауэра Windows не запущена";
                }
            }
            catch (InvalidOperationException)
            {
                return "служба брандмауэра Windows не найдена";
            }
            catch (Win32Exception error)
            {
                return "служба брандмауэра Windows недоступна: " + error.Message;
            }
        }

        public static List<string> Problems()
        {
            var problems = new List<string>();
            string service = ServiceProblem();
            if (service != null) problems.Add(service);
            problems.AddRange(DisabledProfiles());
            return problems;
        }

        public static List<string> DisabledProfiles()
        {
            var problems = new List<string>();
            for (int i = 0; i < ProfileNames.Length; i++)
            {
                bool? policy = ReadFlag(GroupPolicyKey + PolicyProfiles[i]);
                bool? local = ReadFlag(LocalPolicyKey + LocalProfiles[i]);
                bool enabled = policy ?? local ?? true;
                if (!enabled) problems.Add("брандмауэр Windows выключен (" + ProfileNames[i] + " профиль" + (policy.HasValue ? ", групповой политикой" : "") + ")");
            }
            return problems;
        }

        private static bool? ReadFlag(string keyPath)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key == null) return null;
                    object value = key.GetValue(EnableValue);
                    if (value is int) return (int)value != 0;
                    return null;
                }
            }
            catch (System.Security.SecurityException)
            {
                return null;
            }
        }
    }
}
