using System;
using System.IO;

namespace AgentVpnGuard
{
    internal static class AppIdentity
    {
        public const string Name = "AgentVpnGuard";
        public const string LegacyName = "ClaudeVpnGuard";
        public const string Version = "3.1";
        public const string ExecutableName = "AgentVpnGuard.exe";
        public const string ProcessName = "AgentVpnGuard";
        public const string UninstallerName = "Uninstall.exe";
        public const string FirewallGroup = "AgentVpnGuard";
        public const string SingleInstanceMutex = @"Global\AgentVpnGuard.SingleInstance";
        public const string GitHubUrl = "https://github.com/aokazantsev/AgentVpnGuard";
        public const string SiteUrl = "https://aokazantsev.ru/pets/agentvpnguard/";
        public const string AutostartDelay = "PT0S";

        public static string DataDirectory
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Name); }
        }

        public static string DefaultInstallDirectory
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Name); }
        }
    }
}
