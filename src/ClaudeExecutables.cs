using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;

namespace AgentVpnGuard
{
    internal static class ClaudeExecutables
    {
        private const string PackagesKey = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

        public static readonly string[] ProcessNames = { "claude", "chrome-native-host" };

        public static SortedSet<string> Find(AppSettings settings)
        {
            var found = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            AddVersioned(found, Path.Combine(roaming, @"Claude\claude-code"), "claude.exe");
            AddFiles(found, Path.Combine(roaming, @"Claude\ChromeNativeHost"), "*.exe");
            AddFile(found, Path.Combine(profile, @".local\bin\claude.exe"));
            AddFile(found, Path.Combine(local, @"AnthropicClaude\claude.exe"));
            AddPrefixed(found, Path.Combine(local, "AnthropicClaude"), "app-", "claude.exe");
            AddFile(found, Path.Combine(local, @"Programs\Claude\Claude.exe"));
            AddEditorExtensions(found, Path.Combine(profile, @".vscode\extensions"));
            AddEditorExtensions(found, Path.Combine(profile, @".cursor\extensions"));
            AddEditorExtensions(found, Path.Combine(profile, @".windsurf\extensions"));
            AddPackagedApps(found);
            foreach (string extra in settings.ExtraExecutables)
            {
                AddFile(found, Environment.ExpandEnvironmentVariables(extra));
            }
            return found;
        }

        public static bool LooksLikeClaude(string path)
        {
            string name = Path.GetFileNameWithoutExtension(path);
            foreach (string processName in ProcessNames)
            {
                if (string.Equals(name, processName, StringComparison.OrdinalIgnoreCase)
                    && path.IndexOf("claude", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }

        private static void AddVersioned(SortedSet<string> found, string root, string fileName)
        {
            if (!Directory.Exists(root)) return;
            try
            {
                foreach (string file in Directory.GetFiles(root, fileName, SearchOption.AllDirectories)) found.Add(file);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private static void AddFiles(SortedSet<string> found, string directory, string pattern)
        {
            if (!Directory.Exists(directory)) return;
            try
            {
                foreach (string file in Directory.GetFiles(directory, pattern)) found.Add(file);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private static void AddPrefixed(SortedSet<string> found, string root, string prefix, string fileName)
        {
            if (!Directory.Exists(root)) return;
            try
            {
                foreach (string directory in Directory.GetDirectories(root, prefix + "*"))
                {
                    AddFile(found, Path.Combine(directory, fileName));
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private static void AddEditorExtensions(SortedSet<string> found, string extensionsRoot)
        {
            if (!Directory.Exists(extensionsRoot)) return;
            try
            {
                foreach (string extension in Directory.GetDirectories(extensionsRoot, "anthropic.claude-code-*"))
                {
                    AddVersioned(found, extension, "claude.exe");
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private static void AddPackagedApps(SortedSet<string> found)
        {
            using (RegistryKey packages = Registry.CurrentUser.OpenSubKey(PackagesKey))
            {
                if (packages == null) return;
                foreach (string packageName in packages.GetSubKeyNames())
                {
                    if (!packageName.StartsWith("Claude_", StringComparison.OrdinalIgnoreCase)
                        && packageName.IndexOf(".Claude_", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    using (RegistryKey package = packages.OpenSubKey(packageName))
                    {
                        string root = package == null ? null : package.GetValue("PackageRootFolder") as string;
                        if (string.IsNullOrEmpty(root)) continue;
                        AddFile(found, Path.Combine(root, @"app\Claude.exe"));
                    }
                }
            }
        }

        private static void AddFile(SortedSet<string> found, string path)
        {
            if (File.Exists(path)) found.Add(Path.GetFullPath(path));
        }
    }
}
