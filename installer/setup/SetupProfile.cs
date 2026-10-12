using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AgentVpnGuard
{
    internal static class SetupProfile
    {
        private const string DefaultVpnAdapter = "Fortinet";
        private const string VpnAdapterKey = "vpnAdapter";
        private const string ResetSettingsKey = "resetSettings";

        public const string Intro =
            "Claude (десктоп, Claude Code, расширения редакторов) сможет выходить в сеть только через VPN. "
            + "Выключен VPN — у Claude нет сети вообще. Программа живёт в трее и сама берёт под защиту новые версии Claude.";

        public static string Notice()
        {
            string problem = FirewallProblem();
            if (problem == null) return null;
            return "Внимание: " + problem + ". Без брандмауэра Windows защита не работает — включи его. Установить можно и сейчас: значок покажет, когда всё заработает.";
        }

        private static string FirewallProblem()
        {
            List<string> problems = FirewallHealth.Problems();
            return problems.Count == 0 ? null : string.Join("; ", problems.ToArray());
        }

        public static List<SetupField> Fields()
        {
            LegacyInstall.CopyData();
            AppSettings current = AppSettings.Load();
            var adapter = new SetupField
            {
                Key = VpnAdapterKey,
                Label = "Адаптер VPN — часть его названия",
                Value = current.HasVpnAdapters ? string.Join("|", current.VpnAdapters) : DefaultVpnAdapter,
                Hint = "Claude выходит в сеть только через адаптеры, в названии которых есть этот текст. Несколько — через «|»."
            };
            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                if (!adapter.Suggestions.Contains(networkInterface.Description)) adapter.Suggestions.Add(networkInterface.Description);
            }
            return new List<SetupField> { adapter };
        }

        public static List<SetupOption> Options()
        {
            return new List<SetupOption>
            {
                new SetupOption
                {
                    Key = ResetSettingsKey,
                    Text = "Сбросить настройки",
                    Hint = "Закрепляемые адреса Claude, дополнительные программы под защитой и уведомления вернутся к стандартным. "
                        + "Адаптер VPN берётся из поля выше. Журнал не трогается. Помогает, если сбой вызван настройками.",
                    Checked = false
                },
                new SetupOption
                {
                    Key = CrashReportConsent.OptionKey,
                    Text = "Отправлять автору отчёты о сбоях",
                    Hint = "В отчёт попадает журнал программы, а в нём — имя пользователя и компьютера, пути к файлам и сетевые адреса, "
                        + "в том числе адреса внутри VPN компании. Не включай, если это запрещают правила твоей компании.",
                    DetailsTitle = "Что уходит в отчёте",
                    Details = "Отчёт уходит один раз — при сбое программы или брандмауэра Windows — на aokazantsev.ru (сервер в России), "
                        + "без повторных попыток:\n"
                        + "• версия программы, Windows и .NET;\n"
                        + "• текст ошибки;\n"
                        + "• последние 100 КБ журнала C:\\ProgramData\\AgentVpnGuard\\log.txt: имя пользователя и компьютера Windows, "
                        + "пути к программам Claude, названия сетевых адаптеров, адреса DNS-серверов VPN и адреса Claude внутри VPN;\n"
                        + "• IP-адрес, с которого пришёл отчёт.\n"
                        + "Отчёты видит только автор, хранятся последние 50 МБ. Изменить выбор — переустановить программу.",
                    Checked = CrashReportConsent.IsGiven
                }
            };
        }

        public static void BeforeExtract(InstallRequest request, Action<int, string> report, List<string> notes)
        {
            report(3, "Убираю прежнюю версию " + AppIdentity.LegacyName + "…");
            LegacyInstall.Remove(request.TargetDirectory, notes);
            report(5, "Папка настроек…");
            PrepareDataDirectory();
            bool reset = request.Has(ResetSettingsKey);
            SetupLog.Append("reset settings: " + reset);
            AppSettings settings = reset ? new AppSettings() : AppSettings.Load();
            settings.VpnAdapters = AppSettings.ParseList(request.Value(VpnAdapterKey));
            if (!settings.TrySave()) throw new InvalidOperationException("Не удалось записать настройки в " + AppSettings.FilePath + ".");
            CrashReportConsent.Set(request.Has(CrashReportConsent.OptionKey));
            SetupLog.Append("crash reports: " + request.Has(CrashReportConsent.OptionKey));
            if (!settings.HasVpnAdapters) notes.Add("Адаптер VPN не указан — у Claude не будет сети, пока не выберешь его в настройках программы.");
            string firewallProblem = FirewallProblem();
            SetupLog.Append("firewall: " + (firewallProblem ?? "ok"));
            if (firewallProblem != null) notes.Add("Защита пока не работает: " + firewallProblem + ". Включи брандмауэр Windows — программа подхватит его сама.");
        }

        public static void AfterExtract(InstallRequest request, Action<int, string> report, List<string> notes)
        {
        }

        public static void Launch(string executable)
        {
            Process.Start(new ProcessStartInfo(executable) { WorkingDirectory = Path.GetDirectoryName(executable), UseShellExecute = false });
        }

        private static void PrepareDataDirectory()
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(AppIdentity.DataDirectory);
            Directory.SetAccessControl(AppIdentity.DataDirectory, security);
        }
    }
}
