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

        private static string fieldsReadError;

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
            AppSettings current = LoadCurrent();
            fieldsReadError = current.ReadError;
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
                    Hint = "Списки имён (закрепляемые, без которых Claude не работает, через прокси VPN), дополнительные программы под защитой "
                        + "и уведомления вернутся к стандартным, выключенная защита включится. "
                        + "Адаптер VPN берётся из поля выше (если настройки не прочитались при открытии окна и поле не менялось — сохранённый). Журнал не трогается. Помогает, если сбой вызван настройками.",
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
                        + "• версия программы, Windows и .NET, время сбоя;\n"
                        + "• текст ошибки;\n"
                        + "• последние 100 КБ журнала " + Path.Combine(AppIdentity.DataDirectory, "log.txt") + ": имя пользователя и компьютера Windows, "
                        + "пути к программам Claude, названия сетевых адаптеров, адреса DNS-серверов VPN и адреса Claude внутри VPN;\n"
                        + "• IP-адрес, с которого пришёл отчёт.\n"
                        + "Отчёты видит только автор, хранятся последние 50 МБ. Изменить выбор — переустановить программу.",
                    Checked = File.Exists(AppSettings.FilePath) ? CrashReportConsent.IsGiven : LegacyInstall.ConsentGiven
                },
                new SetupOption
                {
                    Key = UsageConsent.OptionKey,
                    Text = "Отправлять автору анонимную статистику использования",
                    Hint = "Помогает понять, сколько людей пользуется программой и какие функции нужны. Без имён, путей и адресов. "
                        + "Выключить можно и потом — в настройках программы.",
                    DetailsTitle = "Что уходит в статистике",
                    Details = "Раз в час, пока программа запущена, на aokazantsev.ru (сервер в России) уходят счётчики за текущие и неотправленные прошлые сутки (до недели):\n"
                        + "• случайный номер установки — он не связан с тобой и компьютером;\n"
                        + "• версия программы и Windows;\n"
                        + "• сколько раз за сутки программа запускалась и сама находила новую версию, сколько раз ты пользовался пунктами меню, двойным кликом по значку, настройками и обновлением;\n"
                        + "• текущие настройки: включены ли защита, уведомления, автозапуск, проверка обновлений и отчёты о сбоях, сколько адаптеров VPN, "
                        + "дополнительных программ и программ под защитой, "
                        + "состояние защиты.\n"
                        + "Имена пользователя и компьютера, пути, названия адаптеров и адреса в статистику не попадают, IP-адрес сервер не хранит. "
                        + "Статистика хранится 400 суток, дальше — только итоги по дням.",
                    Checked = UsageConsent.InstallerDefault
                }
            };
        }

        public static void BeforeExtract(InstallRequest request, Action<int, string> report, List<string> notes)
        {
            report(2, "Останавливаю прежнюю версию " + AppIdentity.LegacyName + "…");
            LegacyInstall.StopAndCopyData(notes);
            report(4, "Папка настроек…");
            PrepareDataDirectory();
            bool reset = request.Has(ResetSettingsKey);
            SetupLog.Append("reset settings: " + reset);
            AppSettings settings = reset ? new AppSettings() : LoadCurrent();
            if (settings.ReadError != null) throw new InvalidOperationException("Не удалось прочитать настройки: " + settings.ReadError + ". Защита действует как была.");
            bool fieldGuessed = fieldsReadError != null && request.Value(VpnAdapterKey) == DefaultVpnAdapter;
            SetupLog.Append("settings read at open: " + (fieldsReadError ?? "ok") + ", adapter field guessed: " + fieldGuessed);
            AppSettings saved = reset ? LoadCurrent() : settings;
            bool keepSaved = fieldGuessed && saved.ReadError == null && saved.HasVpnAdapters;
            settings.VpnAdapters = keepSaved ? new List<string>(saved.VpnAdapters) : AppSettings.ParseList(request.Value(VpnAdapterKey));
            string saveProblem = settings.Save();
            if (saveProblem != null) throw new InvalidOperationException("Не удалось записать настройки в " + AppSettings.FilePath + ": " + saveProblem);
            CrashReportConsent.Set(request.Has(CrashReportConsent.OptionKey));
            SetupLog.Append("crash reports: " + request.Has(CrashReportConsent.OptionKey));
            UsageConsent.Set(request.Has(UsageConsent.OptionKey));
            SetupLog.Append("usage statistics: " + request.Has(UsageConsent.OptionKey));
            if (!settings.HasVpnAdapters) notes.Add("Адаптер VPN не указан — у Claude не будет сети, пока не выберешь его в настройках программы.");
            string firewallProblem = FirewallProblem();
            SetupLog.Append("firewall: " + (firewallProblem ?? "ok"));
            if (firewallProblem != null) notes.Add("Защита пока не работает: " + firewallProblem + ". Включи брандмауэр Windows — программа подхватит его сама.");
        }

        public static void AfterExtract(InstallRequest request, Action<int, string> report, List<string> notes)
        {
            LegacyInstall.DisableAutostart(notes);
        }

        public static void AfterLaunch(InstallRequest request, Action<int, string> report, List<string> notes)
        {
            report(98, "Убираю прежнюю версию " + AppIdentity.LegacyName + "…");
            LegacyInstall.Remove(notes);
        }

        public static void Launch(string executable)
        {
            Process.Start(new ProcessStartInfo(executable) { WorkingDirectory = Path.GetDirectoryName(executable), UseShellExecute = false });
        }

        private static AppSettings LoadCurrent()
        {
            return File.Exists(AppSettings.FilePath) ? AppSettings.Load() : AppSettings.LoadFrom(LegacyInstall.SettingsPath);
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
