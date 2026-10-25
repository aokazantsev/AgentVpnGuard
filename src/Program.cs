using System;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Threading;
using System.Windows.Forms;

namespace AgentVpnGuard
{
    internal static class Program
    {
        private const int SettingsReadRetries = 10;
        private const int SettingsReadRetryMs = 1500;

        [STAThread]
        private static int Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            if (args.Length > 0 && args[0] == FirewallWorker.Argument)
            {
                CrashReport.Silent = true;
                return FirewallWorker.Run(args);
            }
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += OnThreadException;
            bool isFirstInstance;
            AppSettings settings;
            using (new Mutex(true, AppIdentity.SingleInstanceMutex, out isFirstInstance))
            {
                if (!isFirstInstance)
                {
                    AppLog.Append("another instance is running, exit");
                    return 0;
                }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                AppLog.Append("start " + AppIdentity.Version + ", user=" + Environment.UserDomainName + "\\" + Environment.UserName
                    + ", os=" + Environment.OSVersion.VersionString + ", 64bit=" + Environment.Is64BitProcess
                    + ", clr=" + Environment.Version + ", exe=" + Application.ExecutablePath);
                FirewallClient.RemoveStaleFiles();
                settings = ReadSettings();
                if (settings.ReadError == null) Application.Run(new TrayApplication(settings));
            }
            if (settings.ReadError == null) return 0;
            MessageBox.Show("Не удалось прочитать настройки " + AppSettings.FilePath + ": " + settings.ReadError + Environment.NewLine + Environment.NewLine
                + "Программа закрыта, защита оставлена как была. Запусти " + AppIdentity.Name + " снова, когда файл освободится.",
                AppIdentity.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }

        private static AppSettings ReadSettings()
        {
            AppSettings settings = AppSettings.Load();
            for (int attempt = 1; settings.ReadError != null && attempt <= SettingsReadRetries; attempt++)
            {
                AppLog.Append("settings not read: " + settings.ReadError + ", retry " + attempt);
                Thread.Sleep(SettingsReadRetryMs);
                settings = AppSettings.Load();
            }
            if (settings.ReadError != null) AppLog.Append("settings not read, exit: " + settings.ReadError);
            return settings;
        }

        private static void OnThreadException(object sender, ThreadExceptionEventArgs e)
        {
            CrashReport.Write("ui thread", e.Exception, false);
        }

        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            CrashReport.Write("unhandled", e.ExceptionObject as Exception, e.IsTerminating);
        }
    }
}
