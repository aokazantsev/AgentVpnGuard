using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Windows.Forms;

namespace AgentVpnGuard
{
    internal sealed class TrayApplication : ApplicationContext
    {
        private const int TickIntervalMs = 5 * 1000;
        private const int SoonIntervalMs = 700;
        private const int BalloonMs = 6000;
        private const int MaxTrayTextLength = 63;
        private const int MaxBalloonTextLength = 255;
        private const int MaxPendingEvents = 20;

        private readonly NotifyIcon trayIcon = new NotifyIcon();
        private readonly Control invoker = new Control();
        private readonly Timer tickTimer = new Timer();
        private readonly Timer soonTimer = new Timer();
        private readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        private AppSettings settings;
        private GuardEngine engine;
        private GuardReport report;
        private SettingsForm settingsForm;
        private bool forceFullSync = true;
        private GuardStatus? settledStatus;
        private string settledCause;
        private readonly List<string> pendingEvents = new List<string>();

        public TrayApplication(AppSettings settings)
        {
            this.settings = settings;
            AppLog.Append("settings: file=" + AppSettings.FileExists + ", vpn=" + string.Join("|", settings.VpnAdapters)
                + ", extra=" + settings.ExtraExecutables.Count + ", protection=" + settings.ProtectionEnabled);
            invoker.CreateControl();
            engine = new GuardEngine(settings, Post, RefreshSoon);
            AppLog.Append("engine created");

            trayIcon.ContextMenuStrip = new ContextMenuStrip();
            trayIcon.ContextMenuStrip.Opening += OnMenuOpening;
            trayIcon.MouseDoubleClick += (sender, e) => ShowSettings();
            trayIcon.Icon = StatusIconPainter.Paint(GuardStatus.Offline);
            trayIcon.Text = AppIdentity.Name + ": проверяю…";
            trayIcon.Visible = true;

            tickTimer.Interval = TickIntervalMs;
            tickTimer.Tick += (sender, e) => Refresh();
            tickTimer.Start();
            soonTimer.Interval = SoonIntervalMs;
            soonTimer.Tick += (sender, e) =>
            {
                soonTimer.Stop();
                Refresh();
            };

            NetworkChange.NetworkAddressChanged += OnNetworkChanged;
            NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;
            WatchClaudeFolders();
            AppLog.Append("watchers: " + watchers.Count);
            Refresh();
            AppLog.Append("first refresh done");
            if (!settings.HasVpnAdapters) ShowSettings();
        }

        protected override void ExitThreadCore()
        {
            NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
            NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
            foreach (FileSystemWatcher watcher in watchers) watcher.Dispose();
            tickTimer.Dispose();
            soonTimer.Dispose();
            if (settingsForm != null) settingsForm.Close();
            trayIcon.Visible = false;
            trayIcon.Dispose();
            invoker.Dispose();
            AppLog.Append("exit");
            base.ExitThreadCore();
        }

        private void Post(Action action)
        {
            try
            {
                invoker.BeginInvoke(action);
            }
            catch (InvalidOperationException)
            {
            }
        }

        private void RefreshSoon()
        {
            Post(() =>
            {
                soonTimer.Stop();
                soonTimer.Start();
            });
        }

        private void OnNetworkChanged(object sender, EventArgs e)
        {
            RefreshSoon();
        }

        private void OnNetworkAvailabilityChanged(object sender, NetworkAvailabilityEventArgs e)
        {
            RefreshSoon();
        }

        private void WatchClaudeFolders()
        {
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            Watch(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Claude"));
            Watch(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Claude-NativeHost"));
            foreach (string packagedRoaming in ClaudeExecutables.PackagedRoamingFolders()) Watch(packagedRoaming);
            Watch(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AnthropicClaude"));
            Watch(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Claude"));
            Watch(Path.Combine(profile, @".local\bin"));
            Watch(Path.Combine(profile, @".vscode\extensions"));
            Watch(Path.Combine(profile, @".cursor\extensions"));
            Watch(Path.Combine(profile, @".windsurf\extensions"));
        }

        private void Watch(string directory)
        {
            if (!Directory.Exists(directory)) return;
            var watcher = new FileSystemWatcher(directory, "*.exe") { IncludeSubdirectories = true };
            watcher.Created += (sender, e) => RefreshSoon();
            watcher.Renamed += (sender, e) => RefreshSoon();
            watcher.EnableRaisingEvents = true;
            watchers.Add(watcher);
        }

        private void Refresh()
        {
            GuardStatus? previous = settledStatus;
            string previousHeadline = report == null ? null : report.Headline;
            bool force = forceFullSync;
            forceFullSync = false;
            try
            {
                report = engine.Evaluate(force);
            }
            catch (Exception error)
            {
                report = new GuardReport { Status = GuardStatus.Broken, Headline = "Сбой проверки: " + error.Message };
                report.Problems.Add(report.Headline);
                AppLog.Append("evaluate failed: " + error);
            }
            foreach (string line in report.Events)
            {
                AppLog.Append(line);
                UserJournal.Append(null, line);
            }
            if (previousHeadline != report.Headline) AppLog.Append("status " + report.Status + ": " + report.Headline);

            trayIcon.Icon = StatusIconPainter.Paint(report.Status);
            string tip = AppIdentity.Name + ": " + report.Headline;
            trayIcon.Text = tip.Length > MaxTrayTextLength ? tip.Substring(0, MaxTrayTextLength - 1) + "…" : tip;

            pendingEvents.AddRange(report.Events);
            if (pendingEvents.Count > MaxPendingEvents) pendingEvents.RemoveRange(0, pendingEvents.Count - MaxPendingEvents);
            if (report.Settling) return;
            var events = new List<string>(pendingEvents);
            pendingEvents.Clear();
            string cause = Cause(report.Headline);
            bool statusChanged = previous.HasValue && (previous.Value != report.Status || cause != settledCause);
            settledStatus = report.Status;
            settledCause = cause;
            bool firstAlarm = !previous.HasValue && report.Status != GuardStatus.Protected;
            if (statusChanged || firstAlarm)
            {
                UserJournal.Append(report.Status, report.Headline);
                if (settings.Notifications)
                {
                    var lines = new List<string> { report.Headline };
                    lines.AddRange(events);
                    trayIcon.ShowBalloonTip(BalloonMs, AppIdentity.Name, BalloonText(lines), BalloonIcon(report.Status));
                }
            }
            else if (events.Count > 0 && settings.Notifications)
            {
                trayIcon.ShowBalloonTip(BalloonMs, AppIdentity.Name, BalloonText(events), ToolTipIcon.Info);
            }
        }

        private static string Cause(string headline)
        {
            int colon = headline.IndexOf(':');
            return colon < 0 ? headline : headline.Substring(0, colon);
        }

        private static string BalloonText(List<string> events)
        {
            string text = string.Join(Environment.NewLine, events);
            return text.Length > MaxBalloonTextLength ? text.Substring(0, MaxBalloonTextLength - 1) + "…" : text;
        }

        private static ToolTipIcon BalloonIcon(GuardStatus status)
        {
            if (status == GuardStatus.Broken) return ToolTipIcon.Error;
            if (status == GuardStatus.Warning) return ToolTipIcon.Warning;
            return ToolTipIcon.Info;
        }

        private void OnMenuOpening(object sender, System.ComponentModel.CancelEventArgs e)
        {
            TrayMenu.Fill(trayIcon.ContextMenuStrip, report, Autostart.IsEnabled(), settings.ProtectionEnabled,
                () =>
                {
                    engine.RetryFirewall();
                    forceFullSync = true;
                    Refresh();
                },
                ShowSettings, JournalForm.ShowSingle, ToggleStartup, ToggleProtection, ConfirmExit);
            e.Cancel = false;
        }

        private void ShowSettings()
        {
            if (settingsForm != null)
            {
                settingsForm.Activate();
                return;
            }
            settingsForm = new SettingsForm(settings, () => settings, ApplySettings);
            settingsForm.FormClosed += (sender, e) => settingsForm = null;
            settingsForm.Show();
        }

        private bool ApplySettings(AppSettings updated)
        {
            if (settings.ProtectionEnabled && !updated.ProtectionEnabled && !ConfirmDisableProtection()) return false;
            string saveProblem = updated.Save();
            if (saveProblem != null)
            {
                AppLog.Append("settings not saved: " + saveProblem);
                MessageBox.Show("Не удалось сохранить настройки в " + AppSettings.FilePath + ": " + saveProblem, AppIdentity.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            settings = updated;
            engine.Reconfigure(updated);
            AppLog.Append("settings saved: vpn=" + string.Join("|", updated.VpnAdapters) + ", protection=" + updated.ProtectionEnabled);
            forceFullSync = true;
            Refresh();
            return true;
        }

        private void ToggleStartup(bool enable)
        {
            string problem = enable ? Autostart.Enable(Application.ExecutablePath) : Autostart.Disable();
            AppLog.Append("autostart " + (enable ? "enable" : "disable") + ": " + (problem ?? "ok"));
            if (problem != null) MessageBox.Show(problem, AppIdentity.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private void ToggleProtection(bool enable)
        {
            AppSettings updated = settings.Copy();
            updated.ProtectionEnabled = enable;
            ApplySettings(updated);
        }

        private static bool ConfirmDisableProtection()
        {
            DialogResult answer = MessageBox.Show(
                "Правила брандмауэра и блок в hosts будут сняты: Claude пойдёт в сеть напрямую, как без " + AppIdentity.Name + ", в том числе мимо VPN."
                + Environment.NewLine + Environment.NewLine
                + "Защита останется выключенной, пока ты не включишь её снова, — в том числе после перезапуска программы и Windows."
                + Environment.NewLine + Environment.NewLine + "Выключить защиту?",
                AppIdentity.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            return answer == DialogResult.Yes;
        }

        private void ConfirmExit()
        {
            if (!settings.ProtectionEnabled)
            {
                DialogResult unprotected = MessageBox.Show(
                    "Защита выключена и останется выключенной: Claude ходит в сеть напрямую. После запуска программы она тоже будет выключена, пока ты её не включишь."
                    + Environment.NewLine + Environment.NewLine + "Выйти?",
                    AppIdentity.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (unprotected == DialogResult.Yes) ExitThread();
                return;
            }
            DialogResult answer = MessageBox.Show(
                "Защита останется включённой: правила брандмауэра и блок в hosts работают и без программы, без VPN у Claude сети не будет."
                + Environment.NewLine + Environment.NewLine
                + "Но пока " + AppIdentity.Name + " закрыт, никто не следит за обновлениями Claude и сетевыми адаптерами: новая версия Claude или новый адаптер, появившиеся в это время, под защиту не попадут, а значок не покажет проблему."
                + Environment.NewLine + Environment.NewLine + "Выйти?",
                AppIdentity.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer == DialogResult.Yes) ExitThread();
        }
    }
}
