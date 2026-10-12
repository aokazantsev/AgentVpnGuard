using System;
using System.Drawing;
using System.Windows.Forms;

namespace AgentVpnGuard
{
    internal static class TrayMenu
    {
        public static void Fill(ContextMenuStrip menu, GuardReport report, bool startupEnabled, bool protectionEnabled,
            Action checkNow, Action showSettings, Action openLog, Action<bool> toggleStartup, Action<bool> toggleProtection, Action exit)
        {
            menu.Items.Clear();
            if (report != null)
            {
                var headline = new ToolStripMenuItem(report.Headline) { Enabled = false, Image = StatusIconPainter.Paint(report.Status).ToBitmap() };
                headline.Font = new Font(menu.Font, FontStyle.Bold);
                menu.Items.Add(headline);
                foreach (string problem in report.Problems)
                {
                    if (problem != report.Headline) menu.Items.Add(new ToolStripMenuItem("• " + problem) { Enabled = false });
                }
                foreach (string detail in report.Details) menu.Items.Add(new ToolStripMenuItem(detail) { Enabled = false });
                if (protectionEnabled)
                {
                    var programs = new ToolStripMenuItem("Программы под защитой (" + report.Executables.Count + ")");
                    foreach (string executable in report.Executables) programs.DropDownItems.Add(new ToolStripMenuItem(executable) { Enabled = false });
                    if (report.Executables.Count == 0) programs.DropDownItems.Add(new ToolStripMenuItem("Claude не найден") { Enabled = false });
                    menu.Items.Add(programs);
                }
            }
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Проверить сейчас", null, (s, a) => checkNow());
            menu.Items.Add(protectionEnabled ? "Выключить защиту…" : "Включить защиту", null, (s, a) => toggleProtection(!protectionEnabled));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Настройки…", null, (s, a) => showSettings());
            menu.Items.Add("Журнал", null, (s, a) => openLog());
            var startup = new ToolStripMenuItem("Запускать при входе в Windows") { Checked = startupEnabled };
            startup.Click += (s, a) => toggleStartup(!startup.Checked);
            menu.Items.Add(startup);
            menu.Items.Add("Проверить обновление…", null, (s, a) => UpdateForm.ShowSingle());
            menu.Items.Add("О приложении…", null, (s, a) => AboutForm.ShowSingle());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Выход", null, (s, a) => exit());
        }
    }
}
