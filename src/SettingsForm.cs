using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace AgentVpnGuard
{
    internal sealed class SettingsForm : Form
    {
        private readonly AppSettings original;
        private readonly Action<AppSettings> save;
        private readonly CheckedListBox adapters = new CheckedListBox();
        private readonly TextBox pinnedHosts = new TextBox();
        private readonly TextBox criticalHosts = new TextBox();
        private readonly TextBox proxiedHosts = new TextBox();
        private readonly TextBox extraExecutables = new TextBox();
        private readonly CheckBox notifications = new CheckBox();
        private readonly CheckBox protection = new CheckBox();
        private readonly List<NetworkAdapter> adapterRows = new List<NetworkAdapter>();
        private readonly bool initialProtection;

        public SettingsForm(AppSettings settings, Action<AppSettings> save)
        {
            original = settings;
            initialProtection = settings.ProtectionEnabled;
            this.save = save;
            Text = AppIdentity.Name + " — настройки";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(620, 745);
            Font = SystemFonts.MessageBoxFont;

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 1 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            Controls.Add(layout);

            AddLabel(layout, "Адаптеры VPN — Claude выходит в сеть только через отмеченные:");
            adapters.Dock = DockStyle.Fill;
            adapters.Height = 150;
            adapters.CheckOnClick = true;
            layout.Controls.Add(adapters);
            FillAdapters(settings);

            AddLabel(layout, "Адреса Claude, которые закрепляются в hosts по DNS VPN (по одному в строке):");
            AddMultiline(layout, pinnedHosts, settings.PinnedHosts, 95);

            AddLabel(layout, "Без каких из них Claude не работает (жёлтый значок, если недоступны):");
            AddMultiline(layout, criticalHosts, settings.CriticalHosts, 50);

            AddLabel(layout, "Через прокси VPN — DNS VPN их не подменяет, закрепляются только при подключённом VPN:");
            AddMultiline(layout, proxiedHosts, settings.ProxiedHosts, 80);

            AddLabel(layout, "Дополнительные программы под защитой — полные пути к exe:");
            AddMultiline(layout, extraExecutables, settings.ExtraExecutables, 60);

            notifications.Text = "Показывать уведомления при смене состояния";
            notifications.AutoSize = true;
            notifications.Checked = settings.Notifications;
            layout.Controls.Add(notifications);

            protection.Text = "Защита включена — без неё Claude ходит в сеть напрямую, в том числе мимо VPN";
            protection.AutoSize = true;
            protection.Checked = settings.ProtectionEnabled;
            layout.Controls.Add(protection);

            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, AutoSize = true };
            var cancel = new Button { Text = "Отмена", AutoSize = true };
            cancel.Click += (sender, e) => Close();
            var ok = new Button { Text = "Сохранить", AutoSize = true };
            ok.Click += OnSave;
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            layout.Controls.Add(buttons);
            AcceptButton = ok;
            CancelButton = cancel;
        }

        private void FillAdapters(AppSettings settings)
        {
            AdapterSnapshot snapshot = AdapterInventory.Read(settings);
            snapshot.Adapters.Sort((a, b) =>
            {
                if (a.IsPresent != b.IsPresent) return a.IsPresent ? -1 : 1;
                return string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase);
            });
            foreach (NetworkAdapter adapter in snapshot.Adapters)
            {
                if (string.IsNullOrEmpty(adapter.Description)) continue;
                adapterRows.Add(adapter);
                string state = !adapter.IsPresent ? "нет в системе" : adapter.IsUp ? "подключён" : "отключён";
                adapters.Items.Add(adapter.Description + "  —  " + adapter.Name + ", " + state, adapter.IsVpn);
            }
        }

        private void OnSave(object sender, EventArgs e)
        {
            var updated = AppSettings.LoadFrom(AppSettings.FilePath);
            updated.VpnAdapters = new List<string>();
            foreach (int index in adapters.CheckedIndices)
            {
                string description = adapterRows[index].Description;
                if (!updated.VpnAdapters.Contains(description)) updated.VpnAdapters.Add(description);
            }
            foreach (string match in original.VpnAdapters)
            {
                bool shown = adapterRows.Exists(row => original.IsVpnAdapter(row.Description) && row.Description.IndexOf(match, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!shown && !updated.VpnAdapters.Contains(match)) updated.VpnAdapters.Add(match);
            }
            updated.PinnedHosts = AppSettings.ParseList(pinnedHosts.Text);
            updated.CriticalHosts = AppSettings.ParseList(criticalHosts.Text);
            updated.ProxiedHosts = AppSettings.ParseList(proxiedHosts.Text);
            updated.ExtraExecutables = AppSettings.ParseList(extraExecutables.Text);
            updated.Notifications = notifications.Checked;
            if (protection.Checked != initialProtection) updated.ProtectionEnabled = protection.Checked;
            foreach (string critical in updated.CriticalHosts)
            {
                if (!updated.PinnedHosts.Contains(critical)) updated.PinnedHosts.Add(critical);
            }
            save(updated);
            DialogResult = DialogResult.OK;
            Close();
        }

        private static void AddLabel(TableLayoutPanel layout, string text)
        {
            layout.Controls.Add(new Label { Text = text, AutoSize = true, Margin = new Padding(0, 8, 0, 3) });
        }

        private static void AddMultiline(TableLayoutPanel layout, TextBox box, List<string> lines, int height)
        {
            box.Multiline = true;
            box.ScrollBars = ScrollBars.Vertical;
            box.Dock = DockStyle.Fill;
            box.Height = height;
            box.Text = string.Join(Environment.NewLine, lines);
            layout.Controls.Add(box);
        }
    }
}
