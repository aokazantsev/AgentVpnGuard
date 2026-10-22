using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace AgentVpnGuard
{
    internal sealed class SettingsForm : Form
    {
        private readonly AppSettings original;
        private readonly Func<AppSettings> current;
        private readonly Func<AppSettings, bool> save;
        private readonly Action optionsChanged;
        private readonly CheckedListBox adapters = new CheckedListBox();
        private readonly TextBox pinnedHosts = new TextBox();
        private readonly TextBox criticalHosts = new TextBox();
        private readonly TextBox proxiedHosts = new TextBox();
        private readonly TextBox extraExecutables = new TextBox();
        private readonly CheckBox notifications = new CheckBox();
        private readonly CheckBox protection = new CheckBox();
        private readonly CheckBox autoUpdate = new CheckBox();
        private readonly CheckBox usageStatistics = new CheckBox();
        private readonly List<NetworkAdapter> adapterRows = new List<NetworkAdapter>();

        public SettingsForm(AppSettings settings, Func<AppSettings> current, Func<AppSettings, bool> save, Action optionsChanged)
        {
            original = settings;
            this.current = current;
            this.save = save;
            this.optionsChanged = optionsChanged;
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
            adapters.CheckOnClick = true;
            layout.Controls.Add(adapters);
            adapters.Height = adapters.ItemHeight * 8 + 4;
            FillAdapters(settings);

            AddLabel(layout, "Адреса Claude, которые закрепляются в hosts по DNS VPN (по одному в строке):");
            AddMultiline(layout, pinnedHosts, settings.PinnedHosts, 5);

            AddLabel(layout, "Без каких из них Claude не работает (жёлтый значок, если недоступны):");
            AddMultiline(layout, criticalHosts, settings.CriticalHosts, 3);

            AddLabel(layout, "Через прокси VPN — DNS VPN их не подменяет, закрепляются только при подключённом VPN:");
            AddMultiline(layout, proxiedHosts, settings.ProxiedHosts, 4);

            AddLabel(layout, "Дополнительные программы под защитой — полные пути к exe:");
            AddMultiline(layout, extraExecutables, settings.ExtraExecutables, 3);

            notifications.Text = "Показывать уведомления при смене состояния";
            notifications.AutoSize = true;
            notifications.Checked = settings.Notifications;
            layout.Controls.Add(notifications);

            protection.Text = "Защита включена — без неё Claude ходит в сеть напрямую, в том числе мимо VPN";
            protection.AutoSize = true;
            protection.Checked = settings.ProtectionEnabled;
            layout.Controls.Add(protection);

            autoUpdate.Text = "Раз в сутки проверять обновление и сообщать о новой версии";
            autoUpdate.AutoSize = true;
            autoUpdate.Checked = AutoUpdateCheck.IsEnabled;
            layout.Controls.Add(autoUpdate);

            usageStatistics.Text = "Отправлять автору анонимную статистику использования";
            usageStatistics.AutoSize = true;
            usageStatistics.Checked = UsageConsent.IsGiven;
            layout.Controls.Add(usageStatistics);

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

            Size preferred = layout.GetPreferredSize(Size.Empty);
            int width = Math.Max(ClientSize.Width, preferred.Width);
            int height = layout.GetPreferredSize(new Size(width, 0)).Height;
            int available = Screen.FromPoint(Cursor.Position).WorkingArea.Height - (Height - ClientSize.Height);
            layout.AutoScroll = height > available;
            ClientSize = new Size(width + (layout.AutoScroll ? SystemInformation.VerticalScrollBarWidth : 0), Math.Min(height, available));
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
            var updated = current().Copy();
            updated.VpnAdapters = AdapterChoiceChanged() ? CheckedAdapters() : new List<string>(original.VpnAdapters);
            updated.PinnedHosts = HostNames(pinnedHosts);
            if (updated.PinnedHosts == null) return;
            updated.CriticalHosts = HostNames(criticalHosts);
            if (updated.CriticalHosts == null) return;
            updated.ProxiedHosts = HostNames(proxiedHosts);
            if (updated.ProxiedHosts == null) return;
            updated.ExtraExecutables = AppSettings.ParseList(extraExecutables.Text).ConvertAll(path => path.Trim('"').Trim());
            updated.Notifications = notifications.Checked;
            if (protection.Checked != original.ProtectionEnabled) updated.ProtectionEnabled = protection.Checked;
            foreach (string critical in updated.CriticalHosts)
            {
                if (!updated.PinnedHosts.Exists(pinned => string.Equals(pinned, critical, StringComparison.OrdinalIgnoreCase))) updated.PinnedHosts.Add(critical);
            }
            if (!save(updated)) return;
            string problem = SaveOptions();
            if (problem != null)
            {
                AppLog.Append("options not saved: " + problem);
                MessageBox.Show(this, "Не удалось сохранить выбор проверки обновлений и статистики: " + problem, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            Usage.Hit("settings.save");
            optionsChanged();
            Close();
        }

        private string SaveOptions()
        {
            try
            {
                if (autoUpdate.Checked != AutoUpdateCheck.IsEnabled) AutoUpdateCheck.Set(autoUpdate.Checked);
                if (usageStatistics.Checked != UsageConsent.IsGiven) Usage.SetConsent(usageStatistics.Checked);
                return null;
            }
            catch (System.IO.IOException error)
            {
                return error.Message;
            }
            catch (UnauthorizedAccessException error)
            {
                return error.Message;
            }
        }

        private bool AdapterChoiceChanged()
        {
            for (int index = 0; index < adapterRows.Count; index++)
            {
                if (adapters.GetItemChecked(index) != original.IsVpnAdapter(adapterRows[index].Description)) return true;
            }
            return false;
        }

        private List<string> CheckedAdapters()
        {
            var chosen = new List<string>();
            foreach (int index in adapters.CheckedIndices)
            {
                string description = adapterRows[index].Description;
                if (!chosen.Contains(description)) chosen.Add(description);
            }
            foreach (string match in original.VpnAdapters)
            {
                bool shown = adapterRows.Exists(row => original.IsVpnAdapter(row.Description) && row.Description.IndexOf(match, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!shown && !chosen.Contains(match)) chosen.Add(match);
            }
            return chosen;
        }

        private List<string> HostNames(TextBox box)
        {
            var names = new List<string>();
            foreach (string line in AppSettings.ParseList(box.Text))
            {
                foreach (string name in line.Split(new[] { ' ', '	', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (Uri.CheckHostName(name) != UriHostNameType.Dns)
                    {
                        MessageBox.Show(this, "«" + name + "» — не имя сервера. Пиши имена по одному в строке, например api.anthropic.com.",
                            Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        box.Focus();
                        return null;
                    }
                    if (!names.Exists(known => string.Equals(known, name, StringComparison.OrdinalIgnoreCase))) names.Add(name);
                }
            }
            return names;
        }

        private static void AddLabel(TableLayoutPanel layout, string text)
        {
            layout.Controls.Add(new Label { Text = text, AutoSize = true, Margin = new Padding(0, 8, 0, 3) });
        }

        private static void AddMultiline(TableLayoutPanel layout, TextBox box, List<string> lines, int visibleLines)
        {
            box.Multiline = true;
            box.AcceptsReturn = true;
            box.ScrollBars = ScrollBars.Vertical;
            box.Dock = DockStyle.Fill;
            box.Text = string.Join(Environment.NewLine, lines);
            layout.Controls.Add(box);
            box.Height = box.Font.Height * visibleLines + 8;
        }
    }
}
