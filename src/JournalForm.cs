using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace AgentVpnGuard
{
    internal sealed class JournalForm : Form
    {
        private static JournalForm openForm;

        private readonly DataGridView grid = new DataGridView();
        private readonly Label empty = new Label();
        private readonly Bitmap infoImage = new Bitmap(SystemIcons.Information.ToBitmap(), SystemInformation.SmallIconSize);

        public static void ShowSingle()
        {
            if (openForm != null)
            {
                openForm.Activate();
                return;
            }
            openForm = new JournalForm();
            openForm.FormClosed += (sender, e) => openForm = null;
            openForm.Show();
        }

        private JournalForm()
        {
            Text = AppIdentity.Name + " — журнал";
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = SystemFonts.MessageBoxFont;
            ClientSize = new Size(720, 460);
            MinimumSize = new Size(480, 300);
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 1, RowCount = 3 };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Controls.Add(layout);

            layout.Controls.Add(new Label
            {
                Text = "Что программа сообщала: смена состояния и изменения защиты. Новые записи сверху.",
                AutoSize = true,
                Margin = new Padding(0, 0, 0, 8)
            });

            var host = new Panel { Dock = DockStyle.Fill, Margin = new Padding(0) };
            ConfigureGrid();
            host.Controls.Add(grid);
            empty.Text = "Пока ничего не происходило.";
            empty.ForeColor = SystemColors.GrayText;
            empty.AutoSize = true;
            empty.Location = new Point(8, 8);
            host.Controls.Add(empty);
            empty.BringToFront();
            layout.Controls.Add(host);

            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 8, 0, 0) };
            var close = new Button { Text = "Закрыть", AutoSize = true };
            close.Click += (sender, e) => Close();
            var technical = new Button { Text = "Подробный журнал", AutoSize = true };
            technical.Click += (sender, e) => OpenTechnicalLog();
            buttons.Controls.Add(close);
            buttons.Controls.Add(technical);
            layout.Controls.Add(buttons);
            CancelButton = close;

            List<JournalEntry> entries = UserJournal.ReadAll();
            for (int index = entries.Count - 1; index >= 0; index--) AddRow(entries[index], false);
            UpdateEmpty();
            Shown += (sender, e) => grid.ClearSelection();
            UserJournal.Added += OnAdded;
            FormClosed += (sender, e) => UserJournal.Added -= OnAdded;
        }

        public static void OpenTechnicalLog()
        {
            if (!File.Exists(AppLog.FilePath)) AppLog.Append("log opened");
            Process.Start(new ProcessStartInfo("notepad.exe", "\"" + AppLog.FilePath + "\"") { UseShellExecute = false });
        }

        private void ConfigureGrid()
        {
            grid.Dock = DockStyle.Fill;
            grid.ReadOnly = true;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.AllowUserToResizeRows = false;
            grid.RowHeadersVisible = false;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.BackgroundColor = SystemColors.Window;
            grid.BorderStyle = BorderStyle.FixedSingle;
            grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            grid.GridColor = SystemColors.ControlLight;
            grid.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells;
            grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            grid.DefaultCellStyle.WrapMode = DataGridViewTriState.True;
            grid.DefaultCellStyle.Padding = new Padding(2, 3, 2, 3);
            grid.DefaultCellStyle.SelectionBackColor = SystemColors.ControlLight;
            grid.DefaultCellStyle.SelectionForeColor = SystemColors.ControlText;

            var icon = new DataGridViewImageColumn { HeaderText = "", Width = 28, ImageLayout = DataGridViewImageCellLayout.Normal };
            icon.DefaultCellStyle.Alignment = DataGridViewContentAlignment.TopCenter;
            var time = new DataGridViewTextBoxColumn { HeaderText = "Время", AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells };
            time.DefaultCellStyle.WrapMode = DataGridViewTriState.False;
            time.DefaultCellStyle.Alignment = DataGridViewContentAlignment.TopLeft;
            var text = new DataGridViewTextBoxColumn { HeaderText = "Событие", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill };
            text.DefaultCellStyle.Alignment = DataGridViewContentAlignment.TopLeft;
            grid.Columns.Add(icon);
            grid.Columns.Add(time);
            grid.Columns.Add(text);
        }

        private void OnAdded(JournalEntry entry)
        {
            AddRow(entry, true);
            UpdateEmpty();
        }

        private void AddRow(JournalEntry entry, bool onTop)
        {
            Image image = entry.Status.HasValue ? StatusIconPainter.Paint(entry.Status.Value).ToBitmap() : infoImage;
            object[] values = { image, entry.Time.ToString("dd.MM.yyyy HH:mm:ss"), entry.Text };
            if (onTop) grid.Rows.Insert(0, values);
            else grid.Rows.Add(values);
        }

        private void UpdateEmpty()
        {
            empty.Visible = grid.Rows.Count == 0;
        }
    }
}
