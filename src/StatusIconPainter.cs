using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace AgentVpnGuard
{
    internal static class StatusIconPainter
    {
        private static readonly Dictionary<GuardStatus, Icon> Cache = new Dictionary<GuardStatus, Icon>();

        public static Color ColorOf(GuardStatus status)
        {
            if (status == GuardStatus.Protected) return Color.FromArgb(46, 160, 67);
            if (status == GuardStatus.Offline) return Color.FromArgb(110, 118, 129);
            if (status == GuardStatus.Warning) return Color.FromArgb(219, 143, 0);
            return Color.FromArgb(218, 54, 51);
        }

        public static Icon Paint(GuardStatus status)
        {
            Icon icon;
            if (Cache.TryGetValue(status, out icon)) return icon;
            icon = Create(status);
            Cache[status] = icon;
            return icon;
        }

        private static Icon Create(GuardStatus status)
        {
            Size size = SystemInformation.SmallIconSize;
            using (var bitmap = new Bitmap(size.Width, size.Height))
            using (Graphics graphics = Graphics.FromImage(bitmap))
            {
                graphics.SmoothingMode = SmoothingMode.AntiAlias;
                graphics.Clear(Color.Transparent);
                float w = size.Width;
                float h = size.Height;
                using (GraphicsPath shield = Shield(w, h))
                using (var fill = new SolidBrush(ColorOf(status)))
                using (var outline = new Pen(Color.FromArgb(170, 0, 0, 0), 1f))
                {
                    graphics.FillPath(fill, shield);
                    graphics.DrawPath(outline, shield);
                }
                DrawMark(graphics, status, w, h);
                IntPtr handle = bitmap.GetHicon();
                try
                {
                    using (Icon temporary = Icon.FromHandle(handle))
                    {
                        return (Icon)temporary.Clone();
                    }
                }
                finally
                {
                    DestroyIcon(handle);
                }
            }
        }

        private static GraphicsPath Shield(float w, float h)
        {
            var path = new GraphicsPath();
            float left = w * 0.12f;
            float right = w * 0.88f;
            float top = h * 0.06f;
            path.AddLine(w / 2f, top, right, top + h * 0.14f);
            path.AddBezier(right, top + h * 0.14f, right, h * 0.62f, w * 0.7f, h * 0.82f, w / 2f, h * 0.95f);
            path.AddBezier(w / 2f, h * 0.95f, w * 0.3f, h * 0.82f, left, h * 0.62f, left, top + h * 0.14f);
            path.CloseFigure();
            return path;
        }

        private static void DrawMark(Graphics graphics, GuardStatus status, float w, float h)
        {
            using (var pen = new Pen(Color.White, Math.Max(1.6f, w / 9f)))
            {
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                if (status == GuardStatus.Protected)
                {
                    graphics.DrawLines(pen, new[] { new PointF(w * 0.32f, h * 0.48f), new PointF(w * 0.46f, h * 0.62f), new PointF(w * 0.69f, h * 0.36f) });
                }
                else if (status == GuardStatus.Offline)
                {
                    graphics.DrawLine(pen, w * 0.33f, h * 0.48f, w * 0.67f, h * 0.48f);
                }
                else
                {
                    graphics.DrawLine(pen, w / 2f, h * 0.28f, w / 2f, h * 0.52f);
                    graphics.DrawLine(pen, w / 2f, h * 0.68f, w / 2f, h * 0.69f);
                }
            }
        }

        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr handle);
    }
}
