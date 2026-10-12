using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace AgentVpnGuard
{
    internal static class ClaudeProbe
    {
        public const string Host = "api.anthropic.com";

        private const int Port = 443;
        private const int TimeoutMs = 5000;

        public static void CheckAsync(IPAddress target, IPAddress vpnAddress, int vpnIndex, Action<ProbeOutcome, string> done)
        {
            ThreadPool.QueueUserWorkItem(state =>
            {
                ProbeOutcome outcome;
                string detail;
                try
                {
                    outcome = Check(target, vpnAddress, vpnIndex, out detail);
                }
                catch (Exception error)
                {
                    AppLog.Append("probe failed: " + error);
                    outcome = ProbeOutcome.Unreachable;
                    detail = error.Message;
                }
                done(outcome, detail);
            });
        }

        private static ProbeOutcome Check(IPAddress target, IPAddress vpnAddress, int vpnIndex, out string detail)
        {
            int routeIndex = RouteInspector.BestInterfaceIndex(target);
            if (routeIndex != vpnIndex)
            {
                detail = "маршрут к " + target + " идёт через адаптер " + routeIndex + ", а не через VPN";
                return ProbeOutcome.Bypass;
            }
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    socket.Bind(new IPEndPoint(vpnAddress, 0));
                    IAsyncResult connecting = socket.BeginConnect(new IPEndPoint(target, Port), null, null);
                    if (!connecting.AsyncWaitHandle.WaitOne(TimeoutMs))
                    {
                        detail = target + ":" + Port + " не ответил за " + TimeoutMs / 1000 + " с";
                        return ProbeOutcome.Unreachable;
                    }
                    socket.EndConnect(connecting);
                }
                catch (SocketException error)
                {
                    detail = target + ":" + Port + " — " + error.Message;
                    return ProbeOutcome.Unreachable;
                }
                var local = socket.LocalEndPoint as IPEndPoint;
                if (local == null || !local.Address.Equals(vpnAddress))
                {
                    detail = "соединение ушло не с адреса VPN";
                    return ProbeOutcome.Bypass;
                }
                detail = target + ":" + Port;
                return ProbeOutcome.Reachable;
            }
        }
    }
}
