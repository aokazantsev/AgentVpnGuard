using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace AgentVpnGuard
{
    internal static class ProxyProbe
    {
        private const int Port = 443;
        private const int TimeoutMs = 5000;

        public static bool Serves(IPAddress proxy, IPAddress vpnAddress, int vpnIndex, string host, out string detail)
        {
            int routeIndex = RouteInspector.BestInterfaceIndex(proxy);
            if (routeIndex != vpnIndex)
            {
                detail = "путь к прокси VPN " + proxy + " идёт мимо VPN";
                return false;
            }
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                socket.ReceiveTimeout = TimeoutMs;
                socket.SendTimeout = TimeoutMs;
                try
                {
                    socket.Bind(new IPEndPoint(vpnAddress, 0));
                    IAsyncResult connecting = socket.BeginConnect(new IPEndPoint(proxy, Port), null, null);
                    if (!connecting.AsyncWaitHandle.WaitOne(TimeoutMs))
                    {
                        detail = "прокси VPN " + proxy + " не ответил за " + TimeoutMs / 1000 + " с";
                        return false;
                    }
                    socket.EndConnect(connecting);
                    var local = socket.LocalEndPoint as IPEndPoint;
                    if (local == null || !local.Address.Equals(vpnAddress))
                    {
                        detail = "соединение с прокси VPN ушло не с адреса VPN";
                        return false;
                    }
                    using (var stream = new NetworkStream(socket, false))
                    using (var tls = new SslStream(stream, false))
                    {
                        tls.AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
                    }
                }
                catch (AuthenticationException)
                {
                    detail = "прокси VPN " + proxy + " подменяет сертификат";
                    return false;
                }
                catch (IOException)
                {
                    detail = "прокси VPN " + proxy + " обрывает соединение";
                    return false;
                }
                catch (SocketException error)
                {
                    detail = "прокси VPN " + proxy + " не отвечает: " + error.Message;
                    return false;
                }
            }
            detail = "прокси VPN " + proxy + " пропускает";
            return true;
        }
    }
}
