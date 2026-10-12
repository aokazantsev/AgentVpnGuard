using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;

namespace AgentVpnGuard
{
    internal static class AdapterInventory
    {
        private const string ClassKey = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
        private const string ConnectionsKey = @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

        public static AdapterSnapshot Read(AppSettings settings)
        {
            var snapshot = new AdapterSnapshot();
            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                snapshot.Adapters.Add(Describe(networkInterface, settings));
            }
            AddRegisteredAdapters(snapshot, settings);
            return snapshot;
        }

        private static NetworkAdapter Describe(NetworkInterface networkInterface, AppSettings settings)
        {
            var adapter = new NetworkAdapter
            {
                Name = networkInterface.Name,
                Description = networkInterface.Description,
                IsPresent = true,
                IsUp = networkInterface.OperationalStatus == OperationalStatus.Up
            };
            adapter.IsVpn = settings.IsVpnAdapter(adapter.Description);
            try
            {
                IPInterfaceProperties properties = networkInterface.GetIPProperties();
                foreach (UnicastIPAddressInformation address in properties.UnicastAddresses) adapter.Addresses.Add(address.Address);
                foreach (IPAddress server in properties.DnsAddresses)
                {
                    if (server.AddressFamily == AddressFamily.InterNetwork) adapter.DnsServers.Add(server);
                }
                if (networkInterface.Supports(NetworkInterfaceComponent.IPv4))
                {
                    adapter.Ipv4Index = properties.GetIPv4Properties().Index;
                }
            }
            catch (NetworkInformationException)
            {
            }
            return adapter;
        }

        private static void AddRegisteredAdapters(AdapterSnapshot snapshot, AppSettings settings)
        {
            using (RegistryKey classes = Registry.LocalMachine.OpenSubKey(ClassKey))
            using (RegistryKey connections = Registry.LocalMachine.OpenSubKey(ConnectionsKey))
            {
                if (classes == null || connections == null) return;
                foreach (string subKeyName in classes.GetSubKeyNames())
                {
                    RegistryKey driver;
                    try
                    {
                        driver = classes.OpenSubKey(subKeyName);
                    }
                    catch (System.Security.SecurityException)
                    {
                        continue;
                    }
                    using (driver)
                    {
                        if (driver == null) continue;
                        string instanceId = driver.GetValue("NetCfgInstanceId") as string;
                        string description = driver.GetValue("DriverDesc") as string;
                        if (string.IsNullOrEmpty(instanceId)) continue;
                        string name = ConnectionName(connections, instanceId);
                        if (string.IsNullOrEmpty(name)) continue;
                        if (snapshot.Adapters.Exists(adapter => string.Equals(adapter.Name, name, StringComparison.OrdinalIgnoreCase))) continue;
                        snapshot.Adapters.Add(new NetworkAdapter
                        {
                            Name = name,
                            Description = description ?? "",
                            IsVpn = settings.IsVpnAdapter(description)
                        });
                    }
                }
            }
        }

        private static string ConnectionName(RegistryKey connections, string instanceId)
        {
            using (RegistryKey connection = connections.OpenSubKey(instanceId + @"\Connection"))
            {
                return connection == null ? null : connection.GetValue("Name") as string;
            }
        }
    }
}
