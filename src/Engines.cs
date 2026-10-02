using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace ProtoHaxForward
{
    // 把内嵌的 WinDivert.dll / WinDivert64.sys 释放到临时目录并加载。
    internal static class DivertLoader
    {
        private static readonly object Sync = new object();
        private static bool _loaded;

        public static void EnsureLoaded()
        {
            lock (Sync)
            {
                if (_loaded) { return; }

                string dir = Path.Combine(Path.GetTempPath(), "ProtoHax");
                Directory.CreateDirectory(dir);

                Extract("WinDivert.dll", Path.Combine(dir, "WinDivert.dll"));
                Extract("WinDivert64.sys", Path.Combine(dir, "WinDivert64.sys"));

                Native.SetDllDirectoryW(dir);

                IntPtr h = Native.LoadLibraryW(Path.Combine(dir, "WinDivert.dll"));
                if (h == IntPtr.Zero)
                {
                    throw new Exception("加载 WinDivert.dll 失败：" +
                        new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }
                _loaded = true;
            }
        }

        private static void Extract(string resourceName, string targetPath)
        {
            try
            {
                Assembly asm = Assembly.GetExecutingAssembly();
                using (Stream src = asm.GetManifestResourceStream(resourceName))
                {
                    if (src == null) { throw new Exception("缺少内嵌资源：" + resourceName); }

                    if (File.Exists(targetPath) && new FileInfo(targetPath).Length == src.Length)
                    {
                        return;   // 已存在且大小一致，避免覆盖正在被占用的文件
                    }

                    byte[] buffer = new byte[src.Length];
                    int read = 0;
                    while (read < buffer.Length)
                    {
                        int n = src.Read(buffer, read, buffer.Length - read);
                        if (n <= 0) { break; }
                        read += n;
                    }
                    File.WriteAllBytes(targetPath, buffer);
                }
            }
            catch (IOException)
            {
                // 文件被占用（例如驱动已加载），沿用现有文件即可
                if (!File.Exists(targetPath)) { throw; }
            }
        }
    }

    // 透明强制转发：拦截客户端发往任意服务器的 RakNet(UDP) 包，
    // 把目的地址改写为你指定的目标服务器；回包再把源地址改回原服务器。
    internal sealed class DivertRedirector
    {
        private const int MaxMapEntries = 4096;
        private const int MapIdleSeconds = 180;

        private sealed class Origin
        {
            public uint Ip;
            public ushort Port;
            public long Ticks;
        }

        private readonly string _targetIpText;
        private readonly int _targetPort;
        private readonly int[] _interceptPorts;

        private uint _targetIp;
        private ushort _targetPortNet;

        private IntPtr _hOut = IntPtr.Zero;
        private IntPtr _hRet = IntPtr.Zero;
        private Thread _tOut;
        private Thread _tRet;
        private Thread _tPrune;
        private volatile bool _running;

        // 键是 (客户端IP, 客户端端口) 打包成的 64 位整数：热路径上不产生任何字符串分配。
        private readonly Dictionary<ulong, Origin> _map = new Dictionary<ulong, Origin>();
        private readonly object _sync = new object();
        private long _redirected;

        public bool Verbose;

        public event Action<string> Message;

        public DivertRedirector(string targetIpText, int targetPort, int[] interceptPorts)
        {
            _targetIpText = targetIpText;
            _targetPort = targetPort;
            _interceptPorts = interceptPorts;
        }

        public bool IsRunning { get { return _running; } }

        public void Start()
        {
            if (_running) { return; }
            if (_interceptPorts == null || _interceptPorts.Length == 0)
            {
                throw new Exception("拦截端口列表为空。");
            }

            uint parsedIp;
            if (!PacketUtil.TryParseIPv4(_targetIpText, out parsedIp))
            {
                throw new Exception("目标地址必须是 IPv4 地址（透明模式暂只支持 IPv4）。");
            }
            _targetIp = parsedIp;
            _targetPortNet = PacketUtil.ToNetU16(_targetPort);

            DivertLoader.EnsureLoaded();

            string filterOut = BuildOutFilter();
            string filterRet = BuildRetFilter();

            Emit("拦截过滤器(出)： " + filterOut);
            Emit("拦截过滤器(回)： " + filterRet);

            _hOut = OpenHandle(filterOut);
            try
            {
                _hRet = OpenHandle(filterRet);
            }
            catch
            {
                Native.WinDivertClose(_hOut);
                _hOut = IntPtr.Zero;
                throw;
            }

            _running = true;

            _tOut = new Thread(LoopOut);
            _tOut.IsBackground = true;
            _tOut.Start();

            _tRet = new Thread(LoopRet);
            _tRet.IsBackground = true;
            _tRet.Start();

            _tPrune = new Thread(PruneLoop);
            _tPrune.IsBackground = true;
            _tPrune.Start();

            Emit("透明转发已启动：任意服务器 -> " + _targetIpText + ":" + _targetPort);
        }

        public void Stop()
        {
            if (!_running) { return; }
            _running = false;

            if (_hOut != IntPtr.Zero) { Native.WinDivertClose(_hOut); _hOut = IntPtr.Zero; }
            if (_hRet != IntPtr.Zero) { Native.WinDivertClose(_hRet); _hRet = IntPtr.Zero; }

            lock (_sync) { _map.Clear(); }
            Emit("透明转发已停止。");
        }

        private IntPtr OpenHandle(string filter)
        {
            IntPtr h = Native.WinDivertOpen(filter, Native.WINDIVERT_LAYER_NETWORK, 0, 0);
            if (h == IntPtr.Zero || h == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                throw new Exception("WinDivertOpen 失败：" + new Win32Exception(err).Message +
                    "（错误码 " + err + "；请确认以管理员身份运行）");
            }

            // 把内核队列从默认 4096 提到 8192，降低突发流量下的丢包概率。
            Native.WinDivertSetParam(h, Native.WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
            return h;
        }

        private string BuildOutFilter()
        {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 0; i < _interceptPorts.Length; i++)
            {
                if (i > 0) { sb.Append(" or "); }
                sb.Append("udp.DstPort == ").Append(_interceptPorts[i]);
            }
            // not impostor：防止把本程序回注的包再抓一次导致死循环
            return "outbound and udp and (" + sb + ") and not impostor";
        }

        private string BuildRetFilter()
        {
            // 不限方向：loopback 回包在 WinDivert 里也算 outbound
            return "udp and ip.SrcAddr == " + _targetIpText +
                   " and udp.SrcPort == " + _targetPort + " and not impostor";
        }

        private void Emit(string text)
        {
            Action<string> h = Message;
            if (h != null) { h(text); }
        }

        private void LoopOut()
        {
            byte[] packet = new byte[65535];
            WINDIVERT_ADDRESS addr = new WINDIVERT_ADDRESS();

            while (_running)
            {
                uint recvLen;
                if (!Native.WinDivertRecv(_hOut, packet, (uint)packet.Length, out recvLen, ref addr))
                {
                    if (!_running) { break; }
                    continue;
                }

                int len = (int)recvLen;
                int udpOff;
                if (!PacketUtil.TryParseUdpV4(packet, len, out udpOff))
                {
                    Reinject(_hOut, packet, len, ref addr);   // 非 IPv4/UDP，原样放行
                    continue;
                }

                uint srcIp = PacketUtil.ReadU32(packet, PacketUtil.IP_SRC);
                ushort srcPort = PacketUtil.ReadU16(packet, udpOff);
                uint dstIp = PacketUtil.ReadU32(packet, PacketUtil.IP_DST);
                ushort dstPort = PacketUtil.ReadU16(packet, udpOff + 2);

                Record(srcIp, srcPort, dstIp, dstPort);

                if (Verbose && !Log.Saturated)
                {
                    Emit("出包 " + Format(srcIp, srcPort) + " -> " + Format(dstIp, dstPort) +
                         "  改写目标为 " + _targetIpText + ":" + _targetPort +
                         "  IfIdx=" + addr.IfIdx + " out=" + addr.IsOutbound + " loop=" + ((addr.Flags & (1u << 18)) != 0));
                }

                PacketUtil.WriteU32(packet, PacketUtil.IP_DST, _targetIp);
                PacketUtil.WriteU16(packet, udpOff + 2, _targetPortNet);

                Native.WinDivertHelperCalcChecksums(packet, (uint)len, ref addr, 0);
                if (!Reinject(_hOut, packet, len, ref addr) && Verbose)
                {
                    Emit("出包回注失败：错误码 " + Marshal.GetLastWin32Error());
                }

                long n = Interlocked.Increment(ref _redirected);
                if (n == 1 || n % 500 == 0)
                {
                    Emit("已重定向 " + n + " 个数据包（最近：" + Format(srcIp, srcPort) +
                         " 原目标 " + Format(dstIp, dstPort) + "）");
                }
            }
        }

        private void LoopRet()
        {
            byte[] packet = new byte[65535];
            WINDIVERT_ADDRESS addr = new WINDIVERT_ADDRESS();

            while (_running)
            {
                uint recvLen;
                if (!Native.WinDivertRecv(_hRet, packet, (uint)packet.Length, out recvLen, ref addr))
                {
                    if (!_running) { break; }
                    continue;
                }

                int len = (int)recvLen;
                int udpOff;
                if (!PacketUtil.TryParseUdpV4(packet, len, out udpOff))
                {
                    Reinject(_hRet, packet, len, ref addr);
                    continue;
                }

                uint srcIp = PacketUtil.ReadU32(packet, PacketUtil.IP_SRC);
                ushort srcPort = PacketUtil.ReadU16(packet, udpOff);
                uint dstIp = PacketUtil.ReadU32(packet, PacketUtil.IP_DST);
                ushort dstPort = PacketUtil.ReadU16(packet, udpOff + 2);

                if (Verbose && !Log.Saturated)
                {
                    Emit("回包 " + Format(srcIp, srcPort) + " -> " + Format(dstIp, dstPort));
                }

                Origin origin = Lookup(dstIp, dstPort);
                if (origin == null)
                {
                    if (Verbose && !Log.Saturated) { Emit("  回包无匹配会话，原样放行"); }
                    Reinject(_hRet, packet, len, ref addr);   // 不是我们改写的会话，放行
                    continue;
                }

                if (Verbose && !Log.Saturated)
                {
                    Emit("  命中会话，源改回 " + Format(origin.Ip, origin.Port));
                }

                // 把源地址改回客户端原本要连的那台服务器，客户端才会接受这个回包
                PacketUtil.WriteU32(packet, PacketUtil.IP_SRC, origin.Ip);
                PacketUtil.WriteU16(packet, udpOff, origin.Port);

                Native.WinDivertHelperCalcChecksums(packet, (uint)len, ref addr, 0);
                if (!Reinject(_hRet, packet, len, ref addr) && Verbose)
                {
                    Emit("回包回注失败：错误码 " + Marshal.GetLastWin32Error());
                }
            }
        }

        private bool Reinject(IntPtr handle, byte[] packet, int len, ref WINDIVERT_ADDRESS addr)
        {
            // 不清理校验和标志位：WinDivertHelperCalcChecksums 已算好并置位，
            // 让 WinDivert 直接采用，避免其内部重算路径出问题。
            uint sent;
            return Native.WinDivertSend(handle, packet, (uint)len, out sent, ref addr);
        }

        private static string Format(uint ip, ushort netPort)
        {
            byte[] b = BitConverter.GetBytes(ip);
            int port = ((netPort & 0xFF) << 8) | ((netPort >> 8) & 0xFF);
            return b[0] + "." + b[1] + "." + b[2] + "." + b[3] + ":" + port;
        }

        private static ulong Key(uint ip, ushort netPort)
        {
            return ((ulong)ip << 16) | netPort;
        }

        private void Record(uint srcIp, ushort srcPort, uint dstIp, ushort dstPort)
        {
            ulong key = Key(srcIp, srcPort);
            lock (_sync)
            {
                Origin o;
                if (!_map.TryGetValue(key, out o))
                {
                    if (_map.Count >= MaxMapEntries) { return; }
                    o = new Origin();
                    _map[key] = o;
                    Emit("新会话 " + Format(srcIp, srcPort) + "  原目标 " + Format(dstIp, dstPort));
                }
                o.Ip = dstIp;
                o.Port = dstPort;
                o.Ticks = DateTime.UtcNow.Ticks;
            }
        }

        private Origin Lookup(uint dstIp, ushort dstPort)
        {
            ulong key = Key(dstIp, dstPort);
            lock (_sync)
            {
                Origin o;
                if (!_map.TryGetValue(key, out o)) { return null; }
                o.Ticks = DateTime.UtcNow.Ticks;
                return o;
            }
        }

        private void PruneLoop()
        {
            while (_running)
            {
                Thread.Sleep(15000);
                if (!_running) { break; }

                long cutoff = DateTime.UtcNow.AddSeconds(-MapIdleSeconds).Ticks;
                List<ulong> dead = new List<ulong>();
                lock (_sync)
                {
                    foreach (KeyValuePair<ulong, Origin> kv in _map)
                    {
                        if (kv.Value.Ticks < cutoff) { dead.Add(kv.Key); }
                    }
                    foreach (ulong k in dead) { _map.Remove(k); }
                }
            }
        }
    }

    // 免驱动的本地中继模式：在本地端口监听，转发到目标服务器。
    internal sealed class UdpRelay
    {
        private const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);
        private const int MaxSessions = 256;
        private const int IdleSeconds = 90;

        private Socket _listener;
        private Thread _listenThread;
        private Thread _cleanThread;
        private volatile bool _running;
        private IPEndPoint _target;
        private readonly Dictionary<string, RelaySession> _sessions = new Dictionary<string, RelaySession>();
        private readonly object _sync = new object();

        public event Action<string> Message;

        public bool IsRunning { get { return _running; } }

        public void Start(int listenPort, IPEndPoint target)
        {
            if (_running) { return; }

            _target = target;
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try { s.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null); }
            catch { }
            s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            s.Bind(new IPEndPoint(IPAddress.Any, listenPort));
            _listener = s;
            _running = true;

            _listenThread = new Thread(ListenLoop);
            _listenThread.IsBackground = true;
            _listenThread.Start();

            _cleanThread = new Thread(CleanLoop);
            _cleanThread.IsBackground = true;
            _cleanThread.Start();

            Emit("已启动：监听 0.0.0.0:" + listenPort + "  ->  " + target.Address + ":" + target.Port);
        }

        public void Stop()
        {
            if (!_running) { return; }
            _running = false;
            try { _listener.Close(); } catch { }
            lock (_sync)
            {
                foreach (KeyValuePair<string, RelaySession> kv in _sessions) { kv.Value.Close(); }
                _sessions.Clear();
            }
            Emit("已停止转发。");
        }

        private void Emit(string text)
        {
            Action<string> h = Message;
            if (h != null) { h(text); }
        }

        private void ListenLoop()
        {
            byte[] buf = new byte[65535];
            EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
            while (_running)
            {
                int n;
                try { n = _listener.ReceiveFrom(buf, ref remote); }
                catch { if (!_running) { break; } continue; }
                if (n <= 0) { continue; }

                IPEndPoint from = (IPEndPoint)remote;
                RelaySession session = GetSession(from);
                if (session == null) { continue; }

                byte[] data = new byte[n];
                Buffer.BlockCopy(buf, 0, data, 0, n);
                session.SendToTarget(data);
            }
        }

        private RelaySession GetSession(IPEndPoint from)
        {
            string key = from.Address + ":" + from.Port;
            lock (_sync)
            {
                RelaySession s;
                if (_sessions.TryGetValue(key, out s)) { return s; }
                if (_sessions.Count >= MaxSessions) { return null; }

                s = new RelaySession(_listener, from, _target);
                _sessions[key] = s;
                s.StartPump();
                Emit("新会话 " + key + "  ->  " + _target);
                return s;
            }
        }

        private void CleanLoop()
        {
            while (_running)
            {
                Thread.Sleep(10000);
                if (!_running) { break; }

                long cutoff = DateTime.UtcNow.AddSeconds(-IdleSeconds).Ticks;
                List<string> dead = new List<string>();
                lock (_sync)
                {
                    foreach (KeyValuePair<string, RelaySession> kv in _sessions)
                    {
                        if (kv.Value.LastActiveTicks < cutoff) { dead.Add(kv.Key); }
                    }
                    foreach (string k in dead)
                    {
                        RelaySession s;
                        if (_sessions.TryGetValue(k, out s))
                        {
                            s.Close();
                            _sessions.Remove(k);
                            Emit("会话空闲回收 " + k);
                        }
                    }
                }
            }
        }
    }

    internal sealed class RelaySession
    {
        private const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);

        private readonly Socket _downstream;
        private readonly Socket _upstream;
        private readonly object _upLock = new object();
        private readonly object _downLock = new object();
        private long _lastActiveTicks;

        public readonly IPEndPoint Client;

        public RelaySession(Socket downstream, IPEndPoint client, IPEndPoint target)
        {
            _downstream = downstream;
            Client = client;
            _upstream = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try { _upstream.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null); }
            catch { }
            _upstream.Connect(target);
            _lastActiveTicks = DateTime.UtcNow.Ticks;
        }

        public long LastActiveTicks { get { return Interlocked.Read(ref _lastActiveTicks); } }

        private void Touch() { Interlocked.Exchange(ref _lastActiveTicks, DateTime.UtcNow.Ticks); }

        public void StartPump()
        {
            Thread t = new Thread(Pump);
            t.IsBackground = true;
            t.Start();
        }

        public void SendToTarget(byte[] data)
        {
            try
            {
                lock (_upLock) { _upstream.Send(data); }
                Touch();
            }
            catch { }
        }

        private void Pump()
        {
            byte[] buf = new byte[65535];
            while (true)
            {
                int n;
                try { n = _upstream.Receive(buf); }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionReset) { continue; }
                    break;
                }
                catch { break; }

                if (n <= 0) { continue; }
                Touch();

                byte[] data = new byte[n];
                Buffer.BlockCopy(buf, 0, data, 0, n);
                try
                {
                    lock (_downLock) { _downstream.SendTo(data, Client); }
                }
                catch { }
            }
        }

        public void Close()
        {
            try { _upstream.Close(); } catch { }
        }
    }
}