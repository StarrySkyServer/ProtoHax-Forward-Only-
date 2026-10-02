using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace ProtoHaxForward
{
    // 成品、配置、日志共用一个名字，改这里即可整体改名。
    internal static class AppInfo
    {
        public const string Name = "ProtoHax (Forward Only)";
        public const string LegacyName = "ProtoHaxForward";
    }

    // 落盘日志：界面日志之外再写一份文件，便于事后排查。
    // 调用方只入队、绝不做文件 IO；后台线程成批写盘；积压时置 Saturated 让热路径跳过详细日志。
    internal static class Log
    {
        private const int MaxQueued = 20000;
        private const int SaturateAt = 8000;
        private const int ReleaseAt = 1000;
        private const int BatchMax = 1024;

        private static readonly object Sync = new object();
        private static readonly Queue<string> Pending = new Queue<string>();
        private static StreamWriter _writer;
        private static long _dropped;
        private static volatile bool _saturated;

        public static readonly string Path =
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, AppInfo.Name + ".log");

        // 队列积压时置位。热路径据此跳过详细日志的字符串拼接，避免日志拖慢转发。
        public static bool Saturated { get { return _saturated; } }

        static Log()
        {
            Thread t = new Thread(Pump);
            t.IsBackground = true;
            t.Start();
        }

        public static void Write(string text)
        {
            lock (Sync)
            {
                if (Pending.Count >= MaxQueued) { _dropped++; return; }
                Pending.Enqueue(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "  " + text);
                if (Pending.Count >= SaturateAt) { _saturated = true; }
                Monitor.Pulse(Sync);
            }
        }

        public static void Reset()
        {
            try
            {
                lock (Sync)
                {
                    if (_writer != null)
                    {
                        try { _writer.Flush(); _writer.Dispose(); } catch { }
                        _writer = null;
                    }
                    _dropped = 0;
                    _saturated = false;
                }
                File.WriteAllText(Path, "");
            }
            catch { }
        }

        private static void Pump()
        {
            StringBuilder batch = new StringBuilder(64 * 1024);
            while (true)
            {
                string first = null;
                lock (Sync)
                {
                    if (Pending.Count == 0) { Monitor.Wait(Sync, 250); }
                    if (Pending.Count > 0) { first = Pending.Dequeue(); }
                }
                if (first == null) { continue; }

                // 一次锁内尽量多取，把“每行一次写盘”压成“每批一次”。
                batch.Length = 0;
                batch.Append(first).Append('\n');
                int taken = 1;
                while (taken < BatchMax)
                {
                    string s;
                    lock (Sync)
                    {
                        if (Pending.Count == 0) { break; }
                        s = Pending.Dequeue();
                    }
                    batch.Append(s).Append('\n');
                    taken++;
                }

                lock (Sync)
                {
                    if (_dropped > 0)
                    {
                        batch.Append("（日志过载，已丢弃 ").Append(_dropped).Append(" 条）\n");
                        _dropped = 0;
                    }
                    if (Pending.Count < ReleaseAt) { _saturated = false; }
                }

                try
                {
                    if (_writer == null) { _writer = new StreamWriter(Path, true, Encoding.UTF8); }
                    _writer.Write(batch.ToString());
                    _writer.Flush();
                }
                catch { }
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Log.Reset();
            Log.Write("=== " + AppInfo.Name + " 启动 ===  管理员=" + MainForm.IsAdministrator() +
                      "  exe=" + Application.ExecutablePath);

            Application.ThreadException += delegate(object s, ThreadExceptionEventArgs e)
            {
                Log.Write("[UI异常] " + e.Exception);
            };
            AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e)
            {
                Log.Write("[致命异常] " + e.ExceptionObject);
            };

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            Log.Write("=== 程序退出 ===");
        }
    }

    internal sealed class MainForm : Form
    {
        private readonly UdpRelay _relay = new UdpRelay();
        private readonly string _iniPath;

        private RadioButton _rbTransparent;
        private RadioButton _rbRelay;
        private TextBox _txtHost;
        private TextBox _txtTargetPort;
        private TextBox _txtPorts;
        private TextBox _txtListenPort;
        private Label _lblPorts;
        private Button _btnToggle;
        private CheckBox _chkVerbose;
        private Label _lblHint;
        private TextBox _log;
        private readonly Queue<string> _pendingUi = new Queue<string>();
        private long _uiDropped;
        private System.Windows.Forms.Timer _uiTimer;

        private DivertRedirector _divert;
        private bool _running;

        private const string DefaultInterceptPorts = "19132,19134";
        private const string LegacyDefaultInterceptPorts = "19132,19133";

        public MainForm()
        {
            _iniPath = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), AppInfo.Name + ".ini");
            BuildUi();

            // 标题栏/任务栏图标跟随 exe 内嵌图标。
            try { Icon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch { }

            // 界面日志节流：逐包日志量大时，合并成每 200ms 一批刷新，避免 UI 线程被刷屏卡死。
            _uiTimer = new System.Windows.Forms.Timer();
            _uiTimer.Interval = 200;
            _uiTimer.Tick += delegate { FlushUiLog(); };
            _uiTimer.Start();

            _relay.Message += OnEngineMessage;
            LoadConfig();
            UpdateMode();
            UpdateHint();
        }

        private void BuildUi()
        {
            Text = AppInfo.Name;
            ClientSize = new Size(620, 556);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9F);

            _rbTransparent = new RadioButton();
            _rbTransparent.Text = "透明强制转发（需管理员，WinDivert 驱动）";
            _rbTransparent.Location = new Point(14, 12);
            _rbTransparent.Size = new Size(340, 22);
            _rbTransparent.Checked = true;
            _rbTransparent.CheckedChanged += OnModeChanged;
            Controls.Add(_rbTransparent);

            _rbRelay = new RadioButton();
            _rbRelay.Text = "本地中继（免驱动，需在游戏内填本机地址）";
            _rbRelay.Location = new Point(14, 36);
            _rbRelay.Size = new Size(340, 22);
            _rbRelay.CheckedChanged += OnModeChanged;
            Controls.Add(_rbRelay);

            Label l1 = new Label();
            l1.Text = "目标服务器";
            l1.Location = new Point(14, 74);
            l1.Size = new Size(70, 22);
            Controls.Add(l1);

            _txtHost = new TextBox();
            _txtHost.Location = new Point(88, 71);
            _txtHost.Size = new Size(250, 24);
            Controls.Add(_txtHost);

            Label l2 = new Label();
            l2.Text = "端口";
            l2.Location = new Point(348, 74);
            l2.Size = new Size(36, 22);
            Controls.Add(l2);

            _txtTargetPort = new TextBox();
            _txtTargetPort.Location = new Point(388, 71);
            _txtTargetPort.Size = new Size(70, 24);
            Controls.Add(_txtTargetPort);

            _lblPorts = new Label();
            _lblPorts.Text = "拦截端口";
            _lblPorts.Location = new Point(14, 108);
            _lblPorts.Size = new Size(118, 22);
            Controls.Add(_lblPorts);

            _txtPorts = new TextBox();
            _txtPorts.Location = new Point(136, 105);
            _txtPorts.Size = new Size(160, 24);
            Controls.Add(_txtPorts);

            Label l4 = new Label();
            l4.Text = "（逗号分隔，如 19132,19134）";
            l4.ForeColor = Color.DimGray;
            l4.Location = new Point(304, 108);
            l4.Size = new Size(230, 22);
            Controls.Add(l4);

            Label l5 = new Label();
            l5.Text = "本地监听端口";
            l5.Location = new Point(14, 142);
            l5.Size = new Size(118, 22);
            Controls.Add(l5);

            _txtListenPort = new TextBox();
            _txtListenPort.Location = new Point(136, 139);
            _txtListenPort.Size = new Size(80, 24);
            _txtListenPort.TextChanged += OnListenPortChanged;
            Controls.Add(_txtListenPort);

            _btnToggle = new Button();
            _btnToggle.Text = "启动转发";
            _btnToggle.Location = new Point(14, 178);
            _btnToggle.Size = new Size(140, 32);
            _btnToggle.Click += OnToggleClick;
            Controls.Add(_btnToggle);

            _chkVerbose = new CheckBox();
            _chkVerbose.Text = "详细日志（诊断用）";
            _chkVerbose.Location = new Point(170, 184);
            _chkVerbose.Size = new Size(170, 22);
            Controls.Add(_chkVerbose);

            _lblHint = new Label();
            _lblHint.Location = new Point(14, 220);
            _lblHint.Size = new Size(592, 60);
            _lblHint.ForeColor = Color.FromArgb(0, 90, 160);
            Controls.Add(_lblHint);

            _log = new TextBox();
            _log.Location = new Point(14, 286);
            _log.Size = new Size(592, 256);
            _log.Multiline = true;
            _log.ReadOnly = true;
            _log.ScrollBars = ScrollBars.Vertical;
            _log.BackColor = Color.White;
            _log.Font = new Font("Consolas", 9F);
            Controls.Add(_log);

            FormClosing += OnFormClosing;
        }

        private bool TransparentMode { get { return _rbTransparent.Checked; } }

        private void OnModeChanged(object sender, EventArgs e)
        {
            if (_running) { return; }
            UpdateMode();
            UpdateHint();
        }

        private void UpdateMode()
        {
            bool t = TransparentMode;
            _txtPorts.Enabled = t;
            _lblPorts.Enabled = t;
            _txtListenPort.Enabled = !t;
        }

        private void OnListenPortChanged(object sender, EventArgs e)
        {
            UpdateHint();
        }

        private void OnToggleClick(object sender, EventArgs e)
        {
            if (_running) { StopEngine(); }
            else { StartEngine(); }
        }

        private void StartEngine()
        {
            string host = _txtHost.Text.Trim();
            Log.Write("[启动请求] 模式=" + (TransparentMode ? "Transparent" : "Relay") +
                      " 目标=" + host + ":" + _txtTargetPort.Text.Trim() +
                      " 拦截端口=" + _txtPorts.Text.Trim() +
                      " 详细日志=" + _chkVerbose.Checked +
                      " 管理员=" + IsAdministrator());
            if (host.Length == 0)
            {
                Warn("请先填写目标服务器地址。");
                return;
            }

            int targetPort;
            if (!int.TryParse(_txtTargetPort.Text.Trim(), out targetPort) || targetPort < 1 || targetPort > 65535)
            {
                Warn("目标端口不合法。");
                return;
            }

            if (TransparentMode)
            {
                if (!IsAdministrator())
                {
                    Warn("透明模式需要管理员权限。\r\n请右键本程序 →「以管理员身份运行」。");
                    return;
                }

                IPAddress ip = ResolveIPv4(host);
                if (ip == null)
                {
                    Warn("无法解析目标地址：" + host);
                    return;
                }

                int[] ports = ParsePorts(_txtPorts.Text);
                if (ports.Length == 0)
                {
                    Warn("拦截端口列表不合法，示例：19132,19134");
                    return;
                }

                try
                {
                    _divert = new DivertRedirector(ip.ToString(), targetPort, ports);
                    _divert.Verbose = _chkVerbose.Checked;
                    _divert.Message += OnEngineMessage;
                    _divert.Start();
                    Log.Write("[启动] 透明转发已启动：目标 " + ip + ":" + targetPort +
                              " 拦截端口 " + string.Join(",", ports));
                }
                catch (Exception ex)
                {
                    _divert = null;
                    Warn("启动透明转发失败：\r\n" + ex.Message);
                    return;
                }
            }
            else
            {
                int listenPort;
                if (!int.TryParse(_txtListenPort.Text.Trim(), out listenPort) || listenPort < 1 || listenPort > 65535)
                {
                    Warn("本地监听端口不合法。");
                    return;
                }

                IPAddress ip = ResolveIPv4(host);
                if (ip == null)
                {
                    Warn("无法解析目标地址：" + host);
                    return;
                }

                try
                {
                    _relay.Start(listenPort, new IPEndPoint(ip, targetPort));
                }
                catch (Exception ex)
                {
                    Warn("启动中继失败：" + ex.Message + "\r\n常见原因：端口被占用；或需要放行 Windows 防火墙。");
                    return;
                }
            }

            _running = true;
            SetRunning(true);
            SaveConfig();
            UpdateHint();
        }

        private void StopEngine()
        {
            Log.Write("[停止] 用户停止转发。");
            if (_divert != null)
            {
                try { _divert.Stop(); } catch { }
                _divert = null;
            }
            try { _relay.Stop(); } catch { }
            _running = false;
            SetRunning(false);
            UpdateHint();
        }

        private void SetRunning(bool running)
        {
            _btnToggle.Text = running ? "停止转发" : "启动转发";
            _rbTransparent.Enabled = !running;
            _rbRelay.Enabled = !running;
            _txtHost.Enabled = !running;
            _txtTargetPort.Enabled = !running;
            _txtPorts.Enabled = !running && TransparentMode;
            _txtListenPort.Enabled = !running && !TransparentMode;
            _chkVerbose.Enabled = !running;
        }

        internal static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity id = WindowsIdentity.GetCurrent();
                WindowsPrincipal p = new WindowsPrincipal(id);
                return p.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private static int[] ParsePorts(string text)
        {
            List<int> list = new List<int>();
            string[] parts = text.Split(new char[] { ',', '，', ' ', ';', '；' });
            foreach (string raw in parts)
            {
                string s = raw.Trim();
                if (s.Length == 0) { continue; }
                int p;
                if (!int.TryParse(s, out p) || p < 1 || p > 65535) { return new int[0]; }
                if (!list.Contains(p)) { list.Add(p); }
            }
            return list.ToArray();
        }

        private static IPAddress ResolveIPv4(string host)
        {
            IPAddress direct;
            if (IPAddress.TryParse(host, out direct)) { return direct; }
            try
            {
                IPAddress[] all = Dns.GetHostAddresses(host);
                foreach (IPAddress a in all)
                {
                    if (a.AddressFamily == AddressFamily.InterNetwork) { return a; }
                }
                if (all.Length > 0) { return all[0]; }
            }
            catch { }
            return null;
        }

        // 引擎线程直接入队，不再逐包 BeginInvoke——那会给每个包投递一条窗口消息，
// 是之前“转发时界面无响应”的主因。这里只加锁入队，由 UI 定时器统一取走。
        private void OnEngineMessage(string text)
        {
            Log.Write(text);                                   // 入队后台写盘，不阻塞
            lock (_pendingUi)
            {
                if (_pendingUi.Count < 5000) { _pendingUi.Enqueue(DateTime.Now.ToString("HH:mm:ss") + "  " + text); }
                else { _uiDropped++; }
            }
        }

        // 每 200ms 批量刷新一次，单批最多显示 200 行，其余只进文件。
        private void FlushUiLog()
        {
            string[] batch;
            long dropped;
            lock (_pendingUi)
            {
                dropped = _uiDropped;
                _uiDropped = 0;
                if (_pendingUi.Count == 0 && dropped == 0) { return; }
                batch = _pendingUi.ToArray();
                _pendingUi.Clear();
            }

            StringBuilder sb = new StringBuilder();
            int shown = batch.Length < 200 ? batch.Length : 200;
            for (int i = 0; i < shown; i++) { sb.AppendLine(batch[i]); }
            if (batch.Length > shown)
            {
                sb.AppendLine("...（本批另有 " + (batch.Length - shown) + " 条已写入日志文件）");
            }
            if (dropped > 0)
            {
                sb.AppendLine("...（界面刷新跟不上，已省略 " + dropped + " 条，完整内容见日志文件）");
            }

            _log.AppendText(sb.ToString());
            TrimLog();
        }

        private void TrimLog()
        {
            if (_log.TextLength < 60000) { return; }
            string t = _log.Text;
            int cut = t.IndexOf('\n', t.Length / 2);
            _log.Text = cut > 0 ? t.Substring(cut + 1) : "";
        }

        private void Warn(string text)
        {
            Log.Write("[提示] " + text.Replace("\r\n", "  "));
            MessageBox.Show(this, text, "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private void UpdateHint()
        {
            if (TransparentMode)
            {
                _lblHint.Text =
                    "透明模式：无需改动游戏设置。\r\n" +
                    "进任意服务器，流量都会被强制转发到上面填写的目标服务器。\r\n" +
                    "需以管理员身份运行（会自动释放并加载 WinDivert 驱动）。";
                return;
            }

            int port;
            if (!int.TryParse(_txtListenPort.Text.Trim(), out port)) { port = 19132; }

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("中继模式：在 Minecraft（网易基岩版）里添加服务器，地址填写下面任意一个：");
            foreach (string ip in LocalIPv4()) { sb.AppendLine("    " + ip + ":" + port); }
            sb.Append("    127.0.0.1:" + port + "   （游戏与本工具在同一台电脑时用这个）");
            _lblHint.Text = sb.ToString();
        }

        private static List<string> LocalIPv4()
        {
            List<string> list = new List<string>();
            try
            {
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface nic in nics)
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) { continue; }
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) { continue; }
                    foreach (UnicastIPAddressInformation ua in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            string s = ua.Address.ToString();
                            if (!list.Contains(s)) { list.Add(s); }
                        }
                    }
                }
            }
            catch { }
            if (list.Count == 0) { list.Add("127.0.0.1"); }
            return list;
        }

        private void LoadConfig()
        {
            _txtHost.Text = "";
            _txtTargetPort.Text = "19132";
            _txtPorts.Text = DefaultInterceptPorts;
            _txtListenPort.Text = "19132";
            _rbTransparent.Checked = true;

            string src = _iniPath;
            bool migrated = false;
            try
            {
                if (!File.Exists(src))
                {
                    // 兼容旧版配置：改名后首次启动自动接续原有设置。
                    string legacy = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath),
                                                 AppInfo.LegacyName + ".ini");
                    if (File.Exists(legacy)) { src = legacy; migrated = true; }
                }

                if (File.Exists(src))
                {
                    foreach (string raw in File.ReadAllLines(src))
                    {
                        string line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith("#")) { continue; }
                        int eq = line.IndexOf('=');
                        if (eq <= 0) { continue; }
                        string key = line.Substring(0, eq).Trim();
                        string val = line.Substring(eq + 1).Trim();
                        if (key == "Mode") { _rbTransparent.Checked = (val != "Relay"); _rbRelay.Checked = !_rbTransparent.Checked; }
                        else if (key == "Host") { _txtHost.Text = val; }
                        else if (key == "TargetPort") { _txtTargetPort.Text = val; }
                        else if (key == "InterceptPorts") { _txtPorts.Text = val; }
                        else if (key == "ListenPort") { _txtListenPort.Text = val; }
                        else if (key == "Verbose") { _chkVerbose.Checked = (val == "1"); }
                    }
                }
            }
            catch { }

            if (migrated)
            {
                // 拦截端口的默认值在新版里改了，沿用旧默认的配置按新默认走，
                // 否则改了默认值却在界面上看不到效果。
                if (_txtPorts.Text.Trim() == LegacyDefaultInterceptPorts) { _txtPorts.Text = DefaultInterceptPorts; }

                SaveConfig();                                   // 先落地新配置再删旧的，中途出错也不会丢设置
                try { File.Delete(src); } catch { }
                Log.Write("[迁移] 旧配置已接续到 " + AppInfo.Name + ".ini");
            }
        }

        private void SaveConfig()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("# " + AppInfo.Name + " 配置");
                sb.AppendLine("Mode=" + (TransparentMode ? "Transparent" : "Relay"));
                sb.AppendLine("Host=" + _txtHost.Text.Trim());
                sb.AppendLine("TargetPort=" + _txtTargetPort.Text.Trim());
                sb.AppendLine("InterceptPorts=" + _txtPorts.Text.Trim());
                sb.AppendLine("ListenPort=" + _txtListenPort.Text.Trim());
                sb.AppendLine("Verbose=" + (_chkVerbose.Checked ? "1" : "0"));
                File.WriteAllText(_iniPath, sb.ToString());
            }
            catch { }
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            try { StopEngine(); } catch { }
            SaveConfig();
        }
    }
}