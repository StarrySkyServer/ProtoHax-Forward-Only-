using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ProtoHaxForward
{
    // WinDivert 的 WINDIVERT_ADDRESS（x64 下固定 80 字节）。
    // 位域 Flags 的位序与 windivert.h 中 MSVC 的分配一致（低位在前）。
    [StructLayout(LayoutKind.Explicit, Size = 80)]
    internal struct WINDIVERT_ADDRESS
    {
        [FieldOffset(0)] public long Timestamp;
        [FieldOffset(8)] public uint Flags;
        [FieldOffset(12)] public uint Reserved2;

        // union Network { UINT32 IfIdx; UINT32 SubIfIdx; }
        [FieldOffset(16)] public uint IfIdx;
        [FieldOffset(20)] public uint SubIfIdx;

        // union Flow / Socket（FLOW 层用；地址/端口为网络字节序）
        [FieldOffset(32)] public uint FlowProcessId;
        [FieldOffset(36)] public uint FlowLocalAddr0;
        [FieldOffset(52)] public uint FlowRemoteAddr0;
        [FieldOffset(68)] public ushort FlowLocalPort;
        [FieldOffset(70)] public ushort FlowRemotePort;
        [FieldOffset(72)] public byte FlowProtocol;

        // Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1
        // IPChecksum:1 TCPChecksum:1 UDPChecksum:1
        public bool IsOutbound { get { return (Flags & (1u << 17)) != 0; } }
        public bool IsImpostor { get { return (Flags & (1u << 19)) != 0; } }
        public bool IsIPv6 { get { return (Flags & (1u << 20)) != 0; } }

        // 让 WinDivert 在回注时自行重算校验和（因为我们会改动 TTL 之外的字段）。
        public void InvalidateChecksums()
        {
            Flags &= ~((1u << 21) | (1u << 22) | (1u << 23));
        }
    }

    internal static class Native
    {
        public const int WINDIVERT_LAYER_NETWORK = 0;
        public const int WINDIVERT_LAYER_FLOW = 2;
        public const ulong WINDIVERT_FLAG_SNIFF = 0x0001;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool SetDllDirectoryW(string lpPathName);

        [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr WinDivertOpen(
            [MarshalAs(UnmanagedType.LPStr)] string filter, int layer, short priority, ulong flags);

        [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WinDivertRecv(
            IntPtr handle, byte[] packet, uint packetLen, out uint recvLen, ref WINDIVERT_ADDRESS addr);

        // FLOW/SOCKET 层没有包体：包缓冲传 NULL，信息全在 addr 里。
        [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl, EntryPoint = "WinDivertRecv")]
        public static extern bool WinDivertRecvFlow(
            IntPtr handle, IntPtr packet, uint packetLen, out uint recvLen, ref WINDIVERT_ADDRESS addr);

        [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WinDivertSend(
            IntPtr handle, byte[] packet, uint packetLen, out uint sendLen, ref WINDIVERT_ADDRESS addr);

        [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WinDivertClose(IntPtr handle);

        // 调整内核队列参数。默认队列 4096 包，突发流量下容易溢出丢包。
        [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WinDivertSetParam(IntPtr handle, int param, ulong value);

        public const int WINDIVERT_PARAM_QUEUE_LENGTH = 0;
        public const int WINDIVERT_PARAM_QUEUE_TIME = 1;

        [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WinDivertHelperCalcChecksums(
            byte[] packet, uint packetLen, ref WINDIVERT_ADDRESS addr, ulong flags);

        [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WinDivertHelperParseIPv4Address(
            [MarshalAs(UnmanagedType.LPStr)] string addrStr, out uint addr);

        [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WinDivertHelperCompileFilter(
            [MarshalAs(UnmanagedType.LPStr)] string filter, int layer, StringBuilder obj, uint objLen,
            out IntPtr errorStr, out uint errorPos);
    }

    // 直接在原始字节上读写 IP/UDP 头，避免结构体对齐带来的歧义。
    // 地址与端口均按网络字节序存放，ReadU32/ReadU16 返回的就是“内存里的字节序值”，
    // 可直接与 WinDivertHelperParseIPv4Address 的返回值比较。
    internal static class PacketUtil
    {
        public const int IP_SRC = 12;
        public const int IP_DST = 16;

        public static uint ReadU32(byte[] p, int off)
        {
            return (uint)(p[off] | (p[off + 1] << 8) | (p[off + 2] << 16) | (p[off + 3] << 24));
        }

        public static void WriteU32(byte[] p, int off, uint v)
        {
            p[off] = (byte)v;
            p[off + 1] = (byte)(v >> 8);
            p[off + 2] = (byte)(v >> 16);
            p[off + 3] = (byte)(v >> 24);
        }

        public static ushort ReadU16(byte[] p, int off)
        {
            return (ushort)(p[off] | (p[off + 1] << 8));
        }

        public static void WriteU16(byte[] p, int off, ushort v)
        {
            p[off] = (byte)v;
            p[off + 1] = (byte)(v >> 8);
        }

        public static ushort ToNetU16(int port)
        {
            return (ushort)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
        }

        // 大端读取（IP/UDP 头字段是网络字节序）。
        public static ushort ReadU16BE(byte[] p, int off)
        {
            return (ushort)((p[off] << 8) | p[off + 1]);
        }

        // 把点分十进制 IPv4 解析成与 ReadU32/WriteU32 相同的“内存字节序”约定：
        // 低字节对应第一个八位组，WriteU32 写出的即为网络字节序。
        // 注意不要用 WinDivertHelperParseIPv4Address 的返回值直接写包——它返回的是
        // 主机序数值，直接写入会导致字节序反转（141.11.39.100 会变成 100.39.11.141）。
        public static bool TryParseIPv4(string text, out uint packetOrder)
        {
            packetOrder = 0;
            if (text == null) { return false; }
            string[] parts = text.Split('.');
            if (parts.Length != 4) { return false; }
            uint v = 0;
            for (int i = 0; i < 4; i++)
            {
                int o;
                if (!int.TryParse(parts[i], out o) || o < 0 || o > 255) { return false; }
                v |= (uint)o << (8 * i);
            }
            packetOrder = v;
            return true;
        }

        // 计算 IPv4 头校验和（跳过偏移 10 的校验和字段本身）。
        public static ushort ComputeIpChecksum(byte[] p, int ihl)
        {
            uint sum = 0;
            for (int i = 0; i < ihl; i += 2)
            {
                if (i == 10) { continue; }
                sum += (uint)((p[i] << 8) | p[i + 1]);
            }
            while ((sum >> 16) != 0) { sum = (sum & 0xFFFF) + (sum >> 16); }
            return (ushort)(~sum);
        }

        // 计算 IPv4/UDP 校验和（含伪首部，跳过 UDP 校验和字段本身）。
        public static ushort ComputeUdpChecksumV4(byte[] p, int len, int udpOff)
        {
            uint sum = 0;
            sum += (uint)((p[12] << 8) | p[13]);
            sum += (uint)((p[14] << 8) | p[15]);
            sum += (uint)((p[16] << 8) | p[17]);
            sum += (uint)((p[18] << 8) | p[19]);
            sum += 17;                                  // 协议号
            int udpLen = len - udpOff;
            sum += (uint)(udpLen & 0xFFFF);
            for (int i = udpOff; i < len; i += 2)
            {
                if (i == udpOff + 6) { continue; }
                int hi = p[i];
                int lo = (i + 1 < len) ? p[i + 1] : 0;
                sum += (uint)((hi << 8) | lo);
            }
            while ((sum >> 16) != 0) { sum = (sum & 0xFFFF) + (sum >> 16); }
            ushort r = (ushort)(~sum);
            return r == 0 ? (ushort)0xFFFF : r;
        }

        // 仅处理 IPv4 + UDP；其余（IPv6、TCP、分片等）返回 false，由调用方原样回注。
        public static bool TryParseUdpV4(byte[] p, int len, out int udpOff)
        {
            udpOff = 0;
            if (len < 28) { return false; }
            if ((p[0] >> 4) != 4) { return false; }

            int ihl = (p[0] & 0x0F) * 4;
            if (ihl < 20 || len < ihl + 8) { return false; }
            if (p[9] != 17) { return false; }              // 17 = UDP
            if ((p[6] & 0x1F) != 0 || (p[6] & 0x20) != 0) { return false; }  // 分片包不处理

            udpOff = ihl;
            return true;
        }
    }
}