using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PreyXMLCPBDisabler
{
    class Program
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess( ProcessAccessFlags processAccess, bool bInheritHandle, int processId );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, Int64 lpBaseAddress, [In, Out] byte[] buffer, int size, ref int lpNumberOfBytesWritten);

        static void Main(string[] args)
        {
            Process[] procArr = Process.GetProcessesByName("Prey");
            if (procArr.Length == 0)
            {
                Console.WriteLine("Awaiting Prey...");
                while(procArr.Length == 0)
                {
                    procArr = Process.GetProcessesByName("Prey");
                }
                IntPtr handle = OpenProcess(ProcessAccessFlags.All, true, (int)procArr[0].Id);
                //Write hook
                try {
                    //Suspending process
                    SuspendProcess(procArr[0].Id);
                    byte[] buffer = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
                    int bytesWrittenFirst = 0;
                    WriteProcessMemory(handle, (procArr[0].MainModule.BaseAddress.ToInt64() + 0x5E56AF), buffer, buffer.Length, ref bytesWrittenFirst);
                    int bytesWrittenSecond = 0;
                    WriteProcessMemory(handle, (procArr[0].MainModule.BaseAddress.ToInt64() + 0x5E57BD), buffer, buffer.Length, ref bytesWrittenSecond);
                    //Resuming process
                    ResumeProcess(procArr[0].Id);
                    Console.WriteLine("Written. First:" + bytesWrittenFirst + "/" + buffer.Length + " Second:" + bytesWrittenSecond + "/" + buffer.Length);
                }
                catch(Exception ex)
                {
                    Console.WriteLine("Exception:" + ex.Message);
                }
                Console.WriteLine("Done. You can close this window now.");
                Console.WriteLine("Press any button to exit...");
                Console.ReadKey();
            }
            else
            {
                Console.WriteLine("Please close Prey and start this program before you start the game.");
                Console.WriteLine("Press any button to exit...");
                Console.ReadKey();
            }
        }

        //Source: https://stackoverflow.com/a/71457
        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);
        [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);


        private static void SuspendProcess(int pid)
        {
            var process = Process.GetProcessById(pid);

            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                SuspendThread(pOpenThread);

                CloseHandle(pOpenThread);
            }
        }

        public static void ResumeProcess(int pid)
        {
            var process = Process.GetProcessById(pid);

            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                var suspendCount = 0;
                do
                {
                    suspendCount = ResumeThread(pOpenThread);
                } while (suspendCount > 0);

                CloseHandle(pOpenThread);
            }
        }
    }
}
