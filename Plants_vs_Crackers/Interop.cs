using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Plants_vs_Crackers
{
    class Interop
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, 
            uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, 
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        // Privileges 
        private enum ProcessAccessFlags : uint
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
        // The memory protection level for the pages which are going to be allocated. 
        private enum MemoryProtection : uint
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        // The type of memory allocation strategy. 
        private enum AllocationType : uint
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        /// Fetch's the current address of the kernel32 Win32 handelr. From the returned handler address,
        /// attempt to return the pointer to LoadLibraryA from kernel32's COM interface - LoadLibrary (ANSI)
        public static IntPtr LoadLibraryAProcessAddress { get { return GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"); } private set { return; } }
        int foo { get; set; }
        // Marshal the payloadName length to get the unmanaged byte length representation, add one to the length
        // of the payloadName to support null terminator.
        private static Func<string, uint> getUnmanagedPayloadNameLength = delegate ( string payloadName ) {
            return (uint) ( ( payloadName.Length + 1 ) * ( Marshal.SizeOf(typeof(char)) ) ); };
        // Create a byte stream to be read by Component Object Model.
        private static Func<string, byte[]> getUnmanagePayloadNameBuffer = delegate (string payloadName) {
            return (Encoding.Unicode.GetBytes(payloadName.ToCharArray()) ); };

        public static IntPtr GetTargetProcessAccess(int targetProcessId)
        {
            if (targetProcessId == 0)
                return IntPtr.Zero;
            return OpenProcess((uint)ProcessAccessFlags.All, false, targetProcessId);
        }
        public static IntPtr SetTargetProcessVirtualAllocation(IntPtr targetProcessHandler, string payloadName)
        {
            if (payloadName.Length < 1 || targetProcessHandler == IntPtr.Zero)
                return IntPtr.Zero; 
            uint payloadNameSize = getUnmanagedPayloadNameLength(payloadName);
            return VirtualAllocEx(targetProcessHandler, IntPtr.Zero, payloadNameSize,
                AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
        }
        public static UIntPtr WritePayloadToTargetProcess(IntPtr processHandler, IntPtr allocatedMemory, string payloadName)
        {
            bool writeProcessState;
            uint payloadNameSize;
            byte[] payloadNameBuffer;
            UIntPtr numberOfBytesWritten;

            if (payloadName.Length < 1 || !payloadName.Contains(".exe"))
                return UIntPtr.Zero;
            payloadNameSize = getUnmanagedPayloadNameLength(payloadName);
            payloadNameBuffer = getUnmanagePayloadNameBuffer(payloadName);
            writeProcessState = WriteProcessMemory(processHandler, allocatedMemory, payloadNameBuffer, payloadNameSize, out numberOfBytesWritten);
            if (!writeProcessState)
                return UIntPtr.Zero;
            return numberOfBytesWritten;
        }
        public static IntPtr GetCreatedRemoteThread(IntPtr processHandler, IntPtr loadLibrary, IntPtr allocatedMemory)
        {
            return CreateRemoteThread(processHandler, IntPtr.Zero, 0, loadLibrary, allocatedMemory, 0, IntPtr.Zero);
        }
    }
}
