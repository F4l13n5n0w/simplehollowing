using System;
using System.Runtime.InteropServices;

namespace simplehollowing
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebAddress;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr UniquePid;
        public IntPtr MoreReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFO
    {
        uint cb;
        IntPtr lpReserved;
        IntPtr lpDesktop;
        IntPtr lpTitle;
        uint dwX;
        uint dwY;
        uint dwXSize;
        uint dwYSize;
        uint dwXCountChars;
        uint dwYCountChars;
        uint dwFillAttributes;
        uint dwFlags;
        ushort wShowWindow;
        ushort cbReserved;
        IntPtr lpReserved2;
        IntPtr hStdInput;
        IntPtr hStdOutput;
        IntPtr hStdErr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public uint dwOem;
        public uint dwPageSize;
        public IntPtr lpMinAppAddress;
        public IntPtr lpMaxAppAddress;
        public IntPtr dwActiveProcMask;
        public uint dwNumProcs;
        public uint dwProcType;
        public uint dwAllocGranularity;
        public ushort wProcLevel;
        public ushort wProcRevision;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LARGE_INTEGER
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Explicit, Size = 88)]
    public unsafe struct PsCreateInfo
    {
        [FieldOffset(0)] public UIntPtr Size;
        [FieldOffset(8)] public PsCreateState State;
        [FieldOffset(16)] public fixed byte Filter[72];
    }
    public enum PsCreateState
    {
        PsCreateInitialState,
        PsCreateFailOnFileOpen,
        PsCreateFailOnSectionCreate,
        PsCreateFailExeFormat,
        PsCreateFailMachineMismatch,
        PsCreateFailExeName, // Debugger specified
        PsCreateSuccess,
        PsCreateMaximumStates
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PsAtrribute
    {
        public uint Attribute;
        public UIntPtr Size;
        public IntPtr Value;
        public IntPtr ReturnLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PsAttributeList
    {
        private const int PsAttributeListSize = 3;

        public UIntPtr TotalLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = PsAttributeListSize)]
        public PsAtrribute[] Attributes;

        public void Init()
        {
            Attributes = new PsAtrribute[PsAttributeListSize];
        }
    }
}
