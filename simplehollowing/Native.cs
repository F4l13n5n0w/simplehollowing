using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace simplehollowing
{
    internal class Native
    {

        public static uint RTL_USER_PROCESS_PARAMETERS_NORMALIZED = 1;

        public static uint PS_ATTRIBUTE_IMAGE_NAME = 0x20005;
        public static uint PS_ATTRIBUTE_PARENT_PROCESS = 0x60000;
        public static uint PS_ATTRIBUTE_MITIGATION_OPTIONS = 0x20010;

        public static long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;
        public static uint THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001;

        public static uint PROCESS_ALL_ACCESS = 0x1FFFFF;
        public static uint THREAD_ALL_ACCESS = 0x1FFFFF;


        public static uint ExecuteReadWrite = 0x40;
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        //public delegate uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, uint ZeroBits, ref uint RegionSize, uint AllocationType, uint Protect);

        public delegate uint NtCreateUserProcess(ref IntPtr ProcessHandle, ref IntPtr ThreadHandle, uint ProcessDesiredAccess, uint ThreadDesiredAccess, IntPtr ProcessObjectAttributes, IntPtr ThreadObjectAttributes, uint ProcessFlags, uint ThreadFlags, IntPtr ProcessParameters, ref PsCreateInfo CreateInfo, ref PsAttributeList AttributeList);

        public delegate uint NtQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        public delegate uint NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, ref IntPtr lpNumWritten);
        public delegate uint NtResumeThread(IntPtr hThread, ref uint suspendCount);
        public delegate uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref UInt32 NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);
        public delegate uint NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToRead, ref uint NumberOfBytesRead);
        public delegate uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        public delegate uint NtMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);
        public delegate uint NtCreateSection(ref IntPtr hSection, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);
    }
}
