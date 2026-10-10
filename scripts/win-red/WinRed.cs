// WinRed.cs (rev3) -- Job Object containment for the win-red harness. Compiled at run time by pwsh 7
// (Add-Type -TypeDefinition) inside run-win-red.ps1. Never shipped; never part of the product.
//
// Why: the rev2 orchestrator discovered descendants by sampling Win32_Process every 250 ms and called the
// result "verified". A child whose parent exits between two samples is never recorded, so that guarantee was
// false. Here every launched process is placed in its OWN Windows Job Object before it runs a single
// instruction, and cleanup is proven by the job's accounting (ActiveProcesses == 0), not by sampling.
//
// Containment contract (every clause enforced here, every violation throws -> the orchestrator aborts):
//   1. a fresh Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; the limit is read back and must be set;
//   2. the process is created CREATE_SUSPENDED, assigned to the job, confirmed in the job (IsProcessInJob),
//      and only then resumed -- there is no window in which it runs unassigned;
//   3. breakaway is NOT permitted: neither JOB_OBJECT_LIMIT_BREAKAWAY_OK nor SILENT_BREAKAWAY_OK is set, so a
//      child created with CREATE_BREAKAWAY_FROM_JOB fails to start instead of escaping, and ordinary children
//      inherit the job; the process is confirmed in the job before it runs;
//   4. assignment or confirmation failure terminates the still-suspended process (ours, never ran) and throws;
//   5. ActiveProcesses() queries the job's accounting information and throws on failure (the orchestrator then
//      records cleanup as UNVERIFIED -- zero is never assumed);
//   6. Terminate() calls TerminateJobObject on this job only; Dispose() closes the job handle, and
//      kill-on-close ends anything still inside. No API here can touch a process outside this job.
// Exception messages are fixed labels plus a Win32 error number: no paths, no identifiers.
//
// Observed nowhere yet: this file has not been compiled or run on Windows (no pwsh/dotnet on the preparing
// machine). The PowerShell side treats any compile or runtime failure as CONTAINMENT-ERROR and stops.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace WinRed
{
    public sealed class ContainedProcess : IDisposable
    {
        // ---- Win32 constants
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint CREATE_ALWAYS = 2;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const int JobObjectBasicAccountingInformation = 1;
        private const int JobObjectBasicProcessIdList = 3;
        private const int JobObjectExtendedLimitInformation = 9;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        // Deliberately NOT used anywhere: JOB_OBJECT_LIMIT_BREAKAWAY_OK (0x800), JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK (0x1000),
        // CREATE_BREAKAWAY_FROM_JOB (0x01000000). The static mechanics check asserts their absence from this file's code.
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint INFINITE_SUSPEND_FAILED = 0xFFFFFFFF;
        private const int ERROR_MORE_DATA = 234;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        // ---- Win32 structures (sequential layout; UIntPtr/IntPtr keep x64 alignment correct)
        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFOW
        {
            public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
            public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute;
            public uint dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2;
            public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit;
            public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount;
            public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit; public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        {
            public long TotalUserTime; public long TotalKernelTime; public long ThisPeriodTotalUserTime; public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount; public uint TotalProcesses; public uint ActiveProcesses; public uint TotalTerminatedProcesses;
        }

        // ---- P/Invoke
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpInfo, uint cbInfo);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool QueryInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpInfo, uint cbInfo, out uint lpReturnLength);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool IsProcessInJob(IntPtr hProcess, IntPtr hJob, out bool result);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(string lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOW lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, ref SECURITY_ATTRIBUTES lpSecurityAttributes,
            uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        // ---- state
        private IntPtr _job = IntPtr.Zero;
        private IntPtr _process = IntPtr.Zero;
        private bool _disposed;
        public int Pid { get; private set; }
        public bool Exited { get; private set; }
        public uint ExitCode { get; private set; }

        private ContainedProcess() { }

        private static InvalidOperationException Fail(string label)
        {
            // fixed label + Win32 error number only; never a path or an identifier
            return new InvalidOperationException("CONTAINMENT: " + label + " (Win32 " + Marshal.GetLastWin32Error() + ")");
        }

        // ---- command-line construction
        // Quote one argument so that CommandLineToArgvW / the MSVCRT parser (which node.exe, git.exe and tar.exe use)
        // yields exactly the original string. Rules: no quoting needed unless empty or containing space/tab/newline/quote;
        // otherwise wrap in quotes, double every backslash that precedes a quote or the end, and escape embedded quotes.
        public static string Quote(string arg)
        {
            if (arg == null) throw new ArgumentNullException("arg");
            if (arg.Length > 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0) return arg;
            var sb = new StringBuilder("\"");
            int i = 0;
            while (i < arg.Length)
            {
                int backslashes = 0;
                while (i < arg.Length && arg[i] == '\\') { backslashes++; i++; }
                if (i == arg.Length) { sb.Append('\\', backslashes * 2); break; }
                if (arg[i] == '"') { sb.Append('\\', backslashes * 2 + 1); sb.Append('"'); }
                else { sb.Append('\\', backslashes); sb.Append(arg[i]); }
                i++;
            }
            sb.Append('"');
            return sb.ToString();
        }

        // cmd.exe is only ever used to run a .cmd shim (npm.cmd). Its command line is parsed by cmd.exe, whose quoting rules
        // differ from MSVCRT's, so the inputs are RESTRICTED instead of escaped: the shim path may contain no cmd metacharacter
        // and each argument must be a plain token. Anything else is refused (never interpolated).
        private static readonly Regex CmdMeta = new Regex("[\"&|<>^%!\r\n]");
        private static readonly Regex PlainToken = new Regex("^[A-Za-z0-9._=-]+$");
        public static bool IsSafeCmdScriptPath(string p) { return p != null && p.Length > 0 && !CmdMeta.IsMatch(p) && p.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase); }
        public static bool IsPlainToken(string a) { return a != null && PlainToken.IsMatch(a); }

        public static string BuildCmdLine(string application, string[] argv, bool viaCmd, string cmdExe)
        {
            if (viaCmd)
            {
                if (!IsSafeCmdScriptPath(application)) throw new InvalidOperationException("CONTAINMENT: cmd script path refused (metacharacter or not .cmd)");
                var inner = new StringBuilder(Quote(application));
                foreach (var a in argv)
                {
                    if (!IsPlainToken(a)) throw new InvalidOperationException("CONTAINMENT: cmd argument refused (not a plain token)");
                    inner.Append(' ').Append(a);
                }
                // /d: no AutoRun; /s: strip only the outer quotes of the /c string; /c: run and exit.
                return Quote(cmdExe) + " /d /s /c \"" + inner.ToString() + "\"";
            }
            var sb = new StringBuilder(Quote(application));
            foreach (var a in argv) sb.Append(' ').Append(Quote(a));
            return sb.ToString();
        }

        // ---- launch: job first, process suspended, assign, confirm, resume
        public static ContainedProcess Start(string application, string[] argv, string cwd, string stdoutPath, string stderrPath, bool viaCmd)
        {
            if (application == null || argv == null || cwd == null || stdoutPath == null || stderrPath == null) throw new ArgumentNullException();
            if (!File.Exists(application)) throw new InvalidOperationException("CONTAINMENT: application file not found");
            if (!Directory.Exists(cwd)) throw new InvalidOperationException("CONTAINMENT: working directory not found");
            string cmdExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            if (viaCmd && !File.Exists(cmdExe)) throw new InvalidOperationException("CONTAINMENT: cmd.exe not found in the system directory");
            string appName = viaCmd ? cmdExe : application;
            string cmdline = BuildCmdLine(application, argv, viaCmd, cmdExe);

            var cp = new ContainedProcess();
            IntPtr hIn = INVALID_HANDLE_VALUE, hOut = INVALID_HANDLE_VALUE, hErr = INVALID_HANDLE_VALUE;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool created = false, resumed = false;
            try
            {
                // 1. job with kill-on-close, read back
                cp._job = CreateJobObjectW(IntPtr.Zero, null);
                if (cp._job == IntPtr.Zero) throw Fail("CreateJobObject failed");
                var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    Marshal.StructureToPtr(limits, buf, false);
                    if (!SetInformationJobObject(cp._job, JobObjectExtendedLimitInformation, buf, (uint)size)) throw Fail("SetInformationJobObject failed");
                    uint ret;
                    if (!QueryInformationJobObject(cp._job, JobObjectExtendedLimitInformation, buf, (uint)size, out ret)) throw Fail("QueryInformationJobObject(limits) failed");
                    var back = (JOBOBJECT_EXTENDED_LIMIT_INFORMATION)Marshal.PtrToStructure(buf, typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                    if ((back.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) == 0) throw new InvalidOperationException("CONTAINMENT: kill-on-close limit not set after SetInformationJobObject");
                }
                finally { Marshal.FreeHGlobal(buf); }

                // 2. inheritable standard handles: stdin from NUL, stdout/stderr to the given files (created/truncated)
                var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), lpSecurityDescriptor = IntPtr.Zero, bInheritHandle = true };
                hIn = CreateFileW("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, ref sa, OPEN_EXISTING, 0, IntPtr.Zero);
                if (hIn == INVALID_HANDLE_VALUE) throw Fail("open NUL failed");
                hOut = CreateFileW(stdoutPath, GENERIC_WRITE, FILE_SHARE_READ, ref sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (hOut == INVALID_HANDLE_VALUE) throw Fail("create stdout file failed");
                hErr = CreateFileW(stderrPath, GENERIC_WRITE, FILE_SHARE_READ, ref sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (hErr == INVALID_HANDLE_VALUE) throw Fail("create stderr file failed");

                // 3. suspended process
                var si = new STARTUPINFOW();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
                si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = hIn; si.hStdOutput = hOut; si.hStdError = hErr;
                var cl = new StringBuilder(cmdline);
                if (!CreateProcessW(appName, cl, IntPtr.Zero, IntPtr.Zero, true, CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, cwd, ref si, out pi)) throw Fail("CreateProcess failed");
                created = true;
                cp._process = pi.hProcess; cp.Pid = pi.dwProcessId;

                // 4. assign while suspended, confirm membership, then resume
                if (!AssignProcessToJobObject(cp._job, pi.hProcess)) throw Fail("AssignProcessToJobObject failed");
                bool inJob;
                if (!IsProcessInJob(pi.hProcess, cp._job, out inJob)) throw Fail("IsProcessInJob failed");
                if (!inJob) throw new InvalidOperationException("CONTAINMENT: process not in its job after assignment");
                uint previousSuspendCount = ResumeThread(pi.hThread);
                if (previousSuspendCount == INFINITE_SUSPEND_FAILED) throw Fail("ResumeThread failed");
                if (previousSuspendCount != 1) throw new InvalidOperationException("CONTAINMENT: unexpected suspend count at resume");
                resumed = true;
                return cp;
            }
            catch
            {
                // the process either never existed or has never run (still suspended): end it, then release everything
                if (created && !resumed) { try { TerminateProcess(pi.hProcess, 1); } catch { } }
                if (cp._job != IntPtr.Zero) { try { TerminateJobObject(cp._job, 1); } catch { } }
                cp.Dispose();
                throw;
            }
            finally
            {
                if (created && pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                // the parent's copies of the inheritable handles are closed so the files end when the child does
                if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);
                if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
                if (hErr != INVALID_HANDLE_VALUE) CloseHandle(hErr);
            }
        }

        // ---- waiting and accounting
        // true when the root process has exited (ExitCode then valid); false on timeout; throws on a wait failure.
        public bool Wait(int timeoutMs)
        {
            EnsureLive();
            if (Exited) return true;
            uint r = WaitForSingleObject(_process, (uint)Math.Max(0, timeoutMs));
            if (r == WAIT_TIMEOUT) return false;
            if (r != WAIT_OBJECT_0) throw Fail("WaitForSingleObject failed");
            uint code;
            if (!GetExitCodeProcess(_process, out code)) throw Fail("GetExitCodeProcess failed");
            ExitCode = code; Exited = true;
            return true;
        }

        // Number of processes currently inside the job, from kernel accounting. Throws on failure (never returns a guess).
        public uint ActiveProcesses()
        {
            EnsureLive();
            int size = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint ret;
                if (!QueryInformationJobObject(_job, JobObjectBasicAccountingInformation, buf, (uint)size, out ret)) throw Fail("QueryInformationJobObject(accounting) failed");
                var acc = (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(buf, typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
                return acc.ActiveProcesses;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        // Diagnostic only: the kernel's count of processes assigned to the job right now (first field of the PID list).
        public uint AssignedProcessCount()
        {
            EnsureLive();
            int size = 8192;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint ret;
                bool ok = QueryInformationJobObject(_job, JobObjectBasicProcessIdList, buf, (uint)size, out ret);
                if (!ok && Marshal.GetLastWin32Error() != ERROR_MORE_DATA) throw Fail("QueryInformationJobObject(pid list) failed");
                return (uint)Marshal.ReadIntPtr(buf, 0).ToInt64();
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        // Polls accounting until ActiveProcesses is 0 or graceMs elapsed; returns the final count (0 = proven empty).
        public uint SettleToZero(int graceMs)
        {
            var deadline = DateTime.UtcNow.AddMilliseconds(Math.Max(0, graceMs));
            while (true)
            {
                uint n = ActiveProcesses();
                if (n == 0) return 0;
                if (DateTime.UtcNow >= deadline) return n;
                System.Threading.Thread.Sleep(100);
            }
        }

        // Terminates every process in THIS job (and nothing else). Returns false if the call failed.
        public bool Terminate()
        {
            EnsureLive();
            return TerminateJobObject(_job, 1);
        }

        private void EnsureLive() { if (_disposed || _job == IntPtr.Zero) throw new InvalidOperationException("CONTAINMENT: job already disposed"); }

        // Closing the job handle (our only one) ends anything still inside it: kill-on-close is the backstop.
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_process != IntPtr.Zero) { CloseHandle(_process); _process = IntPtr.Zero; }
            if (_job != IntPtr.Zero) { CloseHandle(_job); _job = IntPtr.Zero; }
        }

        // ---- self-test hook for the orchestrator: index of the first vector whose Quote() differs, or -1
        public static int QuoteSelfTest(string[] inputs, string[] expected)
        {
            if (inputs == null || expected == null || inputs.Length != expected.Length) return -2;
            for (int i = 0; i < inputs.Length; i++) if (Quote(inputs[i]) != expected[i]) return i;
            return -1;
        }
    }
}
