from Sandbagility.Plugins.HyperApi import HyperApi


class HyperWin32Api(HyperApi):

    _NAME = 'HyperApi'
    _DEPENDENCIES = ['kernelbase', 'kernel32']

    def __init__(self, helper, verbose=None):
        '''
            @brief Initialize the HyperApi class instance
        '''
        HyperApi.__init__(self, helper, verbose)
 
    def AcquireContext(self, Process):

        super().AcquireContext(Process)

        if self.ImpersonateProcess.WoW64Process:
            prefix = 'w'
            LdrData = self.ImpersonateProcess.LdrData32
        else:
            prefix = ''
            LdrData = self.ImpersonateProcess.LdrData

        if not LdrData:
            raise Exception('HyperApiError: No information available on loaded modules')

        for Module in LdrData.Modules:
            for Dependency in self._DEPENDENCIES:
                if not Module.FullDllName or Dependency not in Module.FullDllName: continue
                self.helper.SymReloadModule(Module.DllBase, Module.SizeOfImage)

        self.logger.debug('SymReloadUserModule: Success')

        self.logger.debug('ImpersonateProcess.StackBase: %x', self.ImpersonateProcess.Thread.StackBase)
        self.logger.debug('ImpersonateProcess.StackLimit: %x', self.ImpersonateProcess.Thread.StackLimit)

        self.SavedStackSize = self.ImpersonateProcess.Thread.StackBase - self.ImpersonateProcess.Thread.StackLimit

    def SaveState(self):
        '''
            @brief Save the the memory and cpu state before doing
            the underlying call
            @remark Save the main cpu registers and the stack for the
            active thread from the stack base to the stack limit
        '''

        self.rax = self.helper.dbg.rax
        self.rbx = self.helper.dbg.rbx
        self.rcx = self.helper.dbg.rcx
        self.rdx = self.helper.dbg.rdx
        self.rsi = self.helper.dbg.rsi
        self.rdi = self.helper.dbg.rdi
        self.r8 = self.helper.dbg.r8
        self.r9 = self.helper.dbg.r9
        self.r10 = self.helper.dbg.r10
        self.r11 = self.helper.dbg.r11
        self.r12 = self.helper.dbg.r12
        self.r13 = self.helper.dbg.r13
        self.r14 = self.helper.dbg.r14
        self.r15 = self.helper.dbg.r15

        self.rsp = self.helper.dbg.rsp
        self.rip = self.helper.dbg.rip

        self.logger.debug('Saving stack: StackLimit: %x, SavedStackSize: %x', self.ImpersonateProcess.Thread.StackLimit, self.SavedStackSize)
        self.SavedStack = self.helper.ReadVirtualMemory(self.ImpersonateProcess.Thread.StackLimit, self.SavedStackSize)

        self.logger.debug('SavedStack: %x', len(self.SavedStack))

    def RestoreState(self):
        '''
            @brief Restore the the memory and cpu state before doing
            the underlying call
            @remark Restore the main cpu registers and the stack for the
            active thread from the stack base to the stack limit
        '''
        self.helper.dbg.rax = self.rax
        self.helper.dbg.rbx = self.rbx
        self.helper.dbg.rcx = self.rcx
        self.helper.dbg.rdx = self.rdx
        self.helper.dbg.rsi = self.rsi
        self.helper.dbg.rdi = self.rdi
        self.helper.dbg.r8 = self.r8
        self.helper.dbg.r9 = self.r9
        self.helper.dbg.r10 = self.r10
        self.helper.dbg.r11 = self.r11
        self.helper.dbg.r12 = self.r12
        self.helper.dbg.r13 = self.r13
        self.helper.dbg.r14 = self.r14
        self.helper.dbg.r15 = self.r15

        self.helper.dbg.rsp = self.rsp
        self.helper.dbg.rip = self.rip

        self.helper.WriteVirtualMemory(self.ImpersonateProcess.Thread.StackLimit, self.SavedStack)

    def UnderCall(self, FunctionName, *args, **kwargs):
        '''
            @brief This function perform the underlying call to the win32 api
        '''

        self.SaveState()

        self.logger.debug('Previous stack: %x', self.helper.dbg.rsp)

        '''
            @bugfix A invalid stack alignment can cause the impersonated process
            to crash. The call misalignment is emulated by a add 8 to rsp
        '''
        self.helper.dbg.rsp = ((self.helper.dbg.rsp >> 8) << 8) + 8
        self.logger.debug('New stack      : %x', self.helper.dbg.rsp)

        '''
            Set the parameters into the registers and the stack
        '''
        for Index in range(len(args)):
            if Index == 0:
                self.helper.dbg.rcx = args[Index]
                self.logger.debug('rcx : %x', args[Index])
            elif Index == 1:
                self.helper.dbg.rdx = args[Index]
                self.logger.debug('rdx : %x', args[Index])
            elif Index == 2:
                self.helper.dbg.r8 = args[Index]
                self.logger.debug('r8 : %x', args[Index])
            elif Index == 3:
                self.helper.dbg.r9 = args[Index]
                self.logger.debug('r9 : %x', args[Index])
            else:
                stack_offset = 8 * (Index + 1)
                self.helper.WriteVirtualMemory64(self.helper.dbg.rsp + stack_offset, args[Index])
                self.logger.debug('rsp+%x : %x', stack_offset, args[Index])

        '''
            Store the return address to the original rip
        '''
        ReturnAddress = self.helper.dbg.rip
        self.helper.WriteVirtualMemory64(self.helper.dbg.rsp, ReturnAddress)
        self.logger.debug('New return address written at %x with %x', self.helper.dbg.rsp, ReturnAddress)

        '''
            Resolve the function symbol and set the new rip
        '''
        pfnFunction = self.helper.SymLookupByName(FunctionName)
        self.logger.debug('%s: %x', FunctionName, pfnFunction)
        self.helper.dbg.rip = pfnFunction

        '''
            Execute until the return address is hit with the
            right pid and tid
        '''
        self.helper.SetBreakpoint(ReturnAddress, self.CallbackHandler, cr3=self.ImpersonateProcess.DirectoryTableBase)
        self.helper.Run()

        self.helper.UnsetBreakpoint(ReturnAddress, self.ImpersonateProcess.DirectoryTableBase)

        '''
            Return the result
        '''
        Status = self.helper.dbg.rax
        self.logger.debug('Status : %x', Status)

        self.RestoreState()

        return Status

    def VirtualAlloc(self, dwSize):
        '''
            @brief Allocate a memory space into the ImpersonateProcess
            @remark The newly allocate memory space is paged out by an
            PageFault interrupt injection in order to be used writable
            by the hypervisor
        '''
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000

        PAGE_READWRITE = 0x4

        lpAddress = self.UnderCall('KernelBase!VirtualAlloc', 0, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        self.logger.debug('KernelBase!VirtualAlloc: %x', lpAddress)

        PageOut = self.helper.ReadVirtualMemory(lpAddress, dwSize)
        if PageOut is None:
            raise Exception('UnderCallError: Cannot paged out {:x} of length {:x}'.format(lpAddress, dwSize))

        return lpAddress

    def VirtualFree(self, lpAddress):
        '''
            @brief Free the given memory address from the ImpersonateProcess
        '''
        MEM_RELEASE = 0x8000

        Status = self.UnderCall('KernelBase!VirtualFree', lpAddress, 0, MEM_RELEASE)
        self.logger.debug('KernelBase!VirtualFree: %x', Status)

        return Status

    def CreateFile(self, FileName, DesiredAccess=None, CreationDisposition=None):
        '''
            @brief Create a file with the ImpersonateProcess identity
        '''
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        if DesiredAccess is None: DesiredAccess = GENERIC_READ | GENERIC_WRITE

        CREATE_ALWAYS = 2
        if CreationDisposition is None: CreationDisposition = CREATE_ALWAYS

        FILE_ATTRIBUTE_NORMAL = 0x80

        lpFileName = self.CopyFromBuffer(FileName)
        self.logger.debug('lpFileName: %x with %x', lpFileName, len(FileName))

        hFile = self.UnderCall('KernelBase!CreateFileA', lpFileName, DesiredAccess, 0, 0, CreationDisposition, FILE_ATTRIBUTE_NORMAL, 0)
        self.logger.debug('KernelBase!VirtualAlloc: %x', hFile)

        Status = self.VirtualFree(lpFileName)
        self.logger.debug('lpFileName: %x freed %u', lpFileName, Status)

        return hFile

    def CloseHandle(self, hObject):
        '''
            @brief Close the handle opened in the ImpersonateProcess
        '''
        Result = self.UnderCall('KernelBase!CloseHandle', hObject)
        self.logger.debug('KernelBase!CloseHandle: %x', Result)

        return Result

    def WriteFile(self, hFile, Buffer):
        '''
            @brief Write data into a opened file
        '''
        lpBuffer = self.CopyFromBuffer(Buffer)
        self.logger.debug('lpBuffer: %x allocated %u', lpBuffer, len(Buffer))

        Result = self.UnderCall('KernelBase!WriteFile', hFile, lpBuffer, len(Buffer), 0, 0)
        self.logger.debug('KernelBase!WriteFile: %x', Result)

        Status = self.VirtualFree(lpBuffer)
        self.logger.debug('lpBuffer: %x freed %u', lpBuffer, Status)

        return Result

    def GetFileSize(self, hFile):

        Result = self.UnderCall('KernelBase!GetFileSize', hFile, 0)
        self.logger.debug('KernelBase!GetFileSize: %x', Result)

        return Result

    def ReadFile(self, hFile, Size=None):
        '''
            @brief Read data from an opened file
        '''
        if Size is None: Size = self.GetFileSize(hFile)
        self.logger.debug('Size: %x', Size)

        lpBuffer = self.VirtualAlloc(Size)
        self.logger.debug('lpBuffer: %x', lpBuffer)

        Result = self.UnderCall('KernelBase!ReadFile', hFile, lpBuffer, Size, 0, 0)
        self.logger.debug('KernelBase!ReadFile: %x', Result)

        if Result == 1: Result = self.helper.ReadVirtualMemory(lpBuffer, Size)
        else: Result = None

        Status = self.VirtualFree(lpBuffer)
        self.logger.debug('lpBuffer: %x freed %u', lpBuffer, Status)

        return Result

    def WinExec(self, CmdLine, uCmdShow=5):
        '''
            @brief Execute a command line
        '''
        lpCmdLine = self.CopyFromBuffer(CmdLine)
        self.logger.debug('lpCmdLine: %x allocated %u', lpCmdLine, len(CmdLine))

        Result = self.UnderCall('Kernel32!WinExec', lpCmdLine, uCmdShow)
        self.logger.debug('Kernel32!WinExec: %x', Result)

        Status = self.VirtualFree(lpCmdLine)
        self.logger.debug('lpCmdLine: %x freed %u', lpCmdLine, Status)

        return Result

    def CreateProcess(self, CmdLine, dwCreationFlags=0):
        '''
            @brief Execute a command line
        '''

        lpStartupInfo = self.VirtualAlloc(0x1000)
        self.helper.WriteVirtualMemory64(lpStartupInfo, 0x44)
        self.logger.debug('lpStartupInfo: %x', lpStartupInfo)

        lpProcessInformation = self.VirtualAlloc(0x1000)
        self.logger.debug('lpProcessInformation: %x', lpProcessInformation)

        lpCmdLine = self.CopyFromBuffer(CmdLine)
        self.logger.debug('lpCmdLine: %x allocated %u', lpCmdLine, len(CmdLine))

        Result = self.UnderCall('kernelbase!CreateProcessA', 0, lpCmdLine, 0, 0, 0, dwCreationFlags, 0, 0, lpStartupInfo, lpProcessInformation)
        self.logger.debug('Kernel32!WinExec: %x', Result)

        Status = self.VirtualFree(lpCmdLine)
        self.logger.debug('lpCmdLine: %x freed %u', lpCmdLine, Status)

        Status = self.VirtualFree(lpProcessInformation)
        self.logger.debug('lpProcessInformation: %x freed %u', lpProcessInformation, Status)

        Status = self.VirtualFree(lpStartupInfo)
        self.logger.debug('lpStartupInfo: %x freed %u', lpStartupInfo, Status)

        return Result
