from abc import ABC, abstractmethod

import logging


class HyperApi(ABC):

    def __init__(self, helper, debug=False):
        '''
            @brief Initialize the HyperApi Instance
        '''
        self.helper = helper
        self.logger = logging.getLogger('HyperApi')

        if self._NAME in self.helper.debug: self.logger.setLevel(logging.DEBUG)
        else: self.logger.setLevel(logging.INFO)

    def AcquireContext(self, Process):

        if isinstance(Process, str) or isinstance(Process, int):
            self.helper.SwapContext(Process, Userland=True)
            Process = self.helper.PsGetCurrentProcess(loadLdr=True)

        self.ImpersonateProcess = Process
        self.logger.debug('ImpersonateProcess: %s', self.ImpersonateProcess)

    def ReleaseContext(self):

        self.ImpersonateProcess = None
        self.helper.UnsetAllBreakpoints()
        self.helper.dbg.Resume()

    @abstractmethod
    def SaveState(self):
        '''
            @brief Save the the memory and cpu state before doing
            the underlying call
        '''
        pass

    @abstractmethod
    def RestoreState(self):
        '''
            @brief Restore the memory and cpu state as it was
            before the undercall
        '''
        pass

    @abstractmethod
    def UnderCall(self, FunctionName, *args, **kwargs):
        '''
            @brief This function perform the underlying call
        '''
        pass

    def CopyFromBuffer(self, Buffer):
        '''
            @brief Copy the given data into a newly allocate memory space into
            the impersonated process
        '''

        self.logger.debug('Buffer: %s', Buffer)

        lpBuffer = self.VirtualAlloc(len(Buffer))
        self.logger.debug('lpBuffer: %x with %x bytes', lpBuffer, len(Buffer))

        self.helper.WriteVirtualMemory(lpBuffer, Buffer)

        return lpBuffer

    def CallbackHandler(self):

        self.logger.debug('CallbackHandler: hit at %x', self.helper.dbg.rip)
        ActiveProcess = self.helper.PsGetCurrentProcess()

        self.logger.debug('ActiveProcess.Cid: %s', str(ActiveProcess.Cid))
        self.logger.debug('ImpersonateProcess.Cid: %s', str(self.ImpersonateProcess.Cid))

        '''
            Check if the breakpoint was hit by the right process and thread
        '''
        if ActiveProcess.Cid.Tid != self.ImpersonateProcess.Cid.Tid: return True
        if ActiveProcess.Cid.Pid != self.ImpersonateProcess.Cid.Pid: return True

        '''
            Stop the breakpoint dispatcher if the current
            process Tid and Pid is the impersonated one
        '''
        return False

    @abstractmethod
    def VirtualAlloc(self, dwSize):
        '''
            @brief Allocate a memory space into the ImpersonateProcess
        '''
        pass

    @abstractmethod
    def VirtualFree(self, lpAddress):
        '''
            @brief Free the given memory address from the ImpersonateProcess
        '''
        pass

    @abstractmethod
    def CreateFile(self, FileName):
        '''
            @brief Create a file with the ImpersonateProcess identity
        '''
        pass

    @abstractmethod
    def CloseHandle(self, hObject):
        '''
            @brief Close the handle opened in the ImpersonateProcess
        '''
        pass

    @abstractmethod
    def WriteFile(self, hFile, Buffer):
        '''
            @brief Write data into a opened file
        '''
        pass

    @abstractmethod
    def WinExec(self, CmdLine, *args, **kwargs):
        '''
            @brief Execute a command line
        '''
        pass
