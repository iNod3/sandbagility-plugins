from Sandbagility.Monitors import PsCreateProcessMonitor


class PsWaitForSingleProcessAsync():

    def __init__(self, helper, ProcessName):

        self.helper = helper
        self.ProcessName = ProcessName

        Monitor = PsCreateProcessMonitor(self.helper)
        Monitor.RegisterPostCallback(self.Handler)

    def Handler(self, Monitor):

        '''
            Monitor only CreateProcess operation
            and check if the child process has the name
            of the requested one
        '''
        if Monitor.LastOperation.Action != 'CreateProcess': return True
        if Monitor.LastOperation.Detail != self.ProcessName: return True

        TargetProcess = Monitor.LastOperation.Detail

        '''
            Actually, we are in the parent process context, we have to change
            the cr3 value to the child cr3 in order to read its peb information.
            Then we restore the original cr3 value
        '''
        self.helper.dbg.cr3 = TargetProcess.DirectoryTableBase

        ImageBaseAddress = self.helper.ReadStructureMember64(TargetProcess.Peb, 'nt!_PEB', 'ImageBaseAddress')
        EntryPoint = self.helper.MoGetEntryPoint(ImageBaseAddress)

        self.helper.dbg.cr3 = Monitor.ActiveProcess.DirectoryTableBase

        '''
            Uninstall the monitor to disable any further breakpoint during the
            execution until we reach the child entrypoint
        '''
        Monitor.Uninstall()

        AddressOfEntryPoint = EntryPoint + ImageBaseAddress

        '''
            Break at the Entrypoint, at this time the first instruction should
            create an access violation when fetching the instruction. So we inject an
            interruption before as an access violation when reading and break after
            the page is swapped out
        '''
        self.helper.dbg.SetBreakpointHardware(AddressOfEntryPoint, 0, 'e', 1)
        self.helper.dbg.Resume()
        self.helper.dbg.WaitBreak()
        self.helper.dbg.UnsetBreakpointHardware()

        self.helper.dbg.InjectInterrupt(0x0E, 0x00, AddressOfEntryPoint)

        self.helper.dbg.SetBreakpointHardware(AddressOfEntryPoint, 0, 'e', 1)
        self.helper.dbg.Resume()
        self.helper.dbg.WaitBreak()
        self.helper.dbg.UnsetBreakpointHardware()

        self.helper.ResetCache()

        return False
