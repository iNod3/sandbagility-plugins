from Sandbagility.Monitors import PsCreateProcessMonitor, PsLoadImageMonitor

import os

from Sandbagility.Monitors import AvailableMonitors

class ProcessTracker():

    _LOGGER = 'ProcessTracker'

    def __init__(self, helper, Process, Output='', Monitors=[], BreakOnActions=[]):

        self.helper = helper
        self.Monitors = Monitors
        self.Output = Output
        self.BreakOnActions = BreakOnActions
        
        self.DelayedMonitors = []

        self.__initialize_cache__()

        if hasattr(Process, 'eprocess'):
            self.EnableMonitor(Process)

        self.TargetProcess = [Process]

        Monitor = PsCreateProcessMonitor(self.helper)
        Monitor.RegisterPostCallback(self.__ProcessTrackerHandler__)

        Monitor = PsLoadImageMonitor(self.helper)
        Monitor.RegisterPostCallback(self.__ProcessTrackerHandler__)

    def __initialize_cache__(self):

        self._cache = {}
        self._cache['Service'] = {}
        self._cache['File'] = {}
        self._cache['DynamicCode'] = []

    def GetProcessFromOperation(self, Operation):

        if Operation.Action in ['CreateProcess', 'ExitProcess']:

            if Operation.Process in self.TargetProcess or Operation.Detail in self.TargetProcess:

                if Operation.Action == 'CreateProcess':
                    self.TargetProcess.append(Operation.Detail)
                    self.EnableMonitor(Operation.Detail)
                return Operation.Detail

            elif Operation.Process == 'services.exe':

                for hService, CachedOperation in self._cache['Service'].items():
                    if CachedOperation.Action in ['CreateService', 'OpenService'] and CachedOperation.StartPending:
                        CachedOperation.StartPending = False
                        return Operation.Detail

            elif Operation.Detail in self.TargetProcess:
                return Operation.Detail

        elif Operation.Process in self.TargetProcess:
            return Operation.Process

        return None

    def EnableMonitor(self, Process):

        for AvailableMonitor in AvailableMonitors:

            if self.Monitors and AvailableMonitor._NAME not in self.Monitors: continue

            Monitor = AvailableMonitor(self.helper, Process=Process)
            Monitor.RegisterPostCallback(self.__ProcessTrackerHandler__)
            
            if Monitor.mode == 1:
                self.DelayedMonitors.append(Monitor)

    def NotifyMonitor(self, Target, Operation):

        if Operation.Action == 'LoadImage':
            for delayed_monitor in self.DelayedMonitors.copy():

                if True not in [ d in Operation.Detail.FullImageName.lower() for d in delayed_monitor.Dependencies ]: continue
                delayed_monitor.NotifyLoadImage(Operation.Process, Operation.Detail)

                if delayed_monitor.Installed:
                    self.DelayedMonitors.remove(delayed_monitor)

        elif Operation.Action == 'ExitProcess':
            if Target in self.TargetProcess and len(self.TargetProcess) > 15:
                self.TargetProcess.remove(Target)
                self.helper.UnsetBreakpointByCr3(Target.DirectoryTableBase)
            
                for delayed_monitor in self.DelayedMonitors.copy():
                    if delayed_monitor.Process == Target:
                        self.DelayedMonitors.remove(delayed_monitor)

        elif Operation.Action == 'CloseServiceHandle':
            if hasattr(Operation.Detail, 'hSCObject') and Operation.Detail.hSCObject in self._cache['Service']:
                del self._cache['Service'][Operation.Detail.hSCObject]

        elif 'DynamicCode' in self._cache and self._cache['DynamicCode']:
            
            for DynamicCodeOperation in self._cache['DynamicCode']:

                self.Dump( DynamicCodeOperation, DynamicCodeOperation.Detail.BaseAddress, DynamicCodeOperation.Detail.RegionSize)
                self._cache['DynamicCode'].remove(DynamicCodeOperation)

        return True

    def Update(self, Operation):

        Target = self.GetProcessFromOperation(Operation)
        if not Target: return None

        if Target not in self.TargetProcess and Operation.Action != 'ExitProcess':
            self.TargetProcess.append(Target)
            self.EnableMonitor(Target)
        else:
            self.NotifyMonitor(Target, Operation)

        return Target

    def Dump(self, Operation=None, Buffer=None, Length=None, Data=None, Caption='', Path='', Lazy=True):

        import zlib

        if Data is None:
            if not Buffer or not Length:
                return False
            Data = self.helper.ReadVirtualMemory(Buffer, Length, Lazy=Lazy)
            if Data is None:
                return False
            Label = '%x' % Buffer
        elif isinstance(Data, bytes):
            Label = '%x' % (zlib.crc32(Data)% 2**32)
        else: Label = 'Unknown'

        if not Path and not Operation: return False
        elif not Path and Operation: 
            Path = '{}_{}_{}_{}'.format(Operation.Process.ImageFileName, str(Operation.Process.Cid).strip(), Operation.Action, Label)
            if Caption: Path += '_%s' % Caption
            Path += '.bin'

        Path = os.path.splitdrive(Path)[-1]
        Path, filename = os.path.split(Path)
        Path = os.path.normpath(os.sep.join([self.Output, Path]))

        try: os.makedirs(Path)
        except: pass

        fullname = os.path.join(Path, filename) + '_'

        """ TODO Create an InMemory Zip file """
        try: open(fullname, 'ab').write(Data)
        except: pass

        return True

    def __ProcessTrackerHandler__(self, monitor):

        Target = self.Update(monitor.LastOperation)
        if Target is None:
            return True

        Process = monitor.LastOperation.Process
        Action = monitor.LastOperation.Action
        Detail = monitor.LastOperation.Detail

        return self.Process(monitor, Action, Process, Detail)

    def Process(self, monitor, Action, Process, Detail):

        if self.Monitors and monitor not in self.Monitors: return True

        if monitor == 'File':

            FileHandle = Detail.FileHandle
            FileObject = monitor.ActiveProcess.ObReferenceObjectByHandle(
                FileHandle)

            if FileObject is not None:

                FileName = str(FileObject)

                if 'Write' in Action:
                    self.Dump(monitor.LastOperation, Path=FileName, Buffer=Detail.Buffer, Length=Detail.Length)

                if 'LastAccess' not in self._cache['File']:
                    self._cache['File']['LastAccess'] = None

                if FileName != self._cache['File']['LastAccess']:
                    self._cache['File']['LastAccess'] = FileName

        elif monitor == 'Service':

            if Action in ['CreateService', 'OpenService']:

                if Detail.Return != 0:  # Success

                    Operation = monitor.LastOperation.Copy()
                    Operation.StartPending = True
                    self._cache['Service'][Detail.Return] = Operation

            elif Action in ['StartService', 'DeleteService']:

                if Detail.hService in self._cache['Service']:

                    Operation = self._cache['Service'][Detail.hService]
                    setattr(monitor.LastOperation.Detail,
                            'lpServiceName', Operation.Detail.ServiceName)

        elif monitor == 'Resource':

            if Action == 'AcquireResource':

                self.Dump(monitor.LastOperation, Data=Detail.Data, Caption=Detail.lpName)
                delattr(monitor.LastOperation.Detail, 'Data')

        elif monitor == 'DynamicCode':

            if Action == 'DynamicCode':
                self._cache['DynamicCode'].append(monitor.LastOperation.Copy())

        elif monitor == 'Crypto':

            if Action == 'CryptEncrypt':

                import zlib

                self.Dump(monitor.LastOperation, Data=Detail.DecryptedBuffer)
                delattr(monitor.LastOperation.Detail, 'DecryptedBuffer')

            elif Action == 'CryptDecrypt':
                self.Dump(monitor.LastOperation, Buffer=Detail.pbData, Length=Detail.dwDataLen)

            elif Action in ['CryptImportKey', 'CryptExportKey']:

                
                if hasattr(Detail, 'dwDataLen'):
                    self.Dump(monitor.LastOperation, Buffer=Detail.pbData, Length=Detail.dwDataLen)

        elif monitor == 'Internet':

            if Action == 'InternetReadFile':

                dwNumberOfBytesRead = self.helper.ReadVirtualMemory32(Detail.lpdwNumberOfBytesRead)
                self.Dump(monitor.LastOperation, Buffer=Detail.lpBuffer, Length=dwNumberOfBytesRead)

        if not monitor.LastOperation.isEmpty: monitor.PrintInfoLog()

        if self.BreakOnActions and Action in self.BreakOnActions:
            exit(0)

        return True
