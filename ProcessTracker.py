from Sandbagility.Monitors import PsCreateProcessMonitor, PsLoadImageMonitor

import os

from Sandbagility.Monitors import AvailableMonitors

class ProcessTracker():

    _LOGGER = 'ProcessTracker'

    def __init__(self, helper, Process, Output='', Monitors=[]):

        self.helper = helper

        self.TargetProcess = []
        self.TargetProcess.append(Process)
        self.Output = Output + '\\' + self.timestamp()
        self.Monitors = Monitors

        self.__initialize_cache__()

        self.DelayedMonitors = []

        Monitor = PsCreateProcessMonitor(self.helper)
        Monitor.RegisterPostCallback(self.__ProcessTrackerHandler__)

        Monitor = PsLoadImageMonitor(self.helper)
        Monitor.RegisterPostCallback(self.__ProcessTrackerHandler__)

    def timestamp(self):
        import time
        return time.strftime('%Y%m%d%H%S', time.localtime())

    def __initialize_cache__(self):

        self._cache = {}
        self._cache['Service'] = {}
        self._cache['File'] = {}

    def GetProcessFromOperation(self, Operation):

        if Operation.Action in ['CreateProcess', 'ExitProcess']:

            if Operation.Process in self.TargetProcess:
                return Operation.Detail

            elif Operation.Process == 'services.exe':

                for hService, CachedOperation in self._cache['Service'].items():
                    if CachedOperation.Action in ['CreateService', 'OpenService'] and CachedOperation.StartPending:
                        CachedOperation.StartPending = False
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
                delayed_monitor.NotifyLoadImage(
                    Operation.Process, Operation.Detail)
                if delayed_monitor.Installed:
                    self.DelayedMonitors.remove(delayed_monitor)

        elif Operation.Action == 'ExitProcess':
            if Target in self.TargetProcess:
                self.TargetProcess.remove(Target)
                self.helper.UnsetBreakpointByCr3(Target.DirectoryTableBase)

        elif Operation.Action == 'CloseServiceHandle':
            if hasattr(Operation.Detail, 'hSCObject') and Operation.Detail.hSCObject in self._cache['Service']:
                del self._cache['Service'][Operation.Detail.hSCObject]

        elif 'DynamicCode' in self._cache and self._cache['DynamicCode']:
            
            for DynamicCode in self._cache['DynamicCode']:
                self.Dump(
                    '%s-%s-%x-%x.bin' % (DynamicCode.Process.ImageFileName, str(DynamicCode.Process.Cid), DynamicCode.Detail.BaseAddress, DynamicCode.Detail.RegionSize),
                    DynamicCode.Detail.BaseAddress,
                    DynamicCode.Detail.RegionSize )
                self._cache['DynamicCode'].remove(DynamicCode)

        return True

    def Update(self, Operation):

        Target = self.GetProcessFromOperation(Operation)
        if not Target:
            return None

        if Target not in self.TargetProcess and Operation.Action != 'ExitProcess':
            self.TargetProcess.append(Target)
            self.EnableMonitor(Target)
        else:
            self.NotifyMonitor(Target, Operation)

        return Target

    def Dump(self, path, buffer=None, length=None, Data=None):

        path = os.path.splitdrive(path)[-1]
        path, filename = os.path.split(path)
        path = os.path.normpath(os.sep.join([self.Output, path]))

        try:
            os.makedirs(path)
        except:
            pass

        if Data is None:
            if buffer is None or length is None:
                return
            Data = self.helper.ReadVirtualMemory(buffer, length, Lazy=True)
            if Data is None:
                return

        fullname = os.path.join(path, filename) + '_'

        """ TODO Create an InMemory Zip file """
        try:
            open(fullname, 'ab').write(Data)
        except:
            pass

        return

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
                if not FileName.endswith('WNCRYT'):

                    if 'Write' in Action:
                        self.Dump(FileName, Detail.Buffer, Detail.Length)

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

                FileName = '{}_{}_{}.rc'.format(
                    Process.ImageFileName, str(Process.Cid), Detail.lpName)
                self.Dump(FileName, Data=Detail.Data)
                monitor.LastOperation.Detail.Data = FileName

        elif monitor == 'DynamicCode':

            if Action == 'DynamicCode':

                if 'DynamicCode' not in self._cache: self._cache['DynamicCode'] = []
                self._cache['DynamicCode'].append(monitor.LastOperation.Copy())

        monitor.PrintInfoLog()

        return True
