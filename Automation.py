

from Sandbagility.Plugins import PsWaitForSingleProcessAsync
from Sandbagility.Plugins import HyperWin32Api as HyperApi
from Sandbagility.Plugins import ProcessTracker

from Sandbagility.Monitors import AvailableMonitors

import os
import string
import random
import sys
import argparse
import time

def timestamp():
    return time.strftime('%Y%m%d%H%M%S', time.localtime())

def GenString(length=8):
    return ''.join(random.sample(string.ascii_lowercase, length))

def Upload(helper, file):

    if file.startswith('http'): return UploadFromRemote(helper, file)
    else: return UploadFromFile(helper, file)

def UploadFromFile(helper, file, randomize=False):

    if randomize: filename = GenString()
    else: filename = os.path.basename(os.path.splitext(file)[0])

    extension = os.path.splitext(file)[-1]
    
    Data = open(file, 'rb').read()
    if extension == '.zip':
        filename, Data = Unzip(Data)
        filename, extension = os.path.splitext(filename)
        extension = '.exe'
    elif not extension: extension = '.exe'
    elif extension == '.exe': pass
    else: pass

    filename = '%s%s' % (filename, extension)
    return __upload__(helper, filename, Data)

def UploadFromRemote(helper, url):

    import re
    import requests

    response = requests.get(url)
    if response.status_code != 200: return None

    try: Filename = '%s.exe' % re.findall('filename=(.*)', response.headers['Content-Disposition'])[0]
    except: return None
    
    Data = requests.get(url).content

    return __upload__(helper, Filename, Data)

def __upload__(helper, Filename, Data, process='explorer.exe', path='C:\\Users\\User\\Desktop\\'):

    filename = path + Filename
    helper.logger.info('Filename: %s', filename)

    api = HyperApi(helper)
    api.AcquireContext(process)

    hFile = api.CreateFile(bytes(filename.encode('utf8')))
    helper.logger.info('CreateFile: %x', hFile)
    if hFile == 0xffffffffffffffff: return None

    Status = api.WriteFile(hFile, Data)
    helper.logger.info('WriteFile: %x', Status)
    if not Status: return None
    
    Status = api.CloseHandle(hFile)
    helper.logger.info('CloseHandle: %x', Status)
    if not Status: return None

    api.ReleaseContext()

    return Filename

def __download__(helper, files, output, process='explorer.exe'):

    api = HyperApi(helper)
    api.AcquireContext(process)

    for file in files:

        hFile = api.CreateFile(bytes(file.encode('utf8')), DesiredAccess=0x80000000, CreationDisposition=3)
        helper.logger.info('CreateFile: %x', hFile)

        if hFile == 0xffffffffffffffff: break

        Data = api.ReadFile(hFile)
        helper.logger.info('ReadFile: %x', len(Data))

        Status = api.CloseHandle(hFile)
        helper.logger.info('CloseHandle: %x', Status)

        basename = os.path.split(file)[-1]
        with open('%s%s_' % (output, basename), 'wb') as f:
            f.write(Data)

    api.ReleaseContext()

def Unzip(data):

    passwords = ['infected', '666', 'virus']

    from io import BytesIO
    from zipfile import ZipFile

    fzip = ZipFile(file=BytesIO(data))

    for zfileinfo in fzip.filelist:
        fname = zfileinfo.filename
        zfile = None
        for pwd in passwords:
            try:
                zfile = fzip.open(fname, pwd=bytes(pwd.encode('utf8')))
                print('extracted with password %s' % pwd)
                break
            except RuntimeError:
                continue
        if zfile:
            return (fname, zfile.read())

def Parser(helper, args, Tracker=ProcessTracker):

    parser = argparse.ArgumentParser(description='Trace a process activity, including its childs .')
    parser.add_argument('--process', type=str, default='explorer.exe', help='Process name to trace')
    parser.add_argument('--entrypoint', action='store_true', help='Break at the entrpoint of the target process')
    parser.add_argument('--vm', default="Windows 10 x64 - 14393", help='Virtual Machine name')
    parser.add_argument('--output', default='D:\\Jail\\DroppedFiles\\' + timestamp(), help='Output directory for dumped files')
    parser.add_argument('--monitor', default=[], nargs='+', help='...')
    parser.add_argument('--upload', type=str, help='File to upload')
    parser.add_argument('--download', type=str, nargs='+', help='File to download')
    parser.add_argument('--execute', type=str, nargs='+', help='File to download')
    parser.add_argument('--save', action='store_true', help='Save the running state')
    parser.add_argument('--restore', action='store_true', help='Restore previous state')
    parser.add_argument('--run', action='store_true', help='Run the virtual machine')
    parser.add_argument('--swap', type=str, help='Change the current process for the given one')
    parser.add_argument('--breakon', default=[], type=str, nargs='+', help='Change the current process for the given one')

    args = parser.parse_args(args)

    Process = args.process

    if args.save: 
        helper.logger.info('Saving %s' % args.vm)
        helper.dbg.Save()
        helper.dbg.Resume()
        helper.logger.info('Success')
        exit(0)

    elif args.restore: 
        helper.logger.info('Restoring %s' % args.vm)
        helper.dbg.Restore()
        helper.dbg.Resume()
        helper.logger.info('Success')
        exit(0)

    if args.swap:
        ActiveProcess = helper.SwapContext(args.swap)
        print(ActiveProcess)
        exit(0)

    if args.upload:
        Filename = Upload(helper, args.upload)

        if Filename is None: 
            helper.logger.info('Upload %s failed' % args.upload)
            exit(0)
        else: 
            helper.logger.info('Upload %s successeeded' % args.upload)
            Process = os.path.basename(args.upload)

        Process = Filename

        helper.UnsetAllBreakpoints()
        helper.dbg.Resume()

    if args.download:
        __download__(helper, args.download, output=args.output)
        helper.dbg.Resume()
        exit(0)

    if args.run:
        helper.UnsetAllBreakpoints()
        helper.dbg.Resume()
        exit(0)

    if args.entrypoint: 
        
        helper.logger.info('Waiting to reach entrypoint for : %s' % Process)
        PsWaitForSingleProcessAsync(helper, Process)
        helper.Run()
        
        Process = helper.PsGetCurrentProcess()

    helper.logger.info('Target process   : %s' % Process)
    helper.logger.info('Enabled monitors : %s' % ', '.join(args.monitor))
    helper.logger.info('Break on actions : %s' % ', '.join(args.breakon))
    helper.logger.info('Dropped files at : %s' % args.output)
    Tracker(helper, Process=Process, Output=args.output, Monitors=args.monitor, BreakOnActions=args.breakon)
    helper.Run()