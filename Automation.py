from Sandbagility.Plugins import HyperWin32Api as HyperApi

import os
import string
import random

def GenString(length=8):
    return ''.join(random.sample(string.ascii_lowercase, length))

def Upload(helper, filetype, process='explorer.exe', path='C:\\Users\\User\\Desktop\\'):

    api = HyperApi(helper)
    api.AcquireContext(process)

    filename = GenString()
    extension = os.path.splitext(filetype.name)[-1]
    
    Data = filetype.raw.readall()
    if extension == '.zip':
        filename, Data = Unzip(Data)
        filename, extension = os.path.splitext(filename)
        extension = '.exe'
    elif not extension: extension = '.exe'
    else: raise Exception('UploadError: Extension not handled %s' % extension)

    filename = path + filename + extension
    helper.logger.info('Filename: %s', filename)

    hFile = api.CreateFile(bytes(filename.encode('utf8')))
    helper.logger.info('CreateFile: %x', hFile)
    if hFile == 0xffffffffffffffff: return False

    Status = api.WriteFile(hFile, Data)
    helper.logger.info('WriteFile: %x', Status)
    if not Status: return False
    
    Status = api.CloseHandle(hFile)
    helper.logger.info('CloseHandle: %x', Status)
    if not Status: return False

    api.ReleaseContext()

    return True

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