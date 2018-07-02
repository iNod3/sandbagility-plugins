from Sandbagility.Plugins import HyperWin32Api as HyperApi

import os
import string
import random

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
    if response.status_code != 200: return False

    try: Filename = '%s.exe' % re.findall('filename=(.*)', response.headers['Content-Disposition'])[0]
    except: return False
    
    Data = requests.get(url).content

    return __upload__(helper, Filename, Data)

def __upload__(helper, Filename, Data, process='explorer.exe', path='C:\\Users\\User\\Desktop\\'):

    filename = path + Filename
    helper.logger.info('Filename: %s', filename)

    api = HyperApi(helper)
    api.AcquireContext(process)

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