#include <fltKernel.h>
#include <dontuse.h>
#include <ntstrsafe.h>
#include <string.h>
#include <wchar.h>

struct ProcessesRoles
{
	wchar_t ProcessName[100];
	wchar_t ProcessRole;
};
struct ProcessesRoles ProcessesRolesList[50];
unsigned int ProcessesRolesCount = 0;

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;
ULONG gTraceFlags = 0;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
#define  BUFFER_SIZE 500

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);
QUERY_INFO_PROCESS ZwQueryInformationProcess;

NTSTATUS ConfigFileParsing();
unsigned int GetRulesByRole(wchar_t *ProcessName);

EXTERN_C_START
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
MyFilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
MyFilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
MyFilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
MyFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
MyFilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
MyFilterPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
MyFilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
MyFilterPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
MyFilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
MyFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );
EXTERN_C_END


//Assign text sections for each routine.
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MyFilterUnload)
#pragma alloc_text(PAGE, MyFilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, MyFilterInstanceSetup)
#pragma alloc_text(PAGE, MyFilterInstanceTeardownStart)
#pragma alloc_text(PAGE, MyFilterInstanceTeardownComplete)
#endif

//типа фильтр ирп
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	{ IRP_MJ_READ,
	  0,
	  MyFilterPreOperation,
	  MyFilterPostOperation },

	{ IRP_MJ_WRITE,
	  0,
	  MyFilterPreOperation,
	  MyFilterPostOperation },

	{ IRP_MJ_OPERATION_END }
};

//  This defines what we want to filter with FltMgr
CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    MyFilterUnload,                           //  MiniFilterUnload

    MyFilterInstanceSetup,                    //  InstanceSetup
    MyFilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    MyFilterInstanceTeardownStart,            //  InstanceTeardownStart
    MyFilterInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};


NTSTATUS
MyFilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.
	Эта процедура вызывается всякий раз, когда на томе создается новый экземпляр. 
	Это дает нам возможность решить, нужно ли нам прикрепить этот том или нет.

    If this routine is not defined in the registration structure, automatic
    instances are always created.
	Если эта процедура не определена в структуре регистрации, 
	автоматические экземпляры создаются всегда.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

	DbgPrint("[MyFilter]: MyFilterInstanceSetup: Entered\n");

    return STATUS_SUCCESS;
}

NTSTATUS
MyFilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

	DbgPrint("[MyFilter]: MyFilterInstanceQueryTeardown: Entered\n");

    return STATUS_SUCCESS;
}


VOID
MyFilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

	DbgPrint("[MyFilter]: MyFilterInstanceTeardownStart: Entered\n");
}


VOID
MyFilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

	DbgPrint("[MyFilter]: MyFilterInstanceTeardownComplete: Entered\n");
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    DbgPrint("[MyFilter]: DriverEntry: Entered\n");
	ConfigFileParsing();

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }
    return status;
}


NTSTATUS
GetProcessImageName(
	PEPROCESS eProcess,
	PUNICODE_STRING* ProcessImageName
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG returnedLength;
	HANDLE hProcess = NULL;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	if (eProcess == NULL)
	{
		return STATUS_INVALID_PARAMETER_1;
	}

	status = ObOpenObjectByPointer(eProcess,
		0, NULL, 0, 0, KernelMode, &hProcess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
		return status;
	}

	if (ZwQueryInformationProcess == NULL)
	{
		UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

		ZwQueryInformationProcess =
			(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (ZwQueryInformationProcess == NULL)
		{
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
			status = STATUS_UNSUCCESSFUL;
			goto cleanUp;
		}
	}

	/* Query the actual size of the process path */
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		NULL, // buffer
		0,    // buffer size
		&returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		DbgPrint("ZwQueryInformationProcess status = %x\n", status);
		goto cleanUp;
	}

	*ProcessImageName = ExAllocatePoolWithTag(NonPagedPoolNx, returnedLength, '2gat');

	if (ProcessImageName == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanUp;
	}

	/* Retrieve the process path from the handle to the process */
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		*ProcessImageName,
		returnedLength,
		&returnedLength);

	if (!NT_SUCCESS(status))
		ExFreePoolWithTag(*ProcessImageName, '2gat');
cleanUp:
	ZwClose(hProcess);
	return status;
}


NTSTATUS
MyFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

	DbgPrint("[MyFilter]: MyFilterUnload: Entered\n");

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


//парсинг конфигурационного файла
NTSTATUS 
ConfigFileParsing()
{
	NTSTATUS status;
	//DbgPrint("[MyFilter]: ConfigFileParsing started!\n");
	UNICODE_STRING UnicodeFileName;
	OBJECT_ATTRIBUTES FileAttributes;
	HANDLE Handle;
	IO_STATUS_BLOCK IoStatusBlock;
	RtlInitUnicodeString(&UnicodeFileName, L"\\Device\\HarddiskVolume2\\Users\\Дима\\Desktop\\config.txt");
	InitializeObjectAttributes(&FileAttributes, &UnicodeFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	//проверяем, можем ли открыть файл
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;
	
	status = ZwCreateFile(&Handle,
		GENERIC_READ,
		&FileAttributes, &IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	char buffer[BUFFER_SIZE];
	memset(buffer, 0, BUFFER_SIZE);
	if (status == STATUS_SUCCESS)
	{
		LARGE_INTEGER byteOffset;
		byteOffset.LowPart = byteOffset.HighPart = 0;
		status = ZwReadFile(Handle, NULL, NULL, NULL, &IoStatusBlock,
			buffer, BUFFER_SIZE, &byteOffset, NULL);
		if (status == STATUS_SUCCESS)
		{
			unsigned int HelpIndex = 0, i = 0;
			while (buffer[i] != 0)
			{
				if (buffer[i] == ' ')
				{
					ProcessesRolesList[ProcessesRolesCount++].ProcessRole = buffer[++i];
					i += 3;
					HelpIndex = 0;
				}
				else
					ProcessesRolesList[ProcessesRolesCount].ProcessName[HelpIndex++] = buffer[i++];
			}
			/*DbgPrint("[MyFilter]: config.txt parsed! %u\n", ProcessesRolesCount);
			for (i = 0; i < ProcessesRolesCount; i++)
				DbgPrint("[MyFilter]: %ws | %wc\n", ProcessesRolesList[i].ProcessName, ProcessesRolesList[i].ProcessRole);*/
		}
		else
		{
			ZwClose(Handle);
			return !STATUS_SUCCESS;
		}	
	}
	else
	{
		ZwClose(Handle);
		return !STATUS_SUCCESS;
	}
	ZwClose(Handle);
	return !STATUS_SUCCESS;
}

//получение роли по имени процесса
unsigned int 
GetRulesByRole(wchar_t *ProcessName)
{
	//вернет роль процесса, если она есть. 0, если процесс не имеет ролей
	//1 - только чтение
	//2 - только запись
	//3 - и запись и чтение
	//0 - разрешений нет
	memset(ProcessesRolesList, 0, sizeof(ProcessesRolesList));
	ProcessesRolesCount = 0;
	ConfigFileParsing();
	unsigned int i;
	for (i = 0; i < ProcessesRolesCount; i++)
	{
		if(!wcscmp(ProcessesRolesList[i].ProcessName, ProcessName))
		{
			if (ProcessesRolesList[i].ProcessRole == '1')
				return 1;
			else if (ProcessesRolesList[i].ProcessRole == '2')
				return 2;
			else if (ProcessesRolesList[i].ProcessRole == '3')
				return 3;
		}
	}
	return 0;
}

FLT_PREOP_CALLBACK_STATUS
MyFilterPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
	NTSTATUS status;
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

	//DbgPrint("[MyFilter]: PreOperation entered!\n");

	PFLT_FILE_NAME_INFORMATION FileNameInformation;
	if (FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInformation) == STATUS_SUCCESS)
	{
		if (FltParseFileNameInformation(FileNameInformation) == STATUS_SUCCESS)
		{
			//DbgPrint("[MyFilter]: %ws in %ws\n", FileNameInformation->Volume.Buffer, FileNameInformation->ParentDir.Buffer);
			if (FileNameInformation->Volume.Length && FileNameInformation->FinalComponent.Length &&
				!wcsncmp(FileNameInformation->Volume.Buffer, L"\\Device\\HarddiskVolume2\\TestFolder", wcslen(L"\\Device\\HarddiskVolume2\\TestFolder")))
			{
				unsigned int FinalComponentLength = 0, FullPathLength = 0;
				while (FileNameInformation->FinalComponent.Buffer[FinalComponentLength++] != 0);
				while (FileNameInformation->Volume.Buffer[FullPathLength++] != 0);
				FinalComponentLength--;
				FullPathLength--;
				if (!wcsncmp(FileNameInformation->Volume.Buffer, L"\\Device\\HarddiskVolume2\\TestFolder", FullPathLength-FinalComponentLength-1) && 
					FullPathLength-FinalComponentLength == 35)
				{
					PUNICODE_STRING ProcessName = NULL;
					GetProcessImageName(IoThreadToProcess(Data->Thread), &ProcessName);
					if (Data->Iopb->MajorFunction == IRP_MJ_READ)
					{
						unsigned int ProcessNameLength = 0, HelpProcessNameLength = 0;
						while (ProcessName->Buffer[ProcessNameLength++] != 0);
						ProcessNameLength--;
						HelpProcessNameLength = ProcessNameLength;
						while (ProcessName->Buffer[HelpProcessNameLength--] != '\\');
						HelpProcessNameLength += 2;
						wchar_t HelpProcessName[50];
						memset(HelpProcessName, 0, 50);
						int i;
						for (i = 0; i + HelpProcessNameLength < ProcessNameLength; i++)
							HelpProcessName[i] = ProcessName->Buffer[HelpProcessNameLength + i];
						HelpProcessName[i] = 0;
						if (GetRulesByRole(HelpProcessName) == 1 || GetRulesByRole(HelpProcessName) == 3)
							DbgPrint("[MyFilter]: %ws read %ws ACCESS ALLOWED!\n", HelpProcessName,
								FileNameInformation->FinalComponent.Buffer);
						else
						{
							DbgPrint("[MyFilter]: %ws read %ws ACCESS DENIED!\n", HelpProcessName,
								FileNameInformation->FinalComponent.Buffer);
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							return FLT_PREOP_COMPLETE;
						}
					}
					else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE)
					{
						unsigned int ProcessNameLength = 0, HelpProcessNameLength = 0;
						while (ProcessName->Buffer[ProcessNameLength++] != 0);
						ProcessNameLength--;
						HelpProcessNameLength = ProcessNameLength;
						while (ProcessName->Buffer[HelpProcessNameLength--] != '\\');
						HelpProcessNameLength += 2;
						wchar_t HelpProcessName[20];
						memset(HelpProcessName, 0, 20);
						int i;
						for (i = 0; i + HelpProcessNameLength < ProcessNameLength; i++)
							HelpProcessName[i] = ProcessName->Buffer[HelpProcessNameLength + i];
						HelpProcessName[i] = 0;
						if (GetRulesByRole(HelpProcessName) == 2 || GetRulesByRole(HelpProcessName) == 3)
							DbgPrint("[MyFilter]: %ws write %ws ACCESS ALLOWED!\n", HelpProcessName,
								FileNameInformation->FinalComponent.Buffer);
						else
						{
							DbgPrint("[MyFilter]: %ws write %ws ACCESS DENIED!\n", HelpProcessName,
								FileNameInformation->FinalComponent.Buffer);
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							return FLT_PREOP_COMPLETE;
						}
					}
				}
			}
		}
	}

	//[MyFilter]: \Device\HarddiskVolume2\Users\Дима\ntuser.dat.LOG1 
	
    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (MyFilterDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    MyFilterOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

			DbgPrint("[MyFilter]: MyFilterPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status);
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


VOID
MyFilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

	DbgPrint("[MyFilter]: OperationStatusCallback: Entered\n");

	DbgPrint("[MyFilter]: MyFilter!MyFilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction));
}


FLT_POSTOP_CALLBACK_STATUS
MyFilterPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

	//DbgPrint("[MyFilter]: PostOperation: Entered\n");

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
MyFilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

	DbgPrint("[MyFilter]: PreOperationNoPostOperation: Entered\n");

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
MyFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}