---
title: "Скрытый PEB. Или напоминалка для реверсера."
author: Qeratos
date: 2025-05-23 10:00:00 +0300
categories: [Research]
tags: [Research, Malware, WINAPI, ru]
---

## Предистория
___

Однажды, анализируя очередной вредоносный файл, под Windows, а именно разбирая техники обнаружения отладки, заглянул внутрь системного вызова **``IsDebuggerPresent``** библиотеки `kernel32.dll` я увидел 2 инструкции ассемблера, отвечающие за весь функционал метода:
```asm 
mov rax,qword ptr gs:[60]
movzx eax,byte ptr ds:[rax+2]
ret 
```
 
![IsDebuggerPresent()](assets/post_img/hidden_peb/is_dbg_p.png)

Немного покопавшись на просторах интернета было выяснено что все дело в PEB (Process Environment Block) или блоке окружения процесса. 
Всякий раз когда вызывается метод `CreateProcess()`, создается запрос к ядру `ntoskrnl`, который в свою очередь формирует и заполняет структуру [EPROCESS](https://learn.microsoft.com/ru-ru/windows-hardware/drivers/kernel/eprocess#eprocess), через которую и происходит дальнейшее взаимодействие между ядром и процессом. Так же необходимо учитывать что наш процесс это просто "оболочка" для потоков, которых может быть более 1-го. Тут встает вопрос, сколько стурктур существует для управления этим всем? 

Если опираться на информацию с MSDN, при создании каждого потока создается и заполняется структура [ETHREAD](https://learn.microsoft.com/ru-ru/windows-hardware/drivers/kernel/eprocess#ethread), но так как процесс у нас остается - один, соответственно и структур EPROCESS - столько же.

Но как же быть процессам уровня пользователя если им очень нужно получить доступ к структуре EPROCESS? Проксировать запросы в ядро при помощи WinAPI и каждый раз читать структуру? А если это необходимо делать с высокой переодичностью? Видимо, об этом так же задумались в Microsoft, и вероятно, по этой причине были созданы структуры PEB и TEB, которые в свою очередь являются почти полными копиями EPROCESS и ETHREAD, соответственно. Исходя из этого, вероятно, в них есть что-то интересное, что подстегнуло ~~спустя пару лет~~ выделить немного времени на их более подробное изучение.


## PEB
___

Структура PEB (примерно выглядит следующим образом):

| Имя                           | Смещение (x86) | Смещение (x64) | Примечание |
| :---------------------------- | :------------- | -------------- | ---------- |
| char InheritedAddressSpace    | `00`           | `00`           |            |
| char ReadImageFileExecOptions | `01`           | `01`           |            |
| DWORD Mutant                  | `04`           | `08`           |            |
| DWORD ImageBaseAddress    | `08`           | `10`           |            |
| _PEB_LDR_DATA* LoaderData | `0C`           | `18`           |            |
| DWORD ProcessParameters       | `10`           | `20`           |            |
| DWORD SubSystemData           | `14`           | `28`           |            |
| DWORD ProcessHeap         | `18`           | `30`           |            |
| DWORD FastPebLock             | `1C`           | `38`           |            |
| DWORD FastPebLockRoutine      | `20`           | `40`           |            |
| DWORD FastPebUnlockRoutine    | `24`           | `48`           |            |
| DWORD EnvironmentUpdateCount  | `28`           | `50`           |            |
| DWORD KernelCallbackTable     | `2C`           | `58`           |            |
| DWORD EventLogSection         | `30`           |                |            |
| DWORD EventLog                | `34`           | `64`           |            |
| DWORD FreeList                | `38`           | `68`           |            |
| DWORD TlsExpansionCounter     | `3C`           | `70`           |            |
| DWORD TlsBitmap               | `40`           | `78`           |            |
| DWORD TlsBitmapBits[0x2]      | `44`           | `80`           |            |
| ULONG NumberOfProcessors  | `64`           | `B8`           |            |
| DWORD NumberOfHeaps           | `88`           | `e8`           |            |
| DWORD MaximumNumberOfHeaps    | `8C`           | `ec`           |            |
| DWORD ProcessHeaps            | `90`           | `f0`           |            |


## TEB
___

Тут сразу появляется вопрос, а как получить доступ к PEB? Для этого необходимо взглянуть на TEB:

| Имя                                 | Смещение (x86) | Смещение (x64) | Примечание |
| :---------------------------------- | :------------- | -------------- | ---------- |
| DWORD EnvironmentPointer            | `1C`           | `38`           |            |
| DWORD ProcessId                     | `20`           | `40`           |            |
| DWORD threadId                      | `24`           |                |            |
| DWORD ActiveRpcInfo                 | `28`           | `50`           |            |
| DWORD ThreadLocalStoragePointer     | `2C`           | `58`           |            |
| PEB* Peb                            | `30`           | `60`           |            |
| DWORD LastErrorValue                | `34`           | `68`           |            |
| DWORD CountOfOwnedCriticalSections; | `38`           | `6C`           |            |
| DWORD CsrClientThread               | `3C`           | `70`           |            |
| DWORD Win32ThreadInfo               | `40`           | `78`           |            |
| DWORD Win32ClientInfo[0x1F]         | `44`           | `80`           |            |
| DWORD WOW32Reserved                 | `48`           |                |            |
| DWORD CurrentLocale                 | `4C`           |                |            |
| DWORD FpSoftwareStatusRegister      | `50`           |                |            |
| DWORD SystemReserved1[0x36]         | `54`           |                |            |
| DWORD Spare1                        | `58`           |                |            |
| DWORD ExceptionCode                 | `5C`           |                |            |
| DWORD SpareBytes1[0x28]             | `60`           |                |            |
| DWORD SystemReserved2[0xA]          | `64`           |                |            |
| DWORD GdiRgn                        | `68`           |                |            |
| DWORD GdiPen                        | `6C`           |                |            |
| DWORD GdiBrush                      | `70`           |                |            |
| DWORD RealClientId1                 | `74`           |                |            |
| DWORD RealClientId2                 | `78`           |                |            |
| DWORD GdiCachedProcessHandle        | `7C`           |                |            |
| DWORD GdiClientPID                  | `80`           |                |            |
| DWORD GdiClientTID                  | `84`           |                |            |
| DWORD GdiThreadLocaleInfo           | `88`           |                |            |
| DWORD UserReserved[5]               | `8C`           |                |            |
| DWORD GlDispatchTable[0x118]        | `90`           |                |            |
| DWORD GlReserved1[0x1A]             | `94`           |                |            |
| DWORD GlReserved2                   | `98`           |                |            |
| DWORD GlSectionInfo                 | `9C`           |                |            |
| DWORD GlSection                     | `A0`           |                |            |
| DWORD GlTable                       | `A4`           |                |            |
| DWORD GlCurrentRC                   | `A8`           |                |            |
| DWORD GlContext                     | `AC`           | `E8`           |            |
| DWORD LastStatusValue               | `B0`           |                |            |
| char* StaticUnicodeString           | `B4`           |                |            |
| char StaticUnicodeBuffer[0x105]     | `B8`           |                |            |
| DWORD DeallocationStack             | `BC`           |                |            |
| DWORD TlsSlots[0x40]                | `C0`           | `100`          |            |
| DWORD TlsLinks                      | `C4`           | `108`          |            |
| DWORD Vdm                           | `C8`           | `10C`          |            |
| DWORD ReservedForNtRpc              | `CC`           | `110`          |            |
| DWORD DbgSsReserved[0x2]            | `D0`           |                |            |

И что же мы в ней видим? Кроме всего прочего, в ней находится указатель на PEB, бинго! Но опять мы упираемся в вопрос, а где тогда взять указатель на TEB? Оказывается, что указатель на TEB расположен в **`fs`** регистре на 32-разрядных и в **`gs`** регистре на 64-битных системах. 

Пожалуй, вернемся к нашей таблице PEB, и рассмотрим ее подробнее, а именно какие поля могут быть интересны для нас.
1) Первое интересное для нас поле это **`ImageBaseAddress**, указывает на реальный адрес по которому загружен наш экземпляр. Злоумышленники могут применять методики инжектирования или патчинга файлов для изменения текущего экземпляра или его заголовков.
2) Также очень "вкусным" для злоумышленников является поле **`BeingDebugged**, находящееся по смещению 0x2 в PEB, а которое устанавливается флаг при подключенному к процессу отладчику. Если флаг равен 1 - значит отладчик подключен. 
3) Почти в самом конце затаился указатель на количество ядер нашего процессора, поле с наименованием **`NumberOfProcessors**, что может помочь злоумышленникам проводить проверку на запуск в контролируемой среде. 
![NumberOfProcessors](assets/post_img/hidden_peb/numb_of_cpu.png)
 
4) И также можно выделить, что в стурктуре имеется указатель на хип, т.е. нам не обязательно вызвать метод GetProcessHeap() для каких-либо действий с ним. **`ProcessHeaps**
5) Сразу же взгляд цепляется за указатель на структуру с интересным именем **`PEB_LDR_DATA`** , в которой содержится информация о модулях юзерспейса, загруженных процессом. Устроена она по-своему интересно.

Если мельком взглянуть на наименование полей структуры можно сделать вывод что это у нас 3 двухсвязных списка, которые хранят в себе информацию о загруженных модулях (библиотеках) в формате **`LDR_DATA_TABLE_ENTRY**.  Структура **`PEB_LDR_DATA**, ранее  хранилась в куче, которую создавала NTDLL при запуске процесса, после версии 5.2 структура переехала в переменные NTDLL.

## PEB_LDR_DATA
___

Структура PEB_LDR_DATA:

| Имя                                        | Смещение (x86) | Смещение (x64) |
| ------------------------------------------ | -------------- | -------------- |
| ULONG Length                               | 0x00           | 0x00           |
| BOOLEAN Initialized                        | 0x04           | 0x04           |
| PVOID SsHandle                             | 0x08           | 0x08           |
| LIST_ENTRY InLoadOrderModuleList           | 0x0C           | 0x10           |
| LIST_ENTRY InMemoryOrderModuleList         | 0x14           | 0x20           |
| LIST_ENTRY InInitializationOrderModuleList | 0x1C           | 0x30           |
| PVOID EntryInProgress                      | 0x24           | 0x40           |
| BOOLEAN ShutdownInProgress                 | 0x28           | 0x48           |
| HANDLE ShutdownThreadId                    | 0x2C           | 0x50           |


> **`InLoadOrderModuleList`** - хранит в себе следующий модуль согласно порядку загрузки;
   **`InMemoryOrderModuleList`** - хранит в себе следующий модуль согласно порядку расположения в памяти;
   **`InInitializationOrderModuleList`** хранит в себе следующий модуль согласно порядку инициализации;


## LDR_DATA_TABLE_ENTRY
---
Далее следует взглянуть, на то, что мы увидим если начнем свое путешествие по двухсвязанному списку, а увидим мы там структуру **`LDR_DATA_TABLE_ENTRY**:

| Имя                                     | Смещение (x86) | Смещение (x64) |
| --------------------------------------- | -------------- | -------------- |
| LIST_ENTRY InLoadOrderLinks             | 0x00           | 0x00           |
| LIST_ENTRY InMemoryOrderLinks           | 0x08           | 0x10           |
| LIST_ENTRY InInitializationOrderLinks   | 0x10           | 0x20           |
| PVOID DllBase                       | 0x18           | 0x30           |
| PVOID EntryPoint                    | 0x1C           | 0x38           |
| ULONG SizeOfImage                  | 0x20           | 0x40           |
| UNICODE_STRING FullDllName         | 0x24           | 0x48           |
| UNICODE_STRING BaseDllName         | 0x2C           | 0x58           |
| ULONG Flags                             | 0x34           | 0x68           |
| USHORT LoadCount                        | 0x38           | 0x6C           |
| USHORT TlsIndex                         | 0x3A           | 0x6E           |
| LIST_ENTRY HashLinks                    | 0x3C           | 0x70           |
| ULONG TimeDateStamp                     | 0x44           | 0x80           |
| PVOID PatchInformation                 | 0x4C           | 0x90           |
| LDR_DDAG_NODE*DdagNode                | 0x50           | 0x98           |
| LIST_ENTRY NodeModuleLink             | 0x54           | 0xA0           |
| LDRP_DLL_SNAP_CONTEXT *SnapContext     | 0x5C           | 0xB0           |
| PVOID ParentDllBase                | 0x60           | 0xB8           |
| PVOID SwitchBackContext                | 0x64           | 0xC0           |
| RTL_BALANCED_NODE BaseAddressIndexNode  | 0x68           | 0xC8           |
| RTL_BALANCED_NODE MappingInfoIndexNode  | 0x74           | 0xE0           |
| ULONG BaseNameHashValue;                | 0x90           | 0x0108         |
| LDR_DLL_LOAD_REASON LoadReason     | 0x94           | 0x010C         |
| ULONG ImplicitPathOptions              | 0x98           | 0x0110         |
| ULONG ReferenceCount                   | 0x9C           | 0x0114         |
| ULONG DependentLoadFlags              | 0xA0           | 0x0118         |
| SE_SIGNING_LEVEL SigningLevel;          | 0xA4           | 0x011C         |

Трудно согласится, но в этой структуре так же есть интересные для нас поля, (выделены).
Например, поле DllBase, содержит, как понятно из названия, адрес текущей библиотеки в памяти. FullDllName, например содержит имя файла с путем:
![FullDllName](assets/post_img/hidden_peb/dll_path.png)
 

Как и для чего может применяться информация о PEB_LDR_DATA? 
Например пробежаться по списку уже загруженных библиотек найти необходимую.
Следом получив адрес необходимой, распарсить экспорт и вызвать необходимый метод через call или jmp, предварительно сформировав правильным образом стек и передав аргументы согласно соглашению о вызове.


## POC
___
Рассмотрим подробнее и реализуем такой функционал(пример под x64):
1) Получаем адрес PEB исходя из нашей разрядности:
```
mov rax, [gs:0x60]           ; PEB
mov [rel peb], rax           ; Save to variable
```

2) Далее нам необходимо получить адрес структуры PEB_LDR_DATA и первого модуля согласно списку загрузки:
```
mov rax, [rax + 0x18]        ; PEB_LDR_DATA
mov rsi, [rax + 0x10]        ; InLoadOrderModuleList | _LDR_DATA_TABLE_ENTRY
```

3) Запускаем парсинг, при условии нахождения нужной нам библиотеки, ищем по полю BaseDllName, по смещению 0x58, если же не нашлось такой библиотеки, а мы прошли по всему списку - выходим: 
```
.modules_loop:
	mov rbx, [rsi + 0x30]        ; 0x30 DllBase

	cmp rbx, 0              
	je .done

	mov [rel dll_addr], rbx
	mov rcx, qword[rsi + 0x60]   ; 0x58 BaseDllName
	push rsi 
	push rax

	mov rsi, lib_name             ; "KERNEL32.DLL" ptr   
	mov rdi, rcx
	call compare_str              ; serach KERNEL32.dll

	cmp rax, 1
	je .pass


	call dll_parce                ; if founded start parce
	jmp .done
	
.pass:
	pop rax
	pop rsi

	mov rsi, [rsi]         ; [+0x000] Flink   
	cmp rsi, [rax + 0x20]  ; Check if next elem is PEB_LDR_DATA

	je .done             
	loop .modules_loop
```

4) Начнем с парсинга PE заголовка найденной библиотеки, нас интересуют смещение EXPORT_DIRECTORY_RVA, нам интересны также поля NumberOfFunctions, для ограничения итерации, а так же ссылки на адреса имен функций и на сами функции. После чего итерируемся, сверяем имя, если совпало, получаем адрес функции (указатель на функции + (размер * номер нужной функции)).
```
push rbp
    mov rbp, rsp

    mov rax, [rel dll_addr]     ; DLL PTR    

    mov ebx, dword[rax + 0x180] ; EXPORT RVA
    add rax, rbx                ; EXPORT TABLE HEADER

    mov [rel dll_export], rax

    mov edi, dword[rax + 0x14]  ; EXPORT COUNTS
    mov [rel module_count], edi 

    mov ebx, [rax + 0x20]       ; ADDRESS OF NAMES

    mov rax, [rel dll_addr] 

    mov r10, rax
    add r10, rbx                ; DLL ADDRESS OF NAMES

    xor rcx, rcx
```

5) Для примера дергаем функцию CreateProcessA(), рассчитав адрес нашей функции:
```
 mov rax, [rel dll_export]
	add rax, 0x28

	sal ecx, 2              ; ecx contains function number
	add rax, rcx            ; CreateProcessA address


	mov ebx, dword[rax]       

	mov rdx, [rel dll_addr] 
	add rdx, rbx

	mov rax, rdx
	xor rdx, rdx
	xor rdi, rdi
	xor rbx, rbx



	mov dword [rel startup_info], 104

	xor rcx, rcx                 ; lpApplicationName (NULL)
	lea rdx, [rel proc_name]               ; lpCommandLine
	 
	xor r8, r8            ; lpProcessAttributes 
	xor r9, r9            ; lpThreadAttributes 
	
	mov qword [rsp+20h], 0       ; bInheritHandles (FALSE)
	mov qword [rsp+28h], 0       ; dwCreationFlags (0)
	mov qword [rsp+30h], 0       ; lpEnvironment (NULL)
	mov qword [rsp+38h], 0       ; lpCurrentDirectory (NULL)
	lea rbx, [rel startup_info]

	mov qword [rsp+40h], rbx     ; lpStartupInfo
	lea rbx, [rel proc_info]

	mov qword [rsp+48h], rbx     ; lpProcessInformation

	call rax
```

Итоговая таблица импорта файла:
![FullDllName](assets/post_img/hidden_peb/res_import.png)

Но в CretaeProcessA() мы в итоге попадаем и новый процесс - создаем:
![FullDllName](assets/post_img/hidden_peb/func_call.png)

Теперь мы имеем адрес нужной функции из библиотеки, и можем вызвать. Замечу, нам не пришлось обращаться ни к LoadLibrary(), ни к GetProcessAdress(), ни к EnumerateLoadedModulesEx(), ни к EnumProcessModules().

[GitHub_lik](https://github.com/qeratos/Hidden-PEB) на итоговый код.


## Подитожим.
___
> В PEB располагается много полезной информации, как для малварщиков, так и для реверсеров. Эта статья как мини напоминалка, что простой анализ таблицы импортов на наличие функций динамической работы с библиотеками. Если подозрительный или вредоносный файл производит какие либо-манипуляции с PEB-ом, стоит взглянуть на его функционал более подробно.
