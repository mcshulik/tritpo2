#define WIN32_LEAN_AND_MEAN
#include <cstdio>
#include <Windows.h>
#include <tchar.h>
#include <locale.h>
#include <shellapi.h>
#include <vector>
#include <functional>
#include <iostream>
#include <conio.h>

#pragma comment(lib, "shell32.lib")

using namespace std;

#pragma pack(push, 1)

struct bootSector
{
    BYTE        jump[3]; // Не имеет значения(переход к загрузочному коду)
    BYTE        oemID[8]; // магическая последовательность ntfs
    WORD        bytePerSector; // размер сектора в байтах
    BYTE        sectorPerCluster; // размер сластера в секторах
    BYTE        reserved[2]; // 0
    BYTE        zero1[3]; // 0
    BYTE        unused1[2]; // 0
    BYTE        mediaDescriptor; // 0xf8 = жёсткий диск
    BYTE        zeros2[2]; // 0
    WORD        sectorPerTrack; // Требуется для загрузки Windows
    WORD        headNumber; // Требуется для загрузки Windows
    DWORD       hiddenSector; // Смещение к началу раздела относительно диска в секторах.Требуется для загрузки Windows
    BYTE        unused2[8]; // 0
    LONGLONG    totalSector; // количество секторов
    LONGLONG    MFTCluster; // Кластерное расположение данных MFT
    LONGLONG    MFTMirrCluster; // Кластерное расположение копии mft
    signed char clusterPerRecord; // Размер записи MFT в кластерах
    BYTE        unused3[3]; // 0
    signed char clusterPerBlock; // Размер индексного блока в кластерах
    BYTE        unused4[3]; // 0
    LONGLONG    serialNumber; // Не имеет значения(серийный номер)
    DWORD       checkSum; // Контрольная сумма загрузочного сектора
    BYTE        bootCode[0x1aa]; // Не имеет значения(код загрузки)
    BYTE        endMarker[2]; // Конец магической последовательности загрузочного сектора.Всегда 0xaa55 с little endian
};



struct RecordHeader
{
    BYTE        signature[4]; // Тип записи NTFS.Когда значение Type рассматривается как последовательность из четырех однобайтовые символы, обычно это аббревиатура типа.Определенные значения включают :
                              //‘FILE’ ‘INDX’ ‘BAAD’ ‘HOLE’ ‘CHKD’
    WORD        updateOffset; // Смещение в байтах от начала структуры до массива последовательности обновления.
    WORD        updateNumber; // Количество значений в массиве последовательности обновления
    LONGLONG    logFile; // запись изменения в структуре тома.
    WORD        sequenceNumber; // Порядковый номер обновления записи NTFS.
    WORD        hardLinkCount; // Количество ссылок каталога на запись MFT
    WORD        attributeOffset; // Смещение в байтах от начала структуры до первого атрибута записи MFT.
    WORD        flag; // Битовый массив флагов, определяющих свойства записи MFT.Определенные значения включают : 0x0001 ; // запись MFT используется, 0x0002 ; // запись MFT представляет каталог
    DWORD       usedSize; // Количество байтов, используемых записью MFT.
    DWORD       allocatedSize; // Количество байтов, выделенных для записи MFT.
    LONGLONG    baseRecord; // Если запись MFT содержит атрибуты, превышающие базовую запись MFT, этот элемент содержит номер ссылки на файл базовой записи; в противном случае он содержит ноль.
    WORD        nextAttributeID; // Номер, который будет присвоен следующему атрибуту, добавленному в запись MFT.
    BYTE        unsed[2]; // 0
    DWORD       MFTRecord; // Номер записи mft
};

struct AttributeHeaderR
{
	DWORD       typeID; // Тип атрибута
	DWORD       length; // Размер в байтах резидентной части атрибута
	BYTE        formCode; // Указывает, когда это значение равно true, что значение атрибута является нерезидентным.
	BYTE        nameLength; // Размер в символах имени(если есть) атрибута.
	WORD        nameOffset; // Смещение в байтах от начала структуры до имени атрибута.Атрибут хранится в виде строки Unicode.
	WORD        flag; // Битовый массив флагов, определяющих свойства атрибута. 0x0001 ; // атрибут сжат
	WORD        attributeID; // ID атрибута
	DWORD       contentLength; // Размер в байтах значения атрибута.
	WORD        contentOffset; // Смещение в байтах от начала структуры до значения атрибута
	WORD        unused; // 0
};

struct AttributeHeaderNR
{
    DWORD       typeID; // Тип атрибута
    DWORD       length; // Размер в байтах нерезидентной части атрибута
    BYTE        formCode; // Указывает, когда это значение равно true, что значение атрибута является нерезидентным.
    BYTE        nameLength; // Размер в символах имени(если есть) атрибута.
    WORD        nameOffset; // азмер в символах имени(если есть) атрибута.
    WORD        flag; // Битовый массив флагов, определяющих свойства атрибута. 0x0001 ; // атрибут сжат
    WORD        attributeID; // ID атрибута
    LONGLONG    startVCN; // Наименьший действительный номер виртуального кластера(VCN) этой части значения атрибута.Если только значение атрибута не сильно фрагментировано(до такой степени, что список атрибутов
                          //необходимо для его описания), существует только одна часть значения атрибута, а значение LowVcn равен нулю.
    LONGLONG    endVCN; // Самый высокий допустимый VCN этой части значения атрибута
    WORD        runListOffset; // Смещение в байтах от начала структуры до массива выполнения, содержащего сопоставления между VCN и номерами логических кластеров(LCN).
    WORD        compressSize; // Размер в байтах значения атрибута после сжатия.Этот член присутствует только когда атрибут сжат.
    DWORD       zero; // 0
    LONGLONG    contentDiskSize; // Размер в байтах дискового пространства, выделенного для хранения значения атрибута.
    LONGLONG    contentSize; // Размер в байтах значения атрибута.Он может быть больше, чем AllocatedSize, если значение атрибута сжато или разрежено.
    LONGLONG    initialContentSize; // Размер в байтах инициализированной части значения атрибута.
};

struct AttributeRecord
{
    DWORD       typeID; // Тип атрибута
    WORD        recordLength; // Размер в байтах записи списка атрибутов.
    BYTE        nameLength; //Размер в символах имени (если есть) атрибута
    BYTE        nameOffset; //Смещение в байтах от начала структуры AttributeRecord до атрибута name. Имя атрибута хранится в виде строки Unicode.
    LONGLONG    lowestVCN; //Наименьший действительный номер виртуального кластера (VCN) этой части значения атрибута.
    LONGLONG    recordNumber; //Номер записи атрибутов
    WORD        sequenceNumber;  //Порядковый номер обновления записи NTFS.
    WORD        reserved; //0
};

#pragma pack(pop)

struct Run
{
    LONGLONG    offset; // смещение
    LONGLONG    length; // размер
    Run() : offset(0LL), length(0LL) {}
    Run(LONGLONG offset, LONGLONG length) : offset(offset), length(length) {}
};

//перемещает указатель в файле и выводит ошибку, если файл повреждён
void seek(
    /*[in]*/HANDLE h, 
    /*[in]*/ULONGLONG position)
    //[in] h - дескриптор устройства
    //[in] position - смещение, на которое нужно передвинуть указатель
{
    try
    {
        LARGE_INTEGER pos;
        pos.QuadPart = (LONGLONG)position;

        LARGE_INTEGER result;
        if (!SetFilePointerEx(h, pos, &result, SEEK_SET) ||
            pos.QuadPart != result.QuadPart)
            throw (std::string) "Не удалось найти файл";
    }
    catch (...)
    {
        std::cout << std::endl << "Диск или директория повреждены!" << std::endl;
        exit(0);
    }
}

//проводит поиск атрибута файла и выводит информацию, если файл повреждён
LPBYTE findAttribute(
    /*[in]*/RecordHeader* record, 
    /*[in]*/DWORD recordSize, 
    /*[in]*/DWORD typeID)
    //[in] record - текущая запись
    //[in] recordSize - размер записи
    //[in] typeID - атрибут файла, который необходимо найти
{
    try
    {
        LPBYTE p = LPBYTE(record) + record->attributeOffset;
        while (true)
        {
            if (p + sizeof(AttributeHeaderR) > LPBYTE(record) + recordSize)
                break;

            AttributeHeaderR* header = (AttributeHeaderR*)p;
            if (header->typeID == 0xffffffff)
                break;

            if (header->typeID == typeID &&
                p + header->length <= LPBYTE(record) + recordSize)
                return p;

            p += header->length;
        }
        return NULL;
    }
    catch (...)
    {
        std::cout << std::endl << "Диск или директория повреждены!" << std::endl;
        exit(0);
    }
}

//парсит набор данных и выводит информацию, если файл повреждён
vector<Run> parseRunList(
    /*[in]*/BYTE* runList, 
    /*[in]*/DWORD runListSize, 
    /*[in]*/LONGLONG totalCluster)
    //[in] runList - указатель на набор данных
    //[in] runListSize - размер набора данных
    //[in] totalCluster - количество кластеров
{
    try
    {
        vector<Run> result;

        LONGLONG offset = 0LL;

        LPBYTE p = runList;
        while (*p != 0x00)
        {
            if (p + 1 > runList + runListSize)
                throw (std::string) "Неверные данные";

            int lenLength = *p & 0xf;
            int lenOffset = *p >> 4;
            p++;

            if (p + lenLength + lenOffset > runList + runListSize ||
                lenLength >= 8 ||
                lenOffset >= 8)
                throw (std::string)"Неверные данные";

            if (lenOffset == 0)
                throw (std::string)"Файл не поддерживается";

            ULONGLONG length = 0;
            for (int i = 0; i < lenLength; i++)
                length |= *p++ << (i * 8);

            LONGLONG offsetDiff = 0;
            for (int i = 0; i < lenOffset; i++)
                offsetDiff |= *p++ << (i * 8);
            if (offsetDiff >= (1LL << ((lenOffset * 8) - 1)))
                offsetDiff -= 1LL << (lenOffset * 8);

            offset += offsetDiff;

            if (offset < 0 || totalCluster <= offset)
                throw (std::string)"Неверные данные";

            result.push_back(Run(offset, length));
        }

        return result;
    }
    catch (...)
    {
        std::cout << std::endl << "Диск или директория повреждены!" << std::endl;
        exit(0);
    }
}

//проверяет порядковый номер файла и выводит информацию, если файл повреждён
void fixRecord(
    /*[in]*/BYTE* buffer, 
    /*[in]*/DWORD recordSize, 
    /*[in]*/DWORD sectorSize)
    //[in] buffer - указатель на буфер
    //[in] recordSize - размер записи
    //[in] clusterSize - размер кластера
{
    try
    {
        RecordHeader* header = (RecordHeader*)buffer;
        LPWORD update = LPWORD(buffer + header->updateOffset);

        if (LPBYTE(update + header->updateNumber) > buffer + recordSize)
            throw (std::string)"Недопустимый порядковый номер файла";

        for (int i = 1; i < header->updateNumber; i++)
            *LPWORD(buffer + i * sectorSize - 2) = update[i];
    }
    catch (...)
    {
        std::cout << std::endl << "Диск или директория повреждены!" << std::endl;
        exit(0);
    }
}

//читает текущую запись и  выводит информацию, если файл повреждён
void readRecord(
    /*[in]*/HANDLE h, 
    /*[in]*/LONGLONG recordIndex, 
    /*[in]*/const vector<Run>& MFTRunList, 
    /*[in]*/DWORD recordSize, 
    /*[in]*/DWORD clusterSize, 
    /*[in]*/DWORD sectorSize, 
    /*[in]*/BYTE* buffer)
    //[in] h - дескриптор устройства
    //[in] recordIndex - смещение сектора
    //[in] запись MFT
    //[in] recordSize - размер записи
    //[in] clusterSize - размер кластера
    //[in] sectorSize - размер сектора
    //[in] buffer - указатель на буфер
{
    try
    {
        LONGLONG sectorOffset = recordIndex * recordSize / sectorSize;
        DWORD sectorNumber = recordSize / sectorSize;

        for (DWORD sector = 0; sector < sectorNumber; sector++)
        {
            LONGLONG cluster = (sectorOffset + sector) / (clusterSize / sectorSize);
            LONGLONG vcn = 0LL;
            LONGLONG offset = -1LL;

            for (const Run& run : MFTRunList)
            {
                if (cluster < vcn + run.length)
                {
                    offset = (run.offset + cluster - vcn) * clusterSize
                        + (sectorOffset + sector) * sectorSize % clusterSize;
                    break;
                }
                vcn += run.length;
            }
            if (offset == -1LL)
                throw (std::string)"Не удалось прочитать запись файла";

            seek(h, offset);
            DWORD read;
            if (!ReadFile(h, buffer + sector * sectorSize, sectorSize, &read, NULL) ||
                read != sectorSize)
                throw (std::string)"Не удалось прочитать запись файла";
        }

        fixRecord(buffer, recordSize, sectorSize);
    }
    catch (...)
    {
        std::cout << std::endl << "Диск или директория повреждены!" << std::endl;
        exit(0);
    }
}

//возвращает стадию атрибута в int
int readRunList(
    /*[in]*/HANDLE h, 
    /*[in]*/LONGLONG recordIndex, 
    /*[in]*/DWORD typeID, 
    /*[in]*/const vector<Run>& MFTRunList, 
    /*[in]*/DWORD recordSize, 
    /*[in]*/DWORD clusterSize,
    /*[in]*/DWORD sectorSize, 
    /*[in]*/LONGLONG totalCluster, 
    /*[in]*/vector<Run>* runList, 
    /*[out]*/LONGLONG* contentSize = NULL)
    //[in] h - дескриптор устройства
    //[in] recordIndex - смещение сектора
    //[in] typeID - Тип атрибута
    //[in] MFTRunList - запись MFT
    //[in] recordSize - размер записи
    //[in] clusterSize - размер кластера
    //[in] sectorSize - размер сектора
    //[in] totalCluster - количество кластеров
    //[in] runList - запись MFT
    //[out] contentSize - размер MFT

{
    try
    {
        vector<BYTE> record(recordSize);
        readRecord(h, recordIndex, MFTRunList, recordSize, clusterSize, sectorSize, &record[0]);

        RecordHeader* recordHeader = (RecordHeader*)&record[0];
        AttributeHeaderNR* attrListNR = (AttributeHeaderNR*)findAttribute(
            recordHeader, recordSize, 0x20);    //  $Attribute_List

        int stage = 0;

        if (attrListNR == NULL)
        {
            //  no attribute list
            AttributeHeaderNR* headerNR = (AttributeHeaderNR*)findAttribute(
                recordHeader, recordSize, typeID);
            if (headerNR == NULL)
                return 0;

            if (headerNR->formCode == 0)
            {
                //  the attribute is resident
                stage = 1;
            }
            else
            {
                //  the attribute is non-resident
                stage = 2;

                vector<Run> runListTmp = parseRunList(
                    LPBYTE(headerNR) + headerNR->runListOffset,
                    headerNR->length - headerNR->runListOffset, totalCluster);

                runList->resize(runListTmp.size());
                for (size_t i = 0; i < runListTmp.size(); i++)
                    (*runList)[i] = runListTmp[i];

                if (contentSize != NULL)
                    *contentSize = headerNR->contentSize;
            }
        }
        else
        {
            vector<BYTE> attrListData;

            if (attrListNR->formCode == 0)
            {
                //  attribute list is resident
                stage = 3;

                AttributeHeaderR* attrListR = (AttributeHeaderR*)attrListNR;
                attrListData.resize(attrListR->contentLength);
                memcpy(
                    &attrListData[0],
                    LPBYTE(attrListR) + attrListR->contentOffset,
                    attrListR->contentLength);
            }
            else
            {
                //  attribute list is non-resident
                stage = 4;

                if (attrListNR->compressSize != 0)
                    throw (std::string)"Список нерезидентных атрибутов не поддерживается";

                vector<Run> attrRunList = parseRunList (LPBYTE(attrListNR) + attrListNR->runListOffset, attrListNR->length - attrListNR->runListOffset, totalCluster);

                attrListData.resize(attrListNR->contentSize);
                vector<BYTE> cluster(clusterSize);
                LONGLONG p = 0;
                for (Run& run : attrRunList)
                {
                    //  some clusters are reserved
                    if (p >= attrListNR->contentSize)
                        break;

                    seek(h, run.offset * clusterSize);
                    for (LONGLONG i = 0; i < run.length && p < attrListNR->contentSize; i++)
                    {
                        DWORD read = 0;
                        if (!ReadFile(h, &cluster[0], clusterSize, &read, NULL) ||
                            read != clusterSize)
                            throw (std::string)"Не удалось прочитать список атрибутов нерезидента ";
                        LONGLONG s = min(attrListNR->contentSize - p, clusterSize);
                        memcpy(&attrListData[p], &cluster[0], s);
                        p += s;
                    }
                }
            }

            AttributeRecord* attr = NULL;
            LONGLONG runNum = 0;
            if (contentSize != NULL)
                *contentSize = -1;
            for (
                LONGLONG p = 0;
                p + sizeof(AttributeRecord) <= attrListData.size();
                p += attr->recordLength)
            {
                attr = (AttributeRecord*)&attrListData[p];
                if (attr->typeID == typeID)
                {
                    vector<BYTE> extRecord(recordSize);
                    RecordHeader* extRecordHeader = (RecordHeader*)&extRecord[0];

                    readRecord(h, attr->recordNumber & 0xffffffffffffLL, MFTRunList, recordSize, clusterSize, sectorSize, &extRecord[0]);
                    if (memcmp(extRecordHeader->signature, "FILE", 4) != 0)
                        throw (std::string)"Запись расширения недействительна";

                    AttributeHeaderNR* extAttr = (AttributeHeaderNR*)findAttribute (extRecordHeader, recordSize, typeID);
                    if (extAttr == NULL)
                        throw (std::string)"Атрибут не найден в записи расширения";
                    if (extAttr->formCode == 0)
                        throw (std::string) "Атрибут в записи расширения является резидентным";

                    if (contentSize != NULL && *contentSize == -1)
                        *contentSize = extAttr->contentSize;

                    vector<Run> runListTmp = parseRunList (LPBYTE(extAttr) + extAttr->runListOffset, extAttr->length - extAttr->runListOffset, totalCluster);

                    runList->resize(runNum + runListTmp.size());
                    for (size_t i = 0; i < runListTmp.size(); i++)
                        (*runList)[runNum + i] = runListTmp[i];
                    runNum += runListTmp.size();
                }
            }
        }
        return stage;
    }
    catch (...)
    {
        std::cout << std::endl << "Диск или директория повреждены!" << std::endl;
        exit (0);
    }
}

int main()
{
    char* argv = new char;
    HANDLE h = INVALID_HANDLE_VALUE;
    HANDLE output = INVALID_HANDLE_VALUE;
    int result = -1;


    try
    {
        _tsetlocale(LC_ALL, _T(""));

        std::cout << "Выберите тип работы приложения NTFS_check" << std::endl << std::endl << "1 - проверка целостности директории" << std::endl 
            <<  "2 - проверка целостности диска" << std::endl;
        char c = _getche();
        std::cout << std::endl;
        switch (c)
        {
        case '1':
        {
            std::cout << "Введите путь директории" << std::endl;
            cin.getline(argv, 256, '\n');
            break;
        }
        case '2':
        {
            std::cout << std::endl << "Введите букву диска" << std::endl;
            argv[0] = _getche();
            std::cout << std::endl;
            break;
        }
        default:
            argv[0] = 0;
        }

        TCHAR drive[] = _T("\\\\?\\_:");
        LONGLONG targetRecord = -1;
        LPWSTR outputFile = NULL;

        drive[4] = argv[0];

        h = CreateFile(drive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE)
            throw (std::string)"Не удалось открыть директорию";

        //  Boot Sector
        BootSector bootSector;
        DWORD read;
        if (!ReadFile(h, &bootSector, sizeof bootSector, &read, NULL) || read != sizeof bootSector)
            throw (std::string) "Не удалось прочитать загрузочный сектор";

        printf("OEM ID: \"%s\"\n", bootSector.oemID);
        if (memcmp(bootSector.oemID, "NTFS    ", 8) != 0)
            throw (std::string)"Не поддерживается файовая система NTFS";

        DWORD sectorSize = bootSector.bytePerSector;
        //DWORD sectorSize = 2;
        DWORD clusterSize = bootSector.bytePerSector * bootSector.sectorPerCluster;
        DWORD recordSize = bootSector.clusterPerRecord >= 0 ? bootSector.clusterPerRecord * clusterSize : 1 << -bootSector.clusterPerRecord;
        LONGLONG totalCluster = bootSector.totalSector / bootSector.sectorPerCluster;

        if (!sectorSize || !clusterSize || !recordSize || !totalCluster || !bootSector.sectorPerCluster || !bootSector.totalSector || !bootSector.MFTCluster || !bootSector.clusterPerRecord)
            throw (std::string) "Директория или диск повреждены!";


        _tprintf(_T("Byte/Sector: %u\n"), sectorSize);
        _tprintf(_T("Sector/Cluster: %u\n"), bootSector.sectorPerCluster);
        _tprintf(_T("Total Sector: %llu\n"), bootSector.totalSector);
        _tprintf(_T("Cluster of MFT: %llu\n"), bootSector.MFTCluster);
        _tprintf(_T("Cluster/Record: %u\n"), bootSector.clusterPerRecord);
        _tprintf(_T("Cluster Size: %u\n"), clusterSize);
        _tprintf(_T("Record Size: %u\n"), recordSize);

        //  Read MFT size and run list
        vector<Run> MFTRunList (1, Run (bootSector.MFTCluster, 24 * recordSize / clusterSize));
        LONGLONG MFTSize = 0LL;
        int MFTStage = readRunList (h, 
            0, /*$MFT*/
            0x80,   /*$Data */
            MFTRunList,
            recordSize,
            clusterSize,
            sectorSize,
            totalCluster,
            &MFTRunList,
            &MFTSize);

        _tprintf(_T("MFT stage: %d\n"), MFTStage);
        if (MFTStage == 0 || MFTStage == 1)
            throw _T("MFT stage is 1");
        _tprintf(_T("MFT size: %llu\n"), MFTSize);
        ULONGLONG recordNumber = MFTSize / recordSize;
        _tprintf(_T("Record number: %llu\n"), recordNumber);
        _tprintf(_T("MFT run list: %lld\n"), MFTRunList.size());
        for (Run& run : MFTRunList)
            _tprintf(_T("  %16llx %16llx\n"), run.offset, run.length);

        //  Read file list
        //_tprintf(_T("File List:\n"));

        vector<BYTE> record(recordSize);
        RecordHeader* recordHeader = (RecordHeader*)&record[0];

        std::cout << std::endl << "Директория или диск не повреждены!" << std::endl;

        result = 0;
    }
    catch (LPWSTR error)
    {
        std::cout << "Ошибка: " << error << std::endl;
    }
    catch (std::string error)
    {
        std::cout << error << std::endl;
    }
    catch (...)
    {
        std::cout << "Неизвестная ошибка" << std::endl;
    }

    //if (argv != NULL)
        //delete argv;
    if (h != NULL)
        CloseHandle(h);
    if (output != NULL)
        CloseHandle(output);

    system("pause");

    return 0;
}
