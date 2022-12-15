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

//  http://www.writeblocked.org/resources/ntfs_cheat_sheets.pdf

struct BootSector
{
    BYTE        jump[3];
    BYTE        oemID[8];
    WORD        bytePerSector;
    BYTE        sectorPerCluster;
    BYTE        reserved[2];
    BYTE        zero1[3];
    BYTE        unused1[2];
    BYTE        mediaDescriptor;
    BYTE        zeros2[2];
    WORD        sectorPerTrack;
    WORD        headNumber;
    DWORD       hiddenSector;
    BYTE        unused2[8];
    LONGLONG    totalSector;
    LONGLONG    MFTCluster;
    LONGLONG    MFTMirrCluster;
    signed char clusterPerRecord;
    BYTE        unused3[3];
    signed char clusterPerBlock;
    BYTE        unused4[3];
    LONGLONG    serialNumber;
    DWORD       checkSum;
    BYTE        bootCode[0x1aa];
    BYTE        endMarker[2];
};

struct RecordHeader
{
    BYTE        signature[4];
    WORD        updateOffset;
    WORD        updateNumber;
    LONGLONG    logFile;
    WORD        sequenceNumber;
    WORD        hardLinkCount;
    WORD        attributeOffset;
    WORD        flag;
    DWORD       usedSize;
    DWORD       allocatedSize;
    LONGLONG    baseRecord;
    WORD        nextAttributeID;
    BYTE        unsed[2];
    DWORD       MFTRecord;
};

struct AttributeHeaderR
{
    DWORD       typeID;
    DWORD       length;
    BYTE        formCode;
    BYTE        nameLength;
    WORD        nameOffset;
    WORD        flag;
    WORD        attributeID;
    DWORD       contentLength;
    WORD        contentOffset;
    WORD        unused;
};

struct AttributeHeaderNR
{
    DWORD       typeID;
    DWORD       length;
    BYTE        formCode;
    BYTE        nameLength;
    WORD        nameOffset;
    WORD        flag;
    WORD        attributeID;
    LONGLONG    startVCN;
    LONGLONG    endVCN;
    WORD        runListOffset;
    WORD        compressSize;
    DWORD       zero;
    LONGLONG    contentDiskSize;
    LONGLONG    contentSize;
    LONGLONG    initialContentSize;
};

struct FileName
{
    LONGLONG    parentDirectory;
    LONGLONG    dateCreated;
    LONGLONG    dateModified;
    LONGLONG    dateMFTModified;
    LONGLONG    dateAccessed;
    LONGLONG    logicalSize;
    LONGLONG    diskSize;
    DWORD       flag;
    DWORD       reparseValue;
    BYTE        nameLength;
    BYTE        nameType;
    BYTE        name[1];
};

struct AttributeRecord
{
    DWORD       typeID;
    WORD        recordLength;
    BYTE        nameLength;
    BYTE        nameOffset;
    LONGLONG    lowestVCN;
    LONGLONG    recordNumber;
    WORD        sequenceNumber;
    WORD        reserved;
};

#pragma pack(pop)

struct Run
{
    LONGLONG    offset;
    LONGLONG    length;
    Run() : offset(0LL), length(0LL) {}
    Run(LONGLONG offset, LONGLONG length) : offset(offset), length(length) {}
};

void seek(HANDLE h, ULONGLONG position)
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

LPBYTE findAttribute(RecordHeader* record, DWORD recordSize, DWORD typeID, function<bool(LPBYTE)> condition = [&](LPBYTE) {return true; })
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
                p + header->length <= LPBYTE(record) + recordSize &&
                condition(p))
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

vector<Run> parseRunList(BYTE* runList, DWORD runListSize, LONGLONG totalCluster)
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

void fixRecord(BYTE* buffer, DWORD recordSize, DWORD sectorSize)
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

void readRecord(HANDLE h, LONGLONG recordIndex, const vector<Run>& MFTRunList, DWORD recordSize, DWORD clusterSize, DWORD sectorSize, BYTE* buffer)
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

//  read a run list of typeID of recordIndex
//  return stage of the attribute
int readRunList(HANDLE h, LONGLONG recordIndex, DWORD typeID, const vector<Run>& MFTRunList, DWORD recordSize, DWORD clusterSize,
    DWORD sectorSize, LONGLONG totalCluster, vector<Run>* runList, LONGLONG* contentSize = NULL)
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
    //PWSTR* argv = NULL;
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
            std::cout <<  "Введите путь директории" << std::endl;
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

    return result;
}
