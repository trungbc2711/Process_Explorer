#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <string>
#include <map>
#include <sstream>
#include <vector>
#include <tchar.h>
#include <iostream>
#pragma comment(lib, "pdh.lib")

namespace std
{
    typedef std::basic_string<TCHAR> tstring;
    typedef std::basic_ostream<TCHAR> tostream;
    typedef std::basic_istream<TCHAR> tistream;
    typedef std::basic_ostringstream<TCHAR> tostringstream;
    typedef std::basic_istringstream<TCHAR> tistringstream;
    typedef std::basic_stringstream<TCHAR> tstringstream;
} // end namespace

#ifdef UNICODE
#define tcout std::wcout
#else
#define tcout std::cout
#endif

class CPdhQuery
{
public:

    // Inner exception class to report error.
    class CException
    {
    public:
        CException(std::tstring const& errorMsg) : m_errorMsg(errorMsg) {}
        std::tstring What() const { return m_errorMsg; }
    private:
        std::tstring m_errorMsg;
    };

    //! Constructor
    explicit CPdhQuery(std::tstring const& counterPath)
        : m_pdhQuery(NULL)
        , m_pdhStatus(ERROR_SUCCESS)
        , m_pdhCounter(NULL)
        , m_counterPath(counterPath)
    {
        if (m_pdhStatus = PdhOpenQuery(NULL, 0, &m_pdhQuery))
        {
            throw CException(GetErrorString(m_pdhStatus));
        }

        // Specify a counter object with a wildcard for the instance.
        if (m_pdhStatus = PdhAddCounter(
            m_pdhQuery,
            m_counterPath.c_str(),
            0,
            &m_pdhCounter)
            )
        {
            GetErrorString(m_pdhStatus);
            throw CException(GetErrorString(m_pdhStatus));
        }
    }

    //! Destructor. The counter and query handle will be closed.
    ~CPdhQuery()
    {
        m_pdhCounter = NULL;
        if (m_pdhQuery)
            PdhCloseQuery(m_pdhQuery);
    }

    //! Collect all the data since the last sampling period.
    std::map<std::tstring, double> CollectQueryData()
    {
        std::map<std::tstring, double> collectedData;

        while (true)
        {
            // Collect the sampling data. This might cause
            // PdhGetFormattedCounterArray to fail because some query type
            // requires two collections (or more?). If such scenario is
            // detected, the while loop will retry.
            if (m_pdhStatus = PdhCollectQueryData(m_pdhQuery))
            {
                throw CException(GetErrorString(m_pdhStatus));
            }

            // Size of the pItems buffer
            DWORD bufferSize = 0;

            // Number of items in the pItems buffer
            DWORD itemCount = 0;

            PDH_FMT_COUNTERVALUE_ITEM* pdhItems = NULL;

            // Call PdhGetFormattedCounterArray once to retrieve the buffer
            // size and item count. As long as the buffer size is zero, this
            // function should return PDH_MORE_DATA with the appropriate
            // buffer size.
            m_pdhStatus = PdhGetFormattedCounterArray(
                m_pdhCounter,
                PDH_FMT_DOUBLE,
                &bufferSize,
                &itemCount,
                pdhItems);

            // If the returned value is nto PDH_MORE_DATA, the function
            // has failed.
            if (PDH_MORE_DATA != m_pdhStatus)
            {
                throw CException(GetErrorString(m_pdhStatus));
            }

            std::vector<unsigned char> buffer(bufferSize);
            pdhItems = (PDH_FMT_COUNTERVALUE_ITEM*)(&buffer[0]);

            m_pdhStatus = PdhGetFormattedCounterArray(
                m_pdhCounter,
                PDH_FMT_DOUBLE,
                &bufferSize,
                &itemCount,
                pdhItems);

            if (ERROR_SUCCESS != m_pdhStatus)
            {
                continue;
            }

            // Everything is good, mine the data.
            for (DWORD i = 0; i < itemCount; i++)
            {
                collectedData.insert(
                    std::make_pair(
                        std::tstring(pdhItems[i].szName),
                        pdhItems[i].FmtValue.doubleValue)
                );
            }

            pdhItems = NULL;
            bufferSize = itemCount = 0;
            break;
        }
        return collectedData;
    }

private:
    //! Helper function that translate the PDH error code into
    //! an useful message.
    std::tstring GetErrorString(PDH_STATUS errorCode)
    {
        HANDLE hPdhLibrary = NULL;
        LPTSTR pMessage = NULL;
        DWORD_PTR pArgs[] = { (DWORD_PTR)m_searchInstance.c_str() };
        std::tstring errorString;

        hPdhLibrary = LoadLibrary(_T("pdh.dll"));
        if (NULL == hPdhLibrary)
        {
            std::tstringstream ss;
            ss
                << _T("Format message failed with ")
                << std::hex << GetLastError();
            return ss.str();
        }

        if (!FormatMessage(FORMAT_MESSAGE_FROM_HMODULE |
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            /*FORMAT_MESSAGE_IGNORE_INSERTS |*/
            FORMAT_MESSAGE_ARGUMENT_ARRAY,
            hPdhLibrary,
            errorCode,
            0,
            (LPTSTR)&pMessage,
            0,
            (va_list*)pArgs))
        {
            std::tstringstream ss;
            ss
                << m_counterPath
                << _T(" ")
                << _T("Format message failed with ")
                << std::hex
                << GetLastError()
                << std::endl;
            errorString = ss.str();
        }
        else
        {
            errorString += m_counterPath;
            errorString += _T(" ");
            errorString += pMessage;
            LocalFree(pMessage);
        }

        return errorString;
    }

private:
    PDH_HQUERY m_pdhQuery;
    PDH_STATUS m_pdhStatus;
    PDH_HCOUNTER m_pdhCounter;
    std::tstring m_searchInstance;
    std::tstring m_counterPath;
};

void DumpMap(std::map<std::tstring, double> const& m)
{
    std::map<std::tstring, double>::const_iterator itr = m.begin();
    while (m.end() != itr)
    {
        tcout << itr->first << " " << itr->second << std::endl;
        ++itr;
    }
}

double CPdhQuery::CollectSingleData()
{
    double data = 0;
    while (true)
    {
        status = PdhCollectQueryData(hQuery);

        if (ERROR_SUCCESS != status)
        {
            throw CException(GetErrorString(status));
        }

        PDH_FMT_COUNTERVALUE cv;
        // Format the performance data record.

        status = PdhGetFormattedCounterValue(hCounter,
            PDH_FMT_DOUBLE,
            (LPDWORD)NULL,
            &cv);

        if (ERROR_SUCCESS != status)
        {
            continue;
        }

        data = cv.doubleValue;

        break;

    }

    return data;
}

void main()
{
    try
    {
        // uncomment to try different counter paths
        CPdhQuery pdhQuery(
            std::tstring(_T("\\Thread(*)\\Context Switches/sec"))
            //std::tstring(_T("\\Thread(firefox/0)\\Context Switches/sec"))
            //tstring(L"\\Processor(*)\\% Processor Time")
            //tstring(_T("\\Processor(*)\\Interrupts/sec"))
            //tstring(L"\\Processor(_Total)\\Interrupts/sec")
        );
        for (int i = 0; i < 100; ++i)
        {
            Sleep(1000);
            DumpMap(pdhQuery.CollectQueryData());
        }
    }
    catch (CPdhQuery::CException const& e)
    {
        tcout << e.What() << std::endl;
    }
}