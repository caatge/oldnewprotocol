#include "netmsg.h"
#include "bitbuf.h"
#include "shared.h"
#include "vstdlib/strtools.h"
#include "vector"
#include "string"

const std::vector<std::string> CommonPathIDs = { "GAME", "MOD" };

const std::vector<std::string> DoNotQuery = { "password", "rcon_address", "rcon_password" };

const char* g_MostCommonPrefixes[] = // ugh
{
    "materials",
    "models",
    "sounds",
    "scripts"
};

static bool CStringInVector(const std::vector<std::string>& v, const char* str) {
    for (auto& elem : v) {
        if (elem == str) return true;
    }
    return false;
}

static int FindCommonPathID(const char* pPathID)
{
    int i = 0;
    for (auto& elem : CommonPathIDs) {
        if (pPathID == elem) {
            return i;
        }
        i++;
    }
    return -1;
}

static int FindCommonPrefix(const char* pStr)
{
    for (int i = 0; i < ARRAYSIZE(g_MostCommonPrefixes); i++)
    {
        if (Q_stristr(pStr, g_MostCommonPrefixes[i]) == pStr)
        {
            int iNextChar = Q_strlen(g_MostCommonPrefixes[i]);
            if (pStr[iNextChar] == '/' || pStr[iNextChar] == '\\')
                return i;
        }
    }
    return -1;
}


bool SVC_GetCvarValue::ReadFromBuffer(bf_read& buffer)
{
    //VPROF("SVC_GetCvarValue::ReadFromBuffer");

    m_iCookie = buffer.ReadSBitLong(32);
    buffer.ReadString(m_szCvarNameBuffer, sizeof(m_szCvarNameBuffer));
    m_szCvarName = m_szCvarNameBuffer;

    return !buffer.IsOverflowed();
}


bool SVC_GetCvarValue::WriteToBuffer(bf_write& buffer)
{
    buffer.WriteUBitLong(GetType(), 5);

    buffer.WriteSBitLong(m_iCookie, 32);
    buffer.WriteString(m_szCvarName);

    return !buffer.IsOverflowed();
}

bool SVC_GetCvarValue::Process() {

    // Prepare the response.
    CLC_RespondCvarValue returnMsg;

    returnMsg.m_iCookie = m_iCookie;
    returnMsg.m_szCvarName = m_szCvarName;
    returnMsg.m_szCvarValue = "";
    returnMsg.m_eStatusCode = eQueryCvarValueStatus_CvarNotFound;

    char tempValue[256];

    // Does any ConCommand exist with this name?
    const ConVar* pVar = g_pCVar->FindVar(m_szCvarName);
    if (pVar)
    {
        if (pVar->IsCommand()) {
            returnMsg.m_eStatusCode = eQueryCvarValueStatus_NotACvar;
        }
        if (CStringInVector(DoNotQuery, m_szCvarName))
        {
            returnMsg.m_eStatusCode = eQueryCvarValueStatus_CvarProtected;
        }
        else
        {
            returnMsg.m_eStatusCode = eQueryCvarValueStatus_ValueIntact;

            if (pVar->IsBitSet(FCVAR_NEVER_AS_STRING))
            {
                // The cvar won't store a string, so we have to come up with a string for it ourselves.
                if (fabs(pVar->GetFloat() - pVar->GetInt()) < 0.001f)
                {
                    Q_snprintf(tempValue, sizeof(tempValue), "%d", pVar->GetInt());
                }
                else
                {
                    Q_snprintf(tempValue, sizeof(tempValue), "%f", pVar->GetFloat());
                }
                returnMsg.m_szCvarValue = tempValue;
            }
            else
            {
                // The easy case..
                returnMsg.m_szCvarValue = pVar->GetString();
            }
        }
    }
    else
    {
        returnMsg.m_eStatusCode = eQueryCvarValueStatus_CvarNotFound;
    }

    // Send back.
    m_NetChannel->SendNetMsg(returnMsg);
    return true;
}

bool CLC_RespondCvarValue::ReadFromBuffer(bf_read& buffer)
{

    m_iCookie = buffer.ReadSBitLong(32);
    m_eStatusCode = (EQueryCvarValueStatus)buffer.ReadSBitLong(4);

    // Read the name.
    buffer.ReadString(m_szCvarNameBuffer, sizeof(m_szCvarNameBuffer));
    m_szCvarName = m_szCvarNameBuffer;

    // Read the value.
    buffer.ReadString(m_szCvarValueBuffer, sizeof(m_szCvarValueBuffer));
    m_szCvarValue = m_szCvarValueBuffer;

    return !buffer.IsOverflowed();
}

bool CLC_RespondCvarValue::WriteToBuffer(bf_write& buffer)
{
    buffer.WriteUBitLong(GetType(), 5);

    buffer.WriteSBitLong(m_iCookie, 32);
    buffer.WriteSBitLong(m_eStatusCode, 4);

    buffer.WriteString(m_szCvarName);
    buffer.WriteString(m_szCvarValue);

    return !buffer.IsOverflowed();
}

bool CLC_FileCRCCheck::WriteToBuffer(bf_write& buffer)
{
    buffer.WriteUBitLong(GetType(), 5);

    // Reserved for future use.
    buffer.WriteOneBit(0);

    // Just write a couple bits for the path ID if it's one of the common ones.
    int iCode = FindCommonPathID(m_szPathID);
    if (iCode == -1)
    {
        buffer.WriteUBitLong(0, 2);
        buffer.WriteString(m_szPathID);
    }
    else
    {
        buffer.WriteUBitLong(iCode + 1, 2);
    }

    iCode = FindCommonPrefix(m_szFilename);
    if (iCode == -1)
    {
        buffer.WriteUBitLong(0, 3);
        buffer.WriteString(m_szFilename);
    }
    else
    {
        buffer.WriteUBitLong(iCode + 1, 3);
        buffer.WriteString(&m_szFilename[Q_strlen(g_MostCommonPrefixes[iCode]) + 1]);
    }

    buffer.WriteUBitLong(m_CRC, 32);
    return !buffer.IsOverflowed();
}

bool CLC_FileCRCCheck::ReadFromBuffer(bf_read& buffer)
{

    // Reserved for future use.
    buffer.ReadOneBit();

    // Read the path ID.
    int iCode = buffer.ReadUBitLong(2);
    if (iCode == 0)
    {
        buffer.ReadString(m_szPathID, sizeof(m_szPathID));
    }
    else if ((iCode - 1) < CommonPathIDs.size())
    {
        Q_strncpy(m_szPathID, CommonPathIDs[iCode - 1].c_str(), sizeof(m_szPathID));
    }
    else
    {
        _SpewMessage("love is in the air? WRONG. INVALID path ID code in my CLC_FileCRCCheck");
        return false;
    }

    // Read the filename.
    iCode = buffer.ReadUBitLong(3);
    if (iCode == 0)
    {
        buffer.ReadString(m_szFilename, sizeof(m_szFilename));
    }
    else if ((iCode - 1) < ARRAYSIZE(g_MostCommonPrefixes))
    {
        char szTemp[MAX_PATH];
        buffer.ReadString(szTemp, sizeof(szTemp));
        Q_snprintf(m_szFilename, sizeof(m_szFilename), "%s%c%s", g_MostCommonPrefixes[iCode - 1], CORRECT_PATH_SEPARATOR, szTemp);
    }
    else
    {
        _SpewMessage("Invalid prefix code in CLC_FileCRCCheck.");
        return false;
    }

    m_CRC = buffer.ReadUBitLong(32);

    return !buffer.IsOverflowed();
}
