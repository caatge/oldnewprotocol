#pragma once
#include "inetchannel.h"
#include "inetmessage.h"

class CNetMessage : public INetMessage
{
public:
    CNetMessage() {
        m_bReliable = true;
        m_NetChannel = 0;
    }

    virtual ~CNetMessage() {};

    virtual int		GetGroup() const { return INetChannelInfo::GENERIC; }
    INetChannel* GetNetChannel() const { return m_NetChannel; }

    virtual void	SetReliable(bool state) { m_bReliable = state; };
    virtual bool	IsReliable() const { return m_bReliable; };
    virtual void    SetNetChannel(INetChannel* netchan) { m_NetChannel = netchan; }
    virtual bool	Process() { return false; };	// no handler set

protected:
    bool				m_bReliable;	// true if message should be send reliable
    INetChannel* m_NetChannel;	// netchannel this message is from/for
};

typedef int QueryCvarCookie_t;

typedef enum
{
    eQueryCvarValueStatus_ValueIntact = 0,	// It got the value fine.
    eQueryCvarValueStatus_CvarNotFound = 1,
    eQueryCvarValueStatus_NotACvar = 2,		// There's a ConCommand, but it's not a ConVar.
    eQueryCvarValueStatus_CvarProtected = 3	// The cvar was marked with FCVAR_SERVER_CAN_NOT_QUERY, so the server is not allowed to have its value.
} EQueryCvarValueStatus;

class SVC_GetCvarValue : public CNetMessage {
public:
    bool			ReadFromBuffer(bf_read& buffer);
    bool			WriteToBuffer(bf_write& buffer);
    bool            Process();
    const char* ToString() const { return ""; }
    int				GetType() const { return 31; }
    const char* GetName() const { return "GetCvarValue"; }
    QueryCvarCookie_t	m_iCookie{};
    const char* m_szCvarName{};
private:
    char		m_szCvarNameBuffer[256]{};
};

class CLC_RespondCvarValue : public CNetMessage
{
public:
    bool			ReadFromBuffer(bf_read& buffer);
    bool			WriteToBuffer(bf_write& buffer);
    bool            Process() { return true; };
    const char* ToString() const { return ""; };
    int				GetType() const { return 13; }
    const char* GetName() const { return "clc_RespondCvarValue"; }

    QueryCvarCookie_t		m_iCookie;

    const char* m_szCvarName;
    const char* m_szCvarValue;	// The sender sets this, and it automatically points it at m_szCvarNameBuffer when receiving.

    EQueryCvarValueStatus	m_eStatusCode;

private:
    char		m_szCvarNameBuffer[256];
    char		m_szCvarValueBuffer[256];
};

class CLC_FileCRCCheck : public CNetMessage
{
public:
    bool			ReadFromBuffer(bf_read& buffer);
    bool			WriteToBuffer(bf_write& buffer);
    bool            Process() { return true; };
    const char* ToString() const { return ""; };
    int				GetType() const { return 14; }
    const char* GetName() const { return "clc_FileCRCCheck"; }

    char		m_szPathID[260]{};
    char		m_szFilename[260]{};
    unsigned long		m_CRC{};
};