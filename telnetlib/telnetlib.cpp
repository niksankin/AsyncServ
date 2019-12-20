#include "telnetlib.hpp"
#include "iostream"
#include <assert.h>
#include <array>
#include <iterator>
#include <sstream>

#pragma comment (lib, "Ws2_32.lib")

bool   TelnetServer::isInitialized;
CRITICAL_SECTION TelnetServer::clientCriticalSection;
TP_CALLBACK_ENVIRON TelnetServer::clientCallbackEnv;
std::list<TelnetSession> TelnetServer::sessions;
volatile long TelnetServer::postedAcceptNum = 0;

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
    u_long iSendResult;
    iSendResult = send(socket, telnetServer->promptString().c_str(), (u_long)telnetServer->promptString().length(), 0);

    if (buffer.length() > 0)
    {
        iSendResult = send(socket, buffer.c_str(), (u_long)buffer.length(), 0);
    }
}

void TelnetSession::eraseLine()
{
    u_long iSendResult;    
    iSendResult = send(socket, ANSI_ERASE_LINE.c_str(), (u_long)ANSI_ERASE_LINE.length(), 0);

    std::string moveBack = "\x1b[80D";
    iSendResult = send(socket, moveBack.c_str(), (u_long)moveBack.length(), 0);
}

void TelnetSession::sendLine(std::string data)
{
    u_long iSendResult;
    if (telnetServer->interactivePrompt() || buffer.length() > 0)
    {
        eraseLine();
    }

    data.append("\r\n");
    iSendResult = send(socket, data.c_str(), (u_long)data.length(), 0);

    if (telnetServer->interactivePrompt())
        sendPromptAndBuffer();
}

void TelnetSession::closeClient()
{
    u_long iResult;

    iResult = shutdown(socket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        return;
    }

    // cleanup
    closesocket(socket);
}

void TelnetSession::echoBack(char * buffer, u_long length)
{
    unsigned char firstItem = * buffer;
    if (firstItem == 0xff)
        return;

    u_long iSendResult;
    iSendResult = send(socket, buffer, length, 0);

    if (iSendResult == SOCKET_ERROR && iSendResult != WSAEWOULDBLOCK) {
        printf("Send failed with Winsock error: %d\n", WSAGetLastError());
        std::cout << "Closing session and socket.\r\n";
        closesocket(socket);
        return;
    }
}

void TelnetSession::initialise()
{
    SOCKADDR_IN client_info = { 0 };
    int addrsize = sizeof(client_info);
    getpeername(socket, (struct sockaddr*)&client_info, &addrsize);

    char ip[16];
    inet_ntop(AF_INET, &client_info.sin_addr, &ip[0], 16);

    std::cout << "Client " << ip << " connected...\n";

    // Set the connection to be non-blocking
    u_long iMode = 1;
    ioctlsocket(socket, FIONBIO, &iMode);

    // Set NVT mode to say that I will echo back characters.
    u_long iSendResult;
    unsigned char willEcho[3] = { 0xff, 0xfb, 0x01 };
    iSendResult = send(socket, (char *)willEcho, 3, 0);

    // Set NVT requesting that the remote system not/dont echo back characters
    unsigned char dontEcho[3] = { 0xff, 0xfe, 0x01 };
    iSendResult = send(socket, (char *)dontEcho, 3, 0);

    // Set NVT mode to say that I will supress go-ahead. Stops remote clients from doing local linemode.
    unsigned char willSGA[3] = { 0xff, 0xfb, 0x03 };
    iSendResult = send(socket, (char *)willSGA, 3, 0);
}

void TelnetSession::initContext()
{
	ioContext.Overlapped.Internal = 0;
	ioContext.Overlapped.InternalHigh = 0;
	ioContext.Overlapped.Offset = 0;
	ioContext.Overlapped.OffsetHigh = 0;
	ioContext.Overlapped.hEvent = NULL;
	ioContext.operation = ClientIoAccept;
	ioContext.session = this;
	ioContext.Buffer = std::make_shared<std::vector<char>>(MAX_BUFF_SIZE);
	ioContext.wsabuf.buf = ioContext.Buffer->data();
	ioContext.wsabuf.len = ioContext.Buffer->capacity();

	ZeroMemory(ioContext.wsabuf.buf, ioContext.wsabuf.len);
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
    if (line != (history.size() > 0 ? history.back() : "") && line != "")
    {
        history.push_back(line);
        if (history.size() > 50)
            history.pop_front();
    }
    historyCursor = history.end();
	--historyCursor;
}

bool TelnetSession::processCommandHistory(std::string &buffer)
{
    // Handle up and down arrow actions
    if (telnetServer->interactivePrompt())
    {
        if (buffer.find(ANSI_ARROW_UP) != std::string::npos && history.size() > 0)
        {
            if (historyCursor != history.begin())
            {
                historyCursor--;
            }
            buffer = *historyCursor;

            // Issue a cursor command to counter it
            u_long iSendResult;
            iSendResult = send(socket, ANSI_ARROW_DOWN.c_str(), (u_long)ANSI_ARROW_DOWN.length(), 0);
            return true;
        }
        if (buffer.find(ANSI_ARROW_DOWN) != std::string::npos && history.size() > 0)
        {
            if (next(historyCursor) != history.end())
            {
                historyCursor++;
            }
            buffer = *historyCursor;

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

        buffer.append(recvbuf, readBytes);

        stripNVT(buffer);

        bool requirePromptReprint = false;

        if (telnetServer->interactivePrompt())
        {
            if (processCommandHistory(buffer))
                requirePromptReprint = true;
            stripEscapeCharacters(buffer);

            if (processBackspace(buffer))
                requirePromptReprint = true;
        }

        auto lines = getCompleteLines(buffer);
        for (auto line : lines)
        {            
            addToHistory(line);

			std::string result = cmd(line);

			sendLine(result);
        }

        if (telnetServer->interactivePrompt() && requirePromptReprint)
        {
            eraseLine();
            sendPromptAndBuffer();
        }
    }

	return true;
}

BOOL TelnetServer::createListenSocket() {
	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iResult;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	iResult = getaddrinfo(NULL, std::to_string(listenPort).c_str(), &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		return false;
	}

	listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (listenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		return false;
	}

	iResult = bind(listenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(listenSocket);
		return false;
	}

	freeaddrinfo(result);

	return true;
}

void CALLBACK TelnetServer::ioCompletionCallback(PTP_CALLBACK_INSTANCE /* Instance */, PVOID  /*Context*/,
	PVOID Overlapped, ULONG IoResult, ULONG_PTR NumberOfBytesTransferred,
	PTP_IO /* Io */)
{
	IO_CONTEXT* lioContext = NULL;
	TelnetSession* localSession;

	lioContext = (IO_CONTEXT*)Overlapped;
	localSession = lioContext->session;

	if (IoResult != ERROR_SUCCESS)
	{
		printf("I/O operation failed. type[%d]\n", lioContext->operation);

		onClose(localSession);
	}
	else
	{
		switch (lioContext->operation) {
		case ClientIoAccept:
			onAccept(localSession);
			break;
		case ClientIoRead:
			localSession->update(NumberOfBytesTransferred, lioContext->Buffer->data());
			onRecv(localSession, NumberOfBytesTransferred);
			break;
		case ClientIoWrite:
			onSend(localSession, NumberOfBytesTransferred);
			break;
		}
	}
}

void CALLBACK TelnetServer::workerPostAccept(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context, PTP_WORK /* Work */) //запускаем цикл ассепта как worker
{
	TelnetServer* server = static_cast<TelnetServer*>(Context);
	assert(server);

	while (server->isInitialized)
	{
		server->postAccept();
	}
}

void CALLBACK TelnetServer::workerRecvPacket(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context)
{
	TelnetSession* session = static_cast<TelnetSession*>(Context);

	postRecv(session);
}

void CALLBACK TelnetServer::workerSendPacket(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context)
{
	TelnetSession* session = static_cast<TelnetSession*>(Context);

	postSend(session);
}

void CALLBACK TelnetServer::workerRemoveClient(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context)
{
	TelnetSession* session = static_cast<TelnetSession*>(Context);

	removeClient(session);
}

void TelnetServer::removeClient(TelnetSession* session)
{
	EnterCriticalSection(&clientCriticalSection);

	auto itor = std::find(sessions.begin(), sessions.end(), *session);

	if (itor != sessions.end())
	{
		printf("[%d] RemoveClient succeeded.\n", GetCurrentThreadId());

		session->closeClient();
		sessions.erase(itor);
	}

	LeaveCriticalSection(&clientCriticalSection);
}

void TelnetServer::postSend(TelnetSession* session)
{
	DWORD dwRecvNumBytes = 0;
	DWORD dwFlags = 0;
	int iResult;

	session->ioContext.operation = ClientIoWrite;

	StartThreadpoolIo(session->getTPIO());

	iResult = WSASend(session->getSocket(), &(session->ioContext.wsabuf),
		1, &dwRecvNumBytes, dwFlags,
		&(session->ioContext.Overlapped), NULL);

	if (iResult == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
		CancelThreadpoolIo(session->getTPIO());

		printf("CreateThreadpoolCleanupGroup failed with error: %d\n", GetLastError());
	}
}

void TelnetServer::postRecv(TelnetSession* session)
{
	DWORD dwRecvNumBytes = 0;
	DWORD dwFlags = 0;
	int iResult;

	session->ioContext.operation = ClientIoRead;

	StartThreadpoolIo(session->getTPIO());

	iResult = WSARecv(session->getSocket(), &(session->ioContext.wsabuf),
		1, &dwRecvNumBytes, &dwFlags,
		&(session->ioContext.Overlapped), NULL);
	if (iResult == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
		CancelThreadpoolIo(session->getTPIO());

		printf("CreateThreadpoolCleanupGroup failed with error: %d\n", GetLastError());

		onClose(session);
	}
}

void TelnetServer::addClient(TelnetSession* session)
{
	TP_IO* TPIO = CreateThreadpoolIo(reinterpret_cast<HANDLE>(session->getSocket()), TelnetServer::ioCompletionCallback, NULL, NULL);

	EnterCriticalSection(&clientCriticalSection);
	session->setTPIO(TPIO);
	session->initialise();
	LeaveCriticalSection(&clientCriticalSection);

	printf("UpdateCompletionPort: Socket(%d) added to IOCP\n", session->getSocket());

	postRecv(session);
}

void CALLBACK TelnetServer::workerAddClient(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context)
{
	TelnetSession* session = static_cast<TelnetSession*>(Context);

	addClient(session);
}

void TelnetServer::onSend(TelnetSession* session, int size)
{
	if (!TrySubmitThreadpoolCallback(workerSendPacket, session, &clientCallbackEnv))
		postSend(session);
}

void TelnetServer::onRecv(TelnetSession* session, int size)
{
	if (!TrySubmitThreadpoolCallback(workerRecvPacket, session, &clientCallbackEnv))
		postRecv(session);
}

void TelnetServer::onAccept(TelnetSession* session)
{
	InterlockedDecrement(&postedAcceptNum);

	if (isInitialized && !TrySubmitThreadpoolCallback(workerAddClient, session, &clientCallbackEnv))
		addClient(session);
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

void TelnetServer::postAccept()
{
	int count = maxSessionCount - postedAcceptNum;
	if (count > 0)
	{
		int i = 0;
		for (; i < count; ++i)
		{
			SOCKET clientSocket = INVALID_SOCKET;
			static BYTE buffer[(sizeof(sockaddr_in6) + 16) * 2];
			int iResult;

			LPFN_ACCEPTEX acceptEx = NULL;
			DWORD dwBytes = 0;
			GUID guidAcceptEx = WSAID_ACCEPTEX;
			if (WSAIoctl(listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guidAcceptEx,
				sizeof(guidAcceptEx), &acceptEx, sizeof(acceptEx), &dwBytes, 0,
				0) == SOCKET_ERROR)
			{
				printf("WSAIoctl() failed: %d\n", GetLastError());
				return;
			}

			clientSocket = CreateSocket(0);

			if (clientSocket == INVALID_SOCKET)
			{
				printf("WSASocket() failed: %d\n", GetLastError());
				return;
			}

			sessions.push_back(TelnetSession(clientSocket, shared_from_this()));
			TelnetSession* s = &(*(--sessions.end()));
			s->initContext();

			StartThreadpoolIo(ioThreadpoolAccept);

			iResult = acceptEx(listenSocket,
				clientSocket,
				&buffer,
				0,
				sizeof(sockaddr_in6) + 16,
				sizeof(sockaddr_in6) + 16,
				NULL,
				&(s->ioContext.Overlapped)
			);

			if (!iResult)
			{
				int error = WSAGetLastError();

				if (error != ERROR_IO_PENDING)
				{
					CancelThreadpoolIo(ioThreadpoolAccept);

					printf("AcceptEx() failed: %d\n", error);
					break;
				}
			}
			else
			{
				onAccept(s);
			}
		}

		InterlockedExchangeAdd(&postedAcceptNum, i);

		printf("[%d] Post AcceptEx : %d\n", GetCurrentThreadId(), postedAcceptNum);
	}
}

/* ------------------ Telnet Server -------------------*/
bool TelnetServer::initialise(u_long listenPort, int maxAccept, std::string promptString)
{
	if (isInitialized)
	{
		std::cout << "This Telnet Server instance has already been initialised. Please shut it down before reinitialising it.";
		return false;
	}

	listenPort = listenPort;
	promtString = promptString;
	listenSocket = INVALID_SOCKET;

	std::cout << "Starting Telnet Server on port " << std::to_string(listenPort) << "\n";

	WSADATA wsaData;
	int iResult;

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return false;
	}

	maxSessionCount = maxAccept;

	InitializeThreadpoolEnvironment(&clientCallbackEnv);

	sessionCleanupGroup = CreateThreadpoolCleanupGroup();
	if (sessionCleanupGroup == NULL)
	{
		printf("CreateThreadpoolCleanupGroup failed with error: %d\n", GetLastError());
		return false;
	}

	SetThreadpoolCallbackCleanupGroup(&clientCallbackEnv, sessionCleanupGroup, NULL);

	if (!createListenSocket())
		return false;

	ioThreadpoolAccept = CreateThreadpoolIo(reinterpret_cast<HANDLE>(listenSocket),
		TelnetServer::ioCompletionCallback, NULL, NULL);
	if (ioThreadpoolAccept == NULL)
	{
		printf("CreateThreadpoolIo failed with error: %d\n",WSAGetLastError());
		shutdown();
		return false;
	}

	StartThreadpoolIo(ioThreadpoolAccept);

	if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(listenSocket);
		return false;
	}

	InitializeCriticalSection(&clientCriticalSection);

	acceptWorkerHandle = CreateThreadpoolWork(TelnetServer::workerPostAccept, this, NULL);
	if (acceptWorkerHandle == NULL)
	{
		printf("CreateThreadpoolWork failed with error: %d\n", WSAGetLastError());
		shutdown();
		return false;
	}

	SubmitThreadpoolWork(acceptWorkerHandle);

    isInitialized = true;
    return true;
}

void TelnetServer::onClose(TelnetSession* session)
{
	printf("Client's socket has been closed.\n");

	if (isInitialized &&
		!TrySubmitThreadpoolCallback(TelnetServer::workerRemoveClient, session, &clientCallbackEnv))
	{
		printf("TrySubmitThreadpoolCallback failed with error: %d\n", WSAGetLastError());

		removeClient(session);
	}
}

void TelnetServer::shutdown()
{
	isInitialized = false;

	if (acceptWorkerHandle != NULL)
	{
		WaitForThreadpoolWorkCallbacks(acceptWorkerHandle, true);
		CloseThreadpoolWork(acceptWorkerHandle);
		acceptWorkerHandle = NULL;
	}

	if (listenSocket != INVALID_SOCKET)
	{
		closesocket(listenSocket);
		CancelIoEx(reinterpret_cast<HANDLE>(listenSocket), NULL);
		listenSocket = INVALID_SOCKET;
	}

	if (ioThreadpoolAccept != NULL)
	{
		WaitForThreadpoolIoCallbacks(ioThreadpoolAccept, true);
		CloseThreadpoolIo(ioThreadpoolAccept);
		ioThreadpoolAccept = NULL;
	}

	if (sessionCleanupGroup != NULL)
	{
		CloseThreadpoolCleanupGroupMembers(sessionCleanupGroup, false, NULL);
		CloseThreadpoolCleanupGroup(sessionCleanupGroup);
		DestroyThreadpoolEnvironment(&clientCallbackEnv);
		sessionCleanupGroup = NULL;
	}

	EnterCriticalSection(&clientCriticalSection);
	for (auto session : sessions)
	{
		session.closeClient();
	}
	sessions.clear();
	LeaveCriticalSection(&clientCriticalSection);

	DeleteCriticalSection(&clientCriticalSection);
}