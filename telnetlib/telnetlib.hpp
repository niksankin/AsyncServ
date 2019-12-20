#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <string>
#include <memory>
#include <vector>
#include <functional>
#include <list>

#define MAX_BUFF_SIZE       8192

enum IO_OPERATION {
	ClientIoAccept,
	ClientIoRead,
	ClientIoWrite
};

class TelnetServer;
class TelnetSession;

struct IO_CONTEXT {
	WSAOVERLAPPED               Overlapped;
	IO_OPERATION                operation;
	TelnetSession*				session;
	std::shared_ptr<std::vector<char>> Buffer;
	WSABUF                      wsabuf;
};

const std::string ANSI_FG_BLACK   ("\x1b[30m");
const std::string ANSI_FG_RED     ("\x1b[31m");
const std::string ANSI_FG_GREEN   ("\x1b[32m");
const std::string ANSI_FG_YELLOW  ("\x1b[33m");
const std::string ANSI_FG_BLUE    ("\x1b[34m");
const std::string ANSI_FG_MAGENTA ("\x1b[35m");
const std::string ANSI_FG_CYAN    ("\x1b[36m");
const std::string ANSI_FG_WHITE   ("\x1b[37m");
const std::string ANSI_FG_DEFAULT ("\x1b[39m");

const std::string ANSI_BG_BLACK   ("\x1b[40m");
const std::string ANSI_BG_RED     ("\x1b[41m");
const std::string ANSI_BG_GREEN   ("\x1b[42m");
const std::string ANSI_BG_YELLOW  ("\x1b[43m");
const std::string ANSI_BG_BLUE    ("\x1b[44m");
const std::string ANSI_BG_MAGENTA ("\x1b[45m");
const std::string ANSI_BG_CYAN    ("\x1b[46m");
const std::string ANSI_BG_WHITE   ("\x1b[47m");
const std::string ANSI_BG_DEFAULT ("\x1b[49m");

const std::string ANSI_BOLD_ON       ("\x1b[1m");
const std::string ANSI_BOLD_OFF      ("\x1b[22m");

const std::string ANSI_ITALICS_ON    ("\x1b[3m");
const std::string ANSI_ITALCIS_OFF   ("\x1b[23m");

const std::string ANSI_UNDERLINE_ON  ("\x1b[4m");
const std::string ANSI_UNDERLINE_OFF ("\x1b[24m");

const std::string ANSI_INVERSE_ON    ("\x1b[7m");
const std::string ANSI_INVERSE_OFF   ("\x1b[27m");

const std::string ANSI_STRIKETHROUGH_ON  ("\x1b[9m");
const std::string ANSI_STRIKETHROUGH_OFF ("\x1b[29m");

const std::string ANSI_ERASE_LINE        ("\x1b[2K");
const std::string ANSI_ERASE_SCREEN      ("\x1b[2J");

const std::string ANSI_ARROW_UP("\x1b\x5b\x41");
const std::string ANSI_ARROW_DOWN("\x1b\x5b\x42");
const std::string ANSI_ARROW_RIGHT("\x1b\x5b\x43");
const std::string ANSI_ARROW_LEFT("\x1b\x5b\x44");


const std::string TELNET_ERASE_LINE("\xff\xf8");

const char SIGINT = 0x03;
const char SIGTSTP = 0x1a;

class	TelnetSession : public std::enable_shared_from_this < TelnetSession >
{
public:
    TelnetSession(SOCKET ClientSocket, std::shared_ptr<TelnetServer> ts) : socket(ClientSocket), telnetServer(ts) 
    {
        historyCursor = history.end();
    };

public:
    void sendLine(std::string data);    // Send a line of data to the Telnet Server
	bool update(int readBytes, char recvbuf[]);
	void closeClient();                 // Finish the session

protected:
    void initialise();                  // 
                          // Called every frame/loop by the Terminal Server
	void setTPIO(PTP_IO TPIO) { ioThreadpool = TPIO; }
	PTP_IO getTPIO() { return ioThreadpool; }
	SOCKET getSocket() { return socket; }

private:
	void initContext();
    void sendPromptAndBuffer();         // Write the prompt and any data sat in the input buffer
    void eraseLine();                   // Erase all characters on the current line and move prompt back to beginning of line
    void echoBack(char * buffer, u_long length);
    static void stripNVT(std::string &buffer);
    static void stripEscapeCharacters(std::string &buffer);                 // Remove all escape characters from the line
    static bool processBackspace(std::string &buffer);                      // Takes backspace commands and removes them and the preceeding character from the buffer. // Handles arrow key actions for history management. Returns true if the input buffer was changed.
    void addToHistory(std::string line);                                    // Add a command into the command history
    bool processCommandHistory(std::string &buffer);                        // Handles arrow key actions for history management. Returns true if the input buffer was changed.
    static std::vector<std::string> getCompleteLines(std::string &buffer);  

	friend bool operator == (TelnetSession &lhs, TelnetSession &rhs)
	{
		return ((lhs.socket == rhs.socket) && (lhs.ioThreadpool == rhs.ioThreadpool));
	}

	friend bool operator == (const TelnetSession &lhs, const TelnetSession &rhs)
	{
		return ((lhs.socket == rhs.socket) && (lhs.ioThreadpool == rhs.ioThreadpool));
	}

private:
    SOCKET socket;                // The Winsock socket
    std::shared_ptr<TelnetServer> telnetServer; // Parent TelnetServer class
    std::string buffer;           // Buffer of input data (mid line)
    std::list<std::string>           history;  // A history of all completed commands
    std::list<std::string>::iterator historyCursor;
	IO_CONTEXT ioContext;
	PTP_IO ioThreadpool = NULL;

friend TelnetServer;
};

class TelnetServer : public std::enable_shared_from_this < TelnetServer >
{
public:
    TelnetServer() : promtString("") 
	{
		isInitialized = false;
	};

	~TelnetServer()
	{
		shutdown();
	}

    bool initialise(u_long listenPort, int maxAccept, std::string promptString = "");
    void shutdown();

    bool interactivePrompt() const { return promtString.length() > 0; }
    void promptString(std::string prompt) { promtString = prompt; }
    std::string promptString() const { return promtString; }

private:
	BOOL createListenSocket();

	static void CALLBACK ioCompletionCallback(PTP_CALLBACK_INSTANCE /* Instance */, PVOID  /*Context*/,
		PVOID Overlapped, ULONG IoResult, ULONG_PTR NumberOfBytesTransferred,
		PTP_IO /* Io */);
	static void CALLBACK workerPostAccept(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context, PTP_WORK /* Work */);
	static void CALLBACK workerAddClient(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context);
	static void CALLBACK workerSendPacket(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context);
	static void CALLBACK workerRecvPacket(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context);
	static void CALLBACK workerRemoveClient(PTP_CALLBACK_INSTANCE /* Instance */, PVOID Context);
	static void addClient(TelnetSession* session);
	static void postRecv(TelnetSession* session);
	static void postSend(TelnetSession* session);
	static void removeClient(TelnetSession* session);
	static void onSend(TelnetSession* session, int size);
	static void onRecv(TelnetSession* session, int size);
	static void onAccept(TelnetSession* session);
	static void onClose(TelnetSession* session);
	void postAccept();

private:
    u_long listenPort;
    SOCKET listenSocket;
    std::string promtString;
	PTP_IO ioThreadpoolAccept = NULL;
	int	maxSessionCount;
	TP_CLEANUP_GROUP* sessionCleanupGroup;
	TP_WORK* acceptWorkerHandle;

	static volatile long postedAcceptNum;

	static bool   isInitialized;
	static CRITICAL_SECTION clientCriticalSection;
	static TP_CALLBACK_ENVIRON clientCallbackEnv;
	static std::list<TelnetSession> sessions;
};