/* START: libnice imports */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <nice/agent.h>
#include <nice/pseudotcp.h>
/* END: libnice imports */
#include <glib-unix.h>

#include <gloox/client.h>
#include <gloox/connectionlistener.h>
#include <gloox/connectiontcpclient.h>
#include <gloox/disco.h>
#include <gloox/jid.h>
#include <gloox/messagehandler.h>
#include <gloox/message.h>

#include <gio/gunixinputstream.h>
#include <gio/gunixoutputstream.h>

#include <sstream>
#include <string>

#include<sys/socket.h>
#include<errno.h> //For errno - the error number
#include<netdb.h> //hostent

#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>

using namespace std;
using namespace gloox;

enum Mode { SERVER, CLIENT };

timeval t; // just for some debugging
GError * error = NULL;

class Icer;

const static int buffer_size = 65536;

GMainLoop *gloop = NULL;

struct StreamState {
	GInputStream * in;
	GOutputStream * out;
	gssize read_bytes;
	gssize written_bytes;
	unsigned char buffer[buffer_size];
	char* inname;
	char* outname;
};

class Agent {
public:
	string remote_candidates;
	bool negotiationComplete[2];
	int connCheckNum; // number of sent connChecks since the last received connCheck
	static const int connCheckInterval = 15000; // in miliseconds

	StreamState remoteToLocal;
	StreamState localToRemote;

	GIOStream * gstream;

	NiceAgent * agent;
	guint stream_id;
	Icer * parent;
	JID * otherJid;
	Agent(Icer * icer, const JID & otherJid);
	~Agent();
	int parse_remote_data(guint component_id, string line_str);
	void initTCP();
	static void new_selected_pair(
		NiceAgent *agent,
		guint stream_id,
		guint component_id,
		gchar *lfoundation,
		gchar *rfoundation,
		gpointer data);
	static void component_state_changed(NiceAgent *agent, guint stream_id,
		guint component_id, guint state,
		gpointer data);
	int print_local_data(guint stream_id, guint component_id, string & candidates);

	static void gathering_done(NiceAgent *agent1, guint stream_id, gpointer data);
	gboolean recvConnCheck();
	gboolean sendConnCheck();
};

/* START: LIBNICE DECLS */
static const gchar *candidate_type_name[] = {"host", "srflx", "prflx", "relay"};
static const gchar *candidate_transport_name[] = {"udp", "tcp_active", "tcp_passive", "tcp_so"};
/* END: LIBNICE DECLS */

// dirty hack
int slp(void*) {
	g_error("kill");
	usleep(1000 * 1000);
	exit(0);
	return true;
}

class Icer : public MessageHandler, public ConnectionListener
{
private:
	JID * otherJid;
public:
	Client* xmppClient;
	Mode mode;
	static const string request;
	Agent* agent;
	gchar* stun_addr;
	guint stun_port;
	char* localport;
	bool connected;

	const static int pipe_buffer_size = 65536;
	unsigned char* pipe_buffer;
	int pipefd[2];
	bool pendingAnswer;
	bool isChildProcess;

	Icer(Client *c, JID * otherJid, Mode mode, gchar* stun_addr, guint stun_port, char * localport)
		: xmppClient(c), otherJid(otherJid), mode(mode), stun_addr(stun_addr), stun_port(stun_port), localport(localport)
	{
		xmppClient->registerConnectionListener(this);
		xmppClient->registerMessageHandler(this);
		
		pendingAnswer = false;
		isChildProcess = false;
		connected = false;
		
		if(pipe(pipefd) != 0) { g_error("no pipe"); }
		pipe_buffer = (unsigned char*) malloc(pipe_buffer_size);
		if (pipe_buffer == NULL) { g_error("can't allocate pipe buffer"); }
// 		if (mode == SERVER) {
// 			c->disco()->addFeature("https://github.com/yokto/xicecat/1/" + otherJid->resource());
// 			c->disco()->setIdentity("client", "xicecat");
// 		}
	}
	void onConnect() {
		connected=true;
		g_debug("connected yes with jid: %s", xmppClient->jid().full().c_str());
		if (mode == CLIENT) {
			xmppClient->send(Message(Message::Normal, *otherJid, "hi"));
			agent = new Agent(this, *otherJid);
		}
		if (mode == SERVER && pendingAnswer == true) {
			requestICE(*otherJid,string((char*)pipe_buffer));
			pendingAnswer = false;
		}
	}
	bool onTLSConnect(const CertInfo& cert) {
		g_debug("ignoring tls certificate (we don't care)");
		return true;
	}
	void onDisconnect(ConnectionError e) {
		g_warning("stream error: %d", xmppClient->streamError());
		g_warning("stream error text: %s", xmppClient->streamErrorText().c_str());
	}
	void handleMessage (const Message &msg, MessageSession *session=0) {
		g_debug("XMPP Message: %s\n\t%s", msg.subject().c_str(), msg.body().c_str());

		if (msg.subject()==request) {
			//c->send(Message(Message::Normal, , "ack"));
			//g_debug("sent ack");
			if (mode==SERVER) {
				fflush(stdout);
				xmppClient->disconnect();
				pid_t pid = fork();
				if (pid < 0) { g_error("Failed to fork."); }
				if (pid > 0) { 
					/* parent */
					g_debug("waiting for first fork");
					waitpid(pid, NULL, 0);
					
					int readed = read(pipefd[0], pipe_buffer, pipe_buffer_size);
					if (readed < 1 || pipe_buffer[readed] != 0) { g_error("something is wrong with candidates"); }
					g_debug("going to send candidates");
					otherJid = new JID(msg.from().full());
					pendingAnswer = true;
				}
				if (pid == 0) { // child
					isChildProcess = true;
					pid = fork(); // double fork to make orphan process
					if (pid < 0) { g_error("Failed to fork 2."); }
					if (pid > 0) { exit(0); } // orphan child process by exiting
					if (pid == 0) {
						gloop = g_main_loop_new(NULL, false);	
						agent = new Agent(this, msg.from());
						agent->parse_remote_data(1, msg.body());
						g_debug("starting gloop server");
						g_unix_signal_add (15, &slp, NULL);
						g_main_loop_run(gloop);
						g_error("how can this end");
					}
				}
			} else {
				pendingAnswer=false;
				agent->parse_remote_data(1, msg.body());
			}
		}
	}

	void requestICE(const JID & jid, const string & cands);

	int parse_remote_data(guint stream_id, guint component_id, string line_str);
};
const string Icer::request = "REQUEST ICE";

int hostname_to_ip(char * hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
         
    if ( (he = gethostbyname( hostname ) ) == NULL)
    {
        // get the host info
        g_error("gethostbyname");
    }
 
    addr_list = (struct in_addr **) he->h_addr_list;
     
    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
          
    g_error("gethostbyname");
    return 1;
}

void argFail(char * prog) {
	g_error("\nUsage: %s server <jid@example.com/resource> <password> <stun.example.com> <stun_port> <localport>\n"
				"       %s client <jid@example.com> <password> <stun.example.com> <stun_port> <server_jid@example.com/resource\n",
				prog, prog);
	exit(EXIT_FAILURE);
}

static char stun_host[100];

int main(int argc, char* argv[]) {
	g_debug("debuging");
	//nice_debug_enable (true);
	Mode mode;
	string password;
	
	gchar *stun_addr = NULL;
	guint stun_port = 3478;
	char* localport = (char*) "-1";
  
	if (argc != 7 && argc != 6)
		argFail(argv[0]);

	password = string(argv[3]);
 
	if (strcmp(argv[1], "server")==0 && argc == 7) {
		mode = SERVER;
		localport = argv[6];
	}
	else if (strcmp(argv[1], "client")==0 && argc == 7) {
		mode = CLIENT;
	}
	else {
		argFail(argv[0]);
	}
	
	JID myJid(argv[2]);
	if (myJid.username() == "" || myJid.server() == "" || mode == SERVER &&  myJid.resource() == "") {
		g_error("invalid jid %s (jid needs recource on server)", myJid.full().c_str());
	}
	JID * otherJid = NULL;
	if (mode == CLIENT) {
		otherJid = new JID(argv[6]);
		if (otherJid->username() == "" || otherJid->server() == "" || mode == SERVER &&  otherJid->resource() == "") {
			g_error("invalid remode jid %s", otherJid->full().c_str());
		}
	}
	
	hostname_to_ip(argv[4],stun_host);
	stun_addr = stun_host;
	stun_port = atoi(argv[5]);

	Client* client = new Client(myJid, password);
	Icer * icer = new Icer(client, otherJid,mode,stun_addr,stun_port, localport);

	
	if(mode == SERVER) {
		while (true) {
			client->connect(true);
		}
	}
	else {
		gloop = g_main_loop_new(NULL, false);
		client->connect(false);
		while(icer->connected == false) {
			client->recv(100000);
		}
		g_debug("starting gloop");
		g_main_loop_run(gloop);
	}

	g_main_loop_unref(gloop);
	return 0;
}

void Icer::requestICE(const JID & jid, const string & cands) {
	g_debug("requesting ice");
	Message m(Message::Normal, jid, cands, Icer::request);
	xmppClient->send(m);
	pendingAnswer=true;
	while(pendingAnswer && mode==CLIENT) {
		xmppClient->recv();
	}
}

static void read_func(GObject *obj, GAsyncResult *res, gpointer sstate_);
static void written_func(GObject *obj, GAsyncResult *res, gpointer sstate_);

static void read_func(GObject *obj, GAsyncResult *res, gpointer sstate_) {
	StreamState * sstate = (StreamState*) sstate_;
	sstate->read_bytes = g_input_stream_read_finish(sstate->in, res, &error);
	if (sstate->read_bytes < 0) { g_error("reading error: %s", error->message); }
	if (sstate->read_bytes == 0) { exit(0); }
	g_debug("received from %s: %d", sstate->inname, sstate->read_bytes);
	g_output_stream_write_async(sstate->out, sstate->buffer, sstate->read_bytes,
				G_PRIORITY_DEFAULT, NULL, &written_func, sstate_);
}

static void written_func(GObject *obj, GAsyncResult *res, gpointer sstate_) {
	StreamState * sstate = (StreamState *) sstate_;
	gssize wrtn = g_output_stream_write_finish(sstate->out, res, NULL);
	sstate->written_bytes += wrtn;
	g_debug("sent to %s: %d", sstate->outname, wrtn);
	if (wrtn < 0) { g_error("can't write to %sanymore", sstate->outname); }
	if (sstate->written_bytes < sstate->read_bytes) {
		g_output_stream_write_async(
				sstate->out,
				sstate->buffer + sstate->written_bytes,
				sstate->read_bytes - sstate->written_bytes,
				G_PRIORITY_DEFAULT, NULL, &written_func, sstate_);
	} else {
		sstate->written_bytes = 0;
		g_input_stream_read_async(sstate->in, sstate->buffer, buffer_size,
				G_PRIORITY_DEFAULT, NULL, &read_func, sstate_);
	}
}

Agent::~Agent() {	
	delete otherJid;

	g_object_unref(agent);
}

Agent::Agent(Icer * icer, const JID & otherJid) : parent(icer) {
	connCheckNum=0;
	negotiationComplete[NICE_COMPONENT_TYPE_RTP]=false;
	negotiationComplete[NICE_COMPONENT_TYPE_RTCP]=false;
	this->otherJid = new JID(otherJid.full());
	gboolean controlling = icer->mode == CLIENT ? true : false;
	g_debug("creating nice agent");
	agent = nice_agent_new_reliable(g_main_loop_get_context (gloop),
		NICE_COMPATIBILITY_RFC5245);
	if (agent == NULL)
		g_error("Failed to create agent");

	g_debug("setting stun server %s:%d", icer->stun_addr, icer->stun_port);
	g_object_set(G_OBJECT(agent), "stun-server", icer->stun_addr, NULL);
	g_object_set(G_OBJECT(agent), "stun-server-port", icer->stun_port, NULL);
	g_object_set(G_OBJECT(agent), "controlling-mode", controlling, NULL);
	
	g_object_set(G_OBJECT(agent), "ice-tcp", false, NULL);

	// Connect to the signals
	g_signal_connect(G_OBJECT(agent), "candidate-gathering-done",
		G_CALLBACK(Agent::gathering_done), this);
	g_signal_connect(G_OBJECT(agent), "new-selected-pair",
		G_CALLBACK(Agent::new_selected_pair), this);
	g_signal_connect(G_OBJECT(agent), "component-state-changed",
		G_CALLBACK(Agent::component_state_changed), this);

	// Create a new stream with one component
	stream_id = nice_agent_add_stream(agent, 2);
	nice_agent_set_stream_name (agent, stream_id, "xicecat");
	if (stream_id == 0)
		g_error("Failed to add stream");

	// Start gathering local candidates
	if (!nice_agent_gather_candidates(agent, stream_id))
		g_error("Failed to start candidate gathering");

	initTCP();

	gstream = nice_agent_get_io_stream(agent, stream_id, NICE_COMPONENT_TYPE_RTP);

	remoteToLocal.in = g_io_stream_get_input_stream(gstream);
	remoteToLocal.read_bytes = 0;
	remoteToLocal.written_bytes = 0;
	remoteToLocal.inname = (char*)"remote";
	remoteToLocal.outname = (char*)"local";

	localToRemote.out = g_io_stream_get_output_stream(gstream);
	localToRemote.read_bytes = 0;
	localToRemote.written_bytes = 0;
	localToRemote.inname = (char*)"local";
	localToRemote.outname = (char*)"remote";
	if (icer->mode == CLIENT) {
		remoteToLocal.out = g_unix_output_stream_new(fileno(stdout), true);
		localToRemote.in = g_unix_input_stream_new(fileno(stdin), TRUE);
	}
	
	g_input_stream_read_async(remoteToLocal.in, remoteToLocal.buffer, buffer_size,
			G_PRIORITY_DEFAULT, NULL, &read_func, (gpointer)&remoteToLocal);
	recvConnCheck();
}

/* START ConnCheck */
static void recvedConnCheck(GObject *obj, GAsyncResult *res, gpointer agent);

static gboolean recvConnCheck_(gpointer p) { return (guint)(((Agent *)p)->recvConnCheck()); }
gboolean Agent::recvConnCheck() {
	GIOStream* stream = nice_agent_get_io_stream(agent, stream_id, NICE_COMPONENT_TYPE_RTCP);
	unsigned char buffer;
	g_input_stream_read_async(
			g_io_stream_get_input_stream(stream),
			&buffer, 1,
			G_PRIORITY_DEFAULT, NULL,
			&recvedConnCheck, (gpointer)this);
	return false;
}

static void recvedConnCheck(GObject *obj, GAsyncResult *res, gpointer agent) {
	GInputStream* stream =  (GInputStream*) obj;
	gssize read_bytes = g_input_stream_read_finish(stream, res, &error);
	if (read_bytes <= 0) { g_error("concheck error: %s", error->message); }
	((Agent*)agent)->connCheckNum = 0;
	g_debug("read conncheck");
	recvConnCheck_(agent);
}

static gboolean sendConnCheck_(gpointer p) { return (guint)(((Agent *)p)->sendConnCheck()); }
gboolean Agent::sendConnCheck() {
	GIOStream* stream = nice_agent_get_io_stream(agent, stream_id, NICE_COMPONENT_TYPE_RTCP);
	unsigned char buffer = 0;
	g_output_stream_write_async(
			g_io_stream_get_output_stream(stream),
			&buffer, 1,
			G_PRIORITY_DEFAULT, NULL,
			NULL, (gpointer)this);
	
	connCheckNum += 1;
	if (connCheckNum>3) { g_error("connection failed"); }
	g_debug("sent conncheck: %d", connCheckNum);
	g_timeout_add(connCheckInterval,&sendConnCheck_, this);
	return false;
}

/* END ConnCheck */

void Agent::initTCP() {
	if (parent->mode == CLIENT ) { return; }
	g_debug("creating local TCP connection to localhost:%s",parent->localport);

	/* create a new connection */
	GSocketConnection * connection = NULL;
	GSocketClient * client = g_socket_client_new();

	/* connect to the host */
	connection = g_socket_client_connect_to_host (
		client,
		(gchar*)"localhost",
		atoi(parent->localport), /* your port goes here */
		NULL,
		&error);

	/* don't forget to check for errors */
	if (error != NULL)
	{
		g_error (error->message);
	}
	else
	{
		g_print ("Connection successful!\n");
	}
	localToRemote.in = g_io_stream_get_input_stream (G_IO_STREAM (connection));
	remoteToLocal.out = g_io_stream_get_output_stream (G_IO_STREAM (connection));
}

void Agent::gathering_done(NiceAgent *agent1, guint stream_id, gpointer data)
{
	Agent * agent = (Agent*) data;
	string candidates = string();
	g_debug("SIGNAL candidate gathering done");

	gchar* sdp = nice_agent_generate_local_sdp (agent->agent);
	g_debug("cands:\n%scands_done",sdp);
	
	if(strlen(sdp)+1 > Icer::pipe_buffer_size) { g_error("too many candidates"); }
	write(agent->parent->pipefd[1], sdp, strlen(sdp)+1);
	
	if(agent->parent->mode == CLIENT) {
		agent->parent->requestICE(*(agent->otherJid), string(sdp));
	}
	g_free(sdp);
}

void Agent::component_state_changed(NiceAgent *agent, guint stream_id,
    guint component_id, guint state,
    gpointer data)
{
	Agent* a = (Agent*) data;
	g_debug("SIGNAL: state changed stream=%d component=%d %s[%d]",
		stream_id, component_id, nice_component_state_to_string((NiceComponentState)state), state);

	if (state == NICE_COMPONENT_STATE_READY) {
		if(a->negotiationComplete[component_id] == true) {
			g_warning("two times complete");
			return;
		} else {
			a->negotiationComplete[component_id] = true;
		}
		if(component_id == NICE_COMPONENT_TYPE_RTP) {
			g_input_stream_read_async(a->localToRemote.in, a->localToRemote.buffer, buffer_size, 
				G_PRIORITY_DEFAULT, NULL, &read_func, (gpointer)&(a->localToRemote));
		} else if (component_id == NICE_COMPONENT_TYPE_RTCP) {
			a->sendConnCheck();
		}

		NiceCandidate *local, *remote;
		// Get current selected candidate pair and print IP address used
		if (nice_agent_get_selected_pair (agent, stream_id, component_id,
				&local, &remote)) {
			gchar ipaddr_local[INET6_ADDRSTRLEN];
			gchar ipaddr_remote[INET6_ADDRSTRLEN];

			nice_address_to_string(&local->addr, ipaddr_local);
			nice_address_to_string(&remote->addr, ipaddr_remote);
			g_debug("Negotiation complete: (%s://s[%s]:%d, %s://[%s]:%d)",
				candidate_transport_name[local->transport],
					ipaddr_local, nice_address_get_port(&local->addr),
				candidate_transport_name[remote->transport],
					ipaddr_remote, nice_address_get_port(&remote->addr));
		}

	} else if (state == NICE_COMPONENT_STATE_FAILED || state == NICE_COMPONENT_STATE_DISCONNECTED) {
		g_error("component failed. This could be a normal eof.");
		exit(0);
	}
}

void Agent::new_selected_pair(NiceAgent *agent, guint stream_id,
    guint component_id, gchar *lfoundation,
    gchar *rfoundation, gpointer data)
{
	//Agent * a = (Agent *) data;
	g_debug("SIGNAL: selected pair %s %s", lfoundation, rfoundation);
}

int Agent::parse_remote_data(guint component_id, string line_str)
{
	int res = nice_agent_parse_remote_sdp(agent, line_str.c_str());
	if (res <= 0) { g_error("no candidate added  (res=%d) cands:\n%scands_done",res,line_str.c_str()); }

	return 0;
}
