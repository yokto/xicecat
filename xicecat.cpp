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
	bool negotiationComplete;

	StreamState remoteToLocal;
	StreamState localToRemote;

	GIOStream * gstream;
	
	GMainLoop *gloop = NULL;

	int sock;

	const static int component = 1;	
	NiceAgent * agent;
	guint stream_id;
	Icer * parent;
	JID * otherJid;
	Agent(Icer * icer, const JID & otherJid);
	~Agent();
	int parse_remote_data(guint component_id, string line_str);
	void initTCP();
	static gboolean closeTimeout(void* stream);
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
	Client* c;
	Mode mode;
	static const string request;
	Agent* agent;
	gchar* stun_addr;
	guint stun_port;
	char* localport;

	const static int pipe_buffer_size = 65536;
	unsigned char* pipe_buffer;
	int pipefd[2];
	bool pendingAnswer;
	bool isChildProcess;

	Icer(Client *c, JID * otherJid, Mode mode, gchar* stun_addr, guint stun_port, char * localport)
		: c(c), otherJid(otherJid), mode(mode), stun_addr(stun_addr), stun_port(stun_port), localport(localport)
	{
		c->registerConnectionListener(this);
		c->registerMessageHandler(this);
		
		pendingAnswer = false;
		isChildProcess = false;
		
		if(pipe(pipefd) != 0) { g_error("no pipe"); }
		pipe_buffer = (unsigned char*) malloc(pipe_buffer_size);
		if (pipe_buffer == NULL) { g_error("can't allocate pipe buffer"); }
// 		if (mode == SERVER) {
// 			c->disco()->addFeature("https://github.com/yokto/xicecat/1/" + otherJid->resource());
// 			c->disco()->setIdentity("client", "xicecat");
// 		}
	}
	void onConnect() {
		g_message("connected yes with jid: %s", c->jid().full().c_str());
		if (mode == CLIENT) {
			c->send(Message(Message::Normal, *otherJid, "hi"));
			agent = new Agent(this, *otherJid);
		}
		if (mode == SERVER && pendingAnswer == true) {
			requestICE(*otherJid,string((char*)pipe_buffer));
			pendingAnswer = false;
		}
	}
	bool onTLSConnect(const CertInfo& cert) {
		g_message("ignoring tls certificate (we don't care)");
		return true;
	}
	void onDisconnect(ConnectionError e) {
		g_warning("stream error: %d", c->streamError());
		g_warning("stream error text: %s", c->streamErrorText().c_str());
	}
	void handleMessage (const Message &msg, MessageSession *session=0) {
		g_message("XMPP Message: %s\n\t%s", msg.subject().c_str(), msg.body().c_str());

		if (msg.subject()==request) {
			if (mode==SERVER) {
				fflush(stdout);
				c->disconnect();
				pid_t pid = fork();
				if (pid < 0) { g_error("Failed to fork."); }
				if (pid > 0) { 
					/* parent */
					g_message("waiting for first fork");
					waitpid(pid, NULL, 0);
					
					int readed = read(pipefd[0], pipe_buffer, pipe_buffer_size);
					if (readed < 1 || pipe_buffer[readed] != 0) { g_error("something is wrong with candidates"); }
					g_message("going to send candidates");
					otherJid = new JID(msg.from().full());
					pendingAnswer = true;
				}
				if (pid == 0) { // child
					isChildProcess = true;
					pid = fork(); // double fork to make orphan process
					if (pid < 0) { g_error("Failed to fork 2."); }
					if (pid > 0) { exit(0); } // orphan child process by exiting
					if (pid == 0) {
						agent = new Agent(this, msg.from());
						agent->parse_remote_data(1, msg.body());
						g_message("starting gloop server");
						g_unix_signal_add (15, &slp, NULL);
						//g_timeout_add(5000, &Agent::closeTimeout, (void*) agent->gstream);
						g_main_loop_run(agent->gloop);
						g_error("how can this end");
					}
				}
			} else {
				agent->parse_remote_data(1, msg.body());
				g_message("starting gloop client");
				g_main_loop_run(agent->gloop);
			}
		}
	}

	void requestICE(const JID & jid, const string & cands);

	int parse_remote_data(guint stream_id, guint component_id, string line_str);
};
const string Icer::request = "REQUEST ICE";

void argFail(char * prog) {
	g_error("\nUsage: %s server <jid@example.com/resource> <password> <stun.example.com> <stun_port> <localport>\n"
				"       %s client <jid@example.com> <password> <stun.example.com> <stun_port> <server_jid@example.com/resource\n",
				prog, prog);
	exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
	g_message("debuging");
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
	
	
	stun_addr = argv[4];
	stun_port = atoi(argv[5]);

	Client* client = new Client(myJid, password);
	Icer * icer = new Icer(client, otherJid,mode,stun_addr,stun_port, localport);
	while (true) {
		client->connect(true);
	}

	return 0;
}

void Icer::requestICE(const JID & jid, const string & cands) {
	Message m(Message::Normal, jid, cands, Icer::request);
	c->send(m);
}

static void read_func(GObject *obj, GAsyncResult *res, gpointer sstate_);
static void written_func(GObject *obj, GAsyncResult *res, gpointer sstate_);

static void read_func(GObject *obj, GAsyncResult *res, gpointer sstate_) {
	StreamState * sstate = (StreamState*) sstate_;
	sstate->read_bytes = g_input_stream_read_finish(sstate->in, res, &error);
	if (sstate->read_bytes < 0) { g_error("reading error: %s", error->message); }
	if (sstate->read_bytes == 0) { exit(0); }
	g_message("received from %s: %d", sstate->inname, sstate->read_bytes);
	g_output_stream_write_async(sstate->out, sstate->buffer, sstate->read_bytes,
				G_PRIORITY_DEFAULT, NULL, &written_func, sstate_);
}

static void written_func(GObject *obj, GAsyncResult *res, gpointer sstate_) {
	StreamState * sstate = (StreamState *) sstate_;
	gssize wrtn = g_output_stream_write_finish(sstate->out, res, NULL);
	sstate->written_bytes += wrtn;
	g_message("sent to %s: %d", sstate->outname, wrtn);
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

bool timeoutCheck(Agent* out) {
	g_message("restart");
	nice_agent_restart_stream(out->agent, out->stream_id);
	return true;
}


Agent::~Agent() {	
	delete otherJid;

	if (parent->mode=SERVER) { close(sock); }
	
	g_object_unref(agent);
	g_main_loop_unref(gloop);
}

Agent::Agent(Icer * icer, const JID & otherJid) : parent(icer) {
	negotiationComplete=false;
	gloop = g_main_loop_new(NULL, false);	
	this->otherJid = new JID(otherJid.full());
	gboolean controlling = icer->mode == CLIENT ? true : false;
	g_message("creating nice agent");
	agent = nice_agent_new_reliable(g_main_loop_get_context (gloop),
		NICE_COMPATIBILITY_RFC5245);
	if (agent == NULL)
		g_error("Failed to create agent");

	g_object_set(G_OBJECT(agent), "stun-server", icer->stun_addr, NULL);
	g_object_set(G_OBJECT(agent), "stun-server-port", icer->stun_port, NULL);
	g_object_set(G_OBJECT(agent), "controlling-mode", controlling, NULL);

	// Connect to the signals
	g_signal_connect(G_OBJECT(agent), "candidate-gathering-done",
		G_CALLBACK(Agent::gathering_done), this);
	g_signal_connect(G_OBJECT(agent), "new-selected-pair",
		G_CALLBACK(Agent::new_selected_pair), this);
	g_signal_connect(G_OBJECT(agent), "component-state-changed",
		G_CALLBACK(Agent::component_state_changed), this);

	// Create a new stream with one component
	stream_id = nice_agent_add_stream(agent, 1);
	if (stream_id == 0)
		g_error("Failed to add stream");



	// Start gathering local candidates
	if (!nice_agent_gather_candidates(agent, stream_id))
		g_error("Failed to start candidate gathering");

	g_message("waiting for candidate-gathering-done signal...");

	initTCP();

	gstream = nice_agent_get_io_stream(agent, stream_id, component);

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
}

gboolean Agent::closeTimeout(void* stream) {
	if (g_io_stream_is_closed((GIOStream *) stream))
		{ g_error("stream is closed exiting"); }
	else
		{ g_message("stream is still open"); }
	return G_SOURCE_CONTINUE;
}

void Agent::initTCP() {
	if (parent->mode == CLIENT ) { return; }
	g_message("creating local TCP connection to localhost:%s",parent->localport);

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
	g_message("SIGNAL candidate gathering done");

	// Candidate gathering is done. Send our local candidates on stdout
	agent->print_local_data(stream_id, 1, candidates);
	g_message("Candidates are:\n\t%s", candidates.c_str());

	if(strlen(candidates.c_str())+1 > Icer::pipe_buffer_size) { g_error("too many candidates"); }
	write(agent->parent->pipefd[1], candidates.c_str(), strlen(candidates.c_str())+1);

	agent->parent->requestICE(*(agent->otherJid), candidates);
}

void Agent::component_state_changed(NiceAgent *agent, guint stream_id,
    guint component_id, guint state,
    gpointer data)
{
	Agent* a = (Agent*) data;
	g_message("SIGNAL: state changed stream=%d component=%d %s[%d]",
		stream_id, component_id, nice_component_state_to_string((NiceComponentState)state), state);

	if (state == NICE_COMPONENT_STATE_READY) {
		if(a->negotiationComplete) {
			g_warning("two times complete");
			return;
		} else {
			a->negotiationComplete = TRUE;
		}
		g_input_stream_read_async(a->localToRemote.in, a->localToRemote.buffer, buffer_size, 
				G_PRIORITY_DEFAULT, NULL, &read_func, (gpointer)&(a->localToRemote));
		//g_timeout_add(5000, (int (*)(void*))&timeoutCheck, (gpointer) a);

		NiceCandidate *local, *remote;
		// Get current selected candidate pair and print IP address used
		if (nice_agent_get_selected_pair (agent, stream_id, component_id,
				&local, &remote)) {
			gchar ipaddr_local[INET6_ADDRSTRLEN];
			gchar ipaddr_remote[INET6_ADDRSTRLEN];

			nice_address_to_string(&local->addr, ipaddr_local);
			nice_address_to_string(&remote->addr, ipaddr_remote);
			g_message("Negotiation complete: (%s://s[%s]:%d, %s://[%s]:%d)",
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
	g_message("SIGNAL: selected pair %s %s", lfoundation, rfoundation);
}

static NiceCandidate *
parse_candidate(char *scand, guint stream_id)
{
	NiceCandidate *cand = NULL;
	NiceCandidateType ntype;
	NiceCandidateTransport ntransport;
	gchar **tokens = NULL;
	guint i;

	tokens = g_strsplit (scand, ",", 7);
	for (i = 0; tokens && tokens[i]; i++);
	if (i != 7)
		{ goto end; }
		
	for (i = 0; i < G_N_ELEMENTS (candidate_type_name); i++) {
		if (strcmp(tokens[5], candidate_type_name[i]) == 0) {
			ntype = (NiceCandidateType) i;
			break;
		}
	}
	if (i == G_N_ELEMENTS (candidate_type_name))
		{ goto end; }
	for (i = 0; i < G_N_ELEMENTS(candidate_transport_name); i++){
		if (strcmp(tokens[6], candidate_transport_name[i]) == 0) {
			ntransport = (NiceCandidateTransport) i;
			break;
		}
	}
	if (i == G_N_ELEMENTS (candidate_transport_name))
		{ goto end; }

	cand = nice_candidate_new(ntype);
	cand->component_id = 1;
	cand->stream_id = stream_id;
	cand->transport = ntransport;
	strncpy(cand->foundation, tokens[0], NICE_CANDIDATE_MAX_FOUNDATION);
	cand->priority = atoi (tokens[1]);

	if (!nice_address_set_from_string(&cand->addr, tokens[2])
			|| !nice_address_set_from_string(&cand->base_addr, tokens[3])) {
		g_message("failed to parse addr: %s", tokens[2]);
		nice_candidate_free(cand);
		cand = NULL;
		goto end;
	}

	nice_address_set_port(&cand->addr, atoi (tokens[4]));

end:
	g_strfreev(tokens);

	return cand;
}

int Agent::print_local_data (guint stream_id, guint component_id, string & candidates)
{
	int result = EXIT_FAILURE;
	gchar *local_ufrag = NULL;
	gchar *local_password = NULL;
	gchar ipaddr[INET6_ADDRSTRLEN];
	gchar ipaddr_base[INET6_ADDRSTRLEN];
	GSList *cands = NULL, *item;
	
	stringstream stream;

	if (!nice_agent_get_local_credentials(agent, stream_id,
			&local_ufrag, &local_password))
		goto end;

	cands = nice_agent_get_local_candidates(agent, stream_id, component_id);
	if (cands == NULL)
		goto end;

	stream << local_ufrag << " " << local_password;

	for (item = cands; item; item = item->next) {
		NiceCandidate *c = (NiceCandidate *)item->data;

		nice_address_to_string(&c->addr, ipaddr);
		nice_address_to_string(&c->base_addr, ipaddr_base);

		
		//if (c->transport != NICE_CANDIDATE_TRANSPORT_UDP) {
		//if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
		if(ipaddr[4]!=':' && c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
			stream
				<< " "
				<< c->foundation << ","
				<< c->priority << ","
				<< ipaddr << ","
				<< ipaddr_base << ","
				<< nice_address_get_port(&c->addr) << ","
				<< candidate_type_name[c->type] << ","
				<< candidate_transport_name[c->transport];
		} else {
			//printf("not candidate: %s,%d,%d \n\n\n\n\n:", candidate_transport_name[c->transport], c->transport,NICE_CANDIDATE_TRANSPORT_UDP);
		}
	}
	result = EXIT_SUCCESS;

	candidates = stream.str();

	end:
	if (local_ufrag)
		g_free(local_ufrag);
	if (local_password)
		g_free(local_password);
	if (cands)
		g_slist_free_full(cands, (GDestroyNotify)&nice_candidate_free);

	return result;
}


int Agent::parse_remote_data(guint component_id, string line_str)
{
  GSList *remote_candidates = NULL;
  gchar **line_argv = NULL;
  const gchar *ufrag = NULL;
  const gchar *passwd = NULL;
  int result = EXIT_FAILURE;
  int i;
  
  const char* line = line_str.c_str();

  line_argv = g_strsplit_set (line, " \t\n", 0);
  for (i = 0; line_argv && line_argv[i]; i++) {
    if (strlen (line_argv[i]) == 0)
      continue;

    // first two args are remote ufrag and password
    if (!ufrag) {
      ufrag = line_argv[i];
    } else if (!passwd) {
      passwd = line_argv[i];
    } else {
      // Remaining args are serialized canidates (at least one is required)
      NiceCandidate *c = parse_candidate(line_argv[i], stream_id);

      if (c == NULL) {
        g_message("failed to parse candidate: %s", line_argv[i]);
        goto end;
      }
      remote_candidates = g_slist_prepend(remote_candidates, c);
    }
  }
  if (ufrag == NULL || passwd == NULL || remote_candidates == NULL) {
    g_message("line must have at least ufrag, password, and one candidate");
    goto end;
  }

  if (!nice_agent_set_remote_credentials(agent, stream_id, ufrag, passwd)) {
    g_message("failed to set remote credentials");
    goto end;
  }

  // Note: this will trigger the start of negotiation.
  if (nice_agent_set_remote_candidates(agent, stream_id, component_id,
      remote_candidates) < 1) {
    g_message("failed to set remote candidates");
    goto end;
  }

  result = EXIT_SUCCESS;

 end:
  if (line_argv != NULL)
    g_strfreev(line_argv);
  if (remote_candidates != NULL)
    g_slist_free_full(remote_candidates, (GDestroyNotify)&nice_candidate_free);

  return result;
}
