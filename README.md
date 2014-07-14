# xicecat


XMPP ICE cat (xicecat) - connects two computers behind NAT/firewall using libnice and gloox

The idea is to get ssh between two computers behind firewalls. But it could be applied for any other tcp based protocoll too.

## Install

Unfortunately xicecat requires > libnice-0.1.5 which is not in the ubuntu/debian repos so for now you will have to compile that yourself.

	sudo apt-get install build-essential libgloox-dev libnice-dev libglib2.0-dev
	g++ -o xicecat xicecat.cpp `pkg-config gloox nice gio-unix-2.0 --cflags --libs`

alternatively if you have a redo program

	redo xicecat

If libnice is installed in your home. Use "PKG_CONFIG_PATH=/path/lib/pkgconfig" and "-Wl,-rpath /path/to/lib/folder/".

## Use

Make a new xmpp account. Your xmpp password will be on ps and in future versions you might even get messages.

xicecat currently does *not work with google a google account* because google changes the resource name.

    Usage:./xicecat server <jid@example.com/resource> <password> <stun.example.com> <stun_port> <localport>
           ./xicecat client <jid@example.com> <password> <stun.example.com> <stun_port> <server_jid@example.com/resource

As resource fill in your hostname. In the server case this will connect to the port specified by localport. On the client side the input/output will be taken from stdin/stout.

To use it with ssh run the command on the server and put the following in your ssh config file

    Host myhostname
        ProxyCommand /path/to/xicecat client myusername@xmpp.example.com mypassword stun.example.com 3478 myusername@xmpp.example.com/myhostname

## Problems

### Big Problems

* Your xmpp password will be on ps so it is adviced that you create a seperate account for this.

### Minor Problems

* libnice can't flush this is a problem when you want to terminate a client. I think if used for ssh, ssh takes care of that

* libnice can't do onesided connection termination ...
