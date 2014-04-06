sf
==

libev sockets framework



just something i put together to replace ZeroMQ, i was getting major perormance loss with the libwebsockets when combined with ZeroMQ.

Warning this is still in its early stage, im actively using this in a project so il be updating this often. I leave it out there for anyone to improve upon it.


Features
- Client/Connection handling
- Intergrated Heartbeat
- Multipart Msg based asynchronous communication
- Validation callback
- Supports server <-> many clients, client <-> many servers
- Intance can be initialized as server or client, can be both client and server if initialized as server, meaning you can accept and do connect



Check the test.c for how to use.


