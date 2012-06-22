global connections = 0;
global sites: set[addr];
event bro_init()
{
    print fmt("Starting...");
}

event connection_established(c: connection)
{
    print fmt("Saw a new connection to %s:%d", c$id$resp_h, c$id$resp_p);
    ++connections;
    add sites[c$id$resp_h];
}

event bro_done()
{
    print "";
    print fmt("There were %d connections", connections);
    print fmt("There were %d unique sites", |sites|);
}
