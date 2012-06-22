global connections = 0;
event bro_init()
{
    print fmt("Starting...");
}

event connection_established(c: connection)
{
    print fmt("Saw a new connection to %s:%d", c$id$resp_h, c$id$resp_p);
    ++connections;
}

event bro_done()
{
    print fmt("There were %d connections", connections);
}
