global connections = 0;
global sites: table[addr] of count &default=0;
event bro_init()
{
    print fmt("Starting...");
}

event connection_established(c: connection)
{
    local host = c$id$resp_h;
    ++connections;
    ++sites[c$id$resp_h];
    print fmt("Saw a new connection to %s:%d (%d so far)", host, c$id$resp_p, sites[host]);
}

event bro_done()
{
    print "";
    print fmt("There were %d connections", connections);
    print fmt("There were %d unique sites", |sites|);
    for(site in sites){
        print fmt("%s had %d connections", site, sites[site]);
    }
}
