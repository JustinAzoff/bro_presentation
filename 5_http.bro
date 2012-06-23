global uas: set[string];
global mime_types: table[string] of count &default=0;
global countries: table[string] of count&default=0;

event HTTP::log_http(rec: HTTP::Info)
{
    print fmt("%s requested %s%s (%s)", rec$id$orig_h, rec$host, rec$uri, rec$mime_type);
    if (rec$user_agent !in uas){
        print fmt("A New user-agent was seen:%s", rec$user_agent);
        add uas[rec$user_agent];
    }

    #count mime types
    mime_types[rec$mime_type] += rec$response_body_len;

    #count countries
    local loc = lookup_location(rec$id$resp_h);
    if(loc?$country_code){
        ++countries[loc$country_code];
    }
}

event bro_done()
{
    print "";
    print fmt("%d user-agents were seen:", |uas|);
    for(agent in uas){
        print agent;
    }

    print "";
    print fmt("%d mime-types were seen:", |mime_types|);
    for(mt in mime_types){
        print fmt("%s - %d bytes", mt, mime_types[mt]);
    }

    print "";
    print fmt("%d countries were talked to:", |countries|);
    for (c in countries){
        print fmt("%s - %d connections", c, countries[c]);
    }
}
