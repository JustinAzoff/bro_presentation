global uas: set[string];
event HTTP::log_http(rec: HTTP::Info)
{
    print fmt("%s requested %s%s", rec$id$orig_h, rec$host, rec$uri);
    if (rec$user_agent !in uas){
        print fmt("A New user-agent was seen:%s", rec$user_agent);
        add uas[rec$user_agent];
    }
}

event bro_done()
{
    print "";
    print fmt("%d user-agents were seen", |uas|);
}
