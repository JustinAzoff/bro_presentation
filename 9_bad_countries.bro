@load base/frameworks/notice

export {
    redef enum Notice::Type += { 
        Too_Many_Countries
    };

    const country_threshold = 3 &redef;
    type country_set: set[string] &create_expire=1hr;
    global host_countries: table[addr] of country_set &create_expire=1hr;
}


event new_connection(c: connection)
{
    local from = c$id$orig_h;
    local to = c$id$resp_h;

    local loc = lookup_location(to);

    if(loc?$country_code){
        if(from !in host_countries){
            local s: country_set;
            host_countries[from] = s;
        } else {
            s = host_countries[from];
        }
        add s[loc$country_code];
        if(|s| >= country_threshold){
            NOTICE([$note=Too_Many_Countries,
                $msg=fmt("%s has connected to too many countries", from),
                $identifier=fmt("%s", from),
                $remote_location=loc,
                $suppress_for=1day,
                $conn=c]);
        }
    }
}
