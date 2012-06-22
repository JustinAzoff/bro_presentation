global name = "STC";
event bro_init()
{
    print fmt("Hello %s", name);
}

event bro_done()
{
    print fmt("Goodbye %s", name);
}
