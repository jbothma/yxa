-module(siprequest).
-export([send_redirect/4, process_register_isauth/3,
	 send_auth_req/4, send_proxyauth_req/4,
	 send_proxy_request/3, location_prio/1,
	 send_notavail/2, send_notfound/2, send_proxy_response/5]).

send_response(Socket, Code, Text, Header, Body) ->
    Via = sipheader:via(keylist:fetch("Via", Header)),
    [Dest | _] = Via,
    logger:log(debug, "send to ~p", [Dest]),
    send_response_to(Socket, Code, Text, Dest, Header, Body).

send_response_to(Socket, Code, Text, Dest, Header, Body) ->
    Line1 = "SIP/2.0 " ++ integer_to_list(Code) ++ " " ++ Text,
    Printheader = fun({Name, Value}) ->
			  Name ++ ": " ++ siputil:printvalue(Value)
		  end,
    HLines = lists:map(Printheader, Header),
    Message = siputil:concat_strings([Line1 | HLines]) ++ "\r\n" ++ Body,
    logger:log(debug, "send response(~p):~p", [Dest, Message]),
    {Protocol, {Host, Port}} = Dest,
    ok = gen_udp:send(Socket, Host, list_to_integer(Port), Message).

url_to_hostport({User, Pass, InHost, InPort, Parameters}) ->
    case dnsutil:siplookup(InHost) of
	{Host, Port} ->
	    {Host, integer_to_list(Port)};
	none ->
	    {InHost, InPort}
    end.

send_proxy_request(Header, Socket, {Action, Dest, Body}) ->
    Line1 = Action ++ " " ++ sipurl:print(Dest) ++ " SIP/2.0",
    Printheader = fun({Name, Value}) ->
			  Name ++ ": " ++ siputil:printvalue(Value)
		  end,
    [Viaadd] = sipheader:via_print([{"SIP/2.0/UDP",
				     {siphost:myip(), "5060"}}]),
    Keylist2 = keylist:prepend({"Via", Viaadd}, Header),
    HLines = lists:map(Printheader, Keylist2),
    Message = siputil:concat_strings([Line1 | HLines]) ++ "\r\n" ++ Body,
    {Host, Port} = url_to_hostport(Dest),
    logger:log(debug, "send request(~p,~p:~p):~p", [Dest, Host, Port, Message]),
    ok = gen_udp:send(Socket, Host, list_to_integer(Port), Message).

process_register_isauth(Header, Socket, {Phone, Location}) ->
    logger:log(normal, "REGISTER phone ~p at ~p", [Phone, Location]),
    Expire = 
	case keylist:fetch("Expires", Header) of	
	    [E] ->
		E;
	    [] ->
		"3600"
	end,

    phone:insert_purge_phone(Phone, [{priority, 100}],
			     dynamic,
			     list_to_integer(Expire) + util:timestamp(),
			     Location),
    send_response(Socket, 200, "OK",
		  [{"via", keylist:fetch("Via", Header)},
		   {"From", keylist:fetch("From", Header)},
		   {"To", keylist:fetch("To", Header)},
		   {"Call-ID", keylist:fetch("Call-ID", Header)},
		   {"CSeq", keylist:fetch("CSeq", Header)},
		   {"Expires", [Expire]}], "").

send_auth_req(Header, Socket, Auth, Stale) ->
    send_response(Socket, 401, "Authentication Required",
		  [{"via", keylist:fetch("Via", Header)},
		   {"From", keylist:fetch("From", Header)},
		   {"To", keylist:fetch("To", Header)},
		   {"Call-ID", keylist:fetch("Call-ID", Header)},
		   {"CSeq", keylist:fetch("CSeq", Header)},
		   {"WWW-Authenticate", sipheader:auth_print(Auth, Stale)}], "").

send_proxyauth_req(Header, Socket, Auth, Stale) ->
    send_response(Socket, 407, "Proxy Authentication Required",
		  [{"via", keylist:fetch("Via", Header)},
		   {"From", keylist:fetch("From", Header)},
		   {"To", keylist:fetch("To", Header)},
		   {"Call-ID", keylist:fetch("Call-ID", Header)},
		   {"CSeq", keylist:fetch("CSeq", Header)},
		   {"Proxy-Authenticate", sipheader:auth_print(Auth, Stale)}], "").

send_redirect(Phone, Location, Header, Socket) ->
    Contact = [{none, Location}],
    send_response(Socket, 302, "Moved Temporarily",
		  [{"via", keylist:fetch("Via", Header)},
		   {"From", keylist:fetch("From", Header)},
		   {"To", keylist:fetch("To", Header)},
		   {"Call-ID", keylist:fetch("Call-ID", Header)},
		   {"CSeq", keylist:fetch("CSeq", Header)},
		   {"Contact", sipheader:contact_print(Contact)}], "").

send_notfound(Header, Socket) ->
    send_response(Socket, 404, "Not found",
		  [{"via", keylist:fetch("Via", Header)},
		   {"From", keylist:fetch("From", Header)},
		   {"To", keylist:fetch("To", Header)},
		   {"Call-ID", keylist:fetch("Call-ID", Header)},
		   {"CSeq", keylist:fetch("CSeq", Header)}], "").

send_notavail(Header, Socket) ->
    send_response(Socket, 480, "Temporarily unavailable",
		  [{"via", keylist:fetch("Via", Header)},
		   {"From", keylist:fetch("From", Header)},
		   {"To", keylist:fetch("To", Header)},
		   {"Call-ID", keylist:fetch("Call-ID", Header)},
		   {"CSeq", keylist:fetch("CSeq", Header)},
		   {"Retry-After", ["180"]}], "").


location_prio([]) ->
    {none, [], none, never};
location_prio([Address]) ->
    Address;
location_prio([Address | Rest]) ->
    Address2 = location_prio(Rest),
    {Location1, Flags1, Class1, Expire1} = Address,
    {Location2, Flags2, Class2, Expire2} = Address2,
    Prio1 = lists:keysearch(priority, 1, Flags1),
    Prio2 = lists:keysearch(priority, 1, Flags2),
    case {Prio1, Prio2} of
	{_, false} ->
	    Address;
	{false, _} ->
	    Address2;
	{{priority,P1},{priority,P2}} when P1 >= P2 ->
	    Address;
	_ ->
	    Address2
    end.

send_proxy_response(Socket, Status, Reason, Header, Body) ->
    [Self | Via] = sipheader:via(keylist:fetch("Via", Header)),
    Keylist = keylist:set("Via", sipheader:via_print(Via),
			  Header),
    send_response(Socket, Status, Reason,
		  Keylist, Body).
