%%%-------------------------------------------------------------------
%%% File    : lookup.erl
%%% @author   Magnus Ahltorp <ahltorp@nada.kth.se>
%%% @doc      Varios lookup functions. Mainly routing logic for our
%%%           three applications incomingproxy, pstnproxy and
%%%           appserver. Most of these functions are called through
%%%           functions in local.erl with the same name, so if you
%%%           want to make them return different values than the
%%%           defaults in this file, make a local.erl specific for
%%%           your domain.
%%%
%%% @since    20 Mar 2003 by Magnus Ahltorp <ahltorp@nada.kth.se>
%%% @end
%%%-------------------------------------------------------------------
-module(lookup).
%%-compile(export_all).

%%--------------------------------------------------------------------
%% External exports
%%--------------------------------------------------------------------
-export([
	 lookupuser_gruu/2,
	 lookupdefault/1,
	 is_request_to_this_proxy/1,
	 homedomain/1,
	 lookup_result_to_str/1,
	 test/0
	]).

%%--------------------------------------------------------------------
%% Include files
%%--------------------------------------------------------------------

-include("siprecords.hrl").
-include("sipsocket.hrl").


%%====================================================================
%% External functions
%%====================================================================


%%--------------------------------------------------------------------
%% @spec    (URL) ->
%%            {ok, Users, Res} | nomatch
%%
%%            URL = #sipurl{}
%%
%%            Users  = [string()] | none "usernames matching URL"
%%            Res    = {proxy, URL}                    |
%%                     {proxy, {with_path, URL, Path}} |
%%                     {relay, URL}                    |
%%                     {forward, URL}                  |
%%                     {response, Status, Reason}      |
%%                     none
%%            URL    = #sipurl{}
%%            Path   = [string()]
%%            Status = integer() "SIP status code"
%%            Reason = string() "SIP reason phrase"
%%
%% @doc     The main 'give me a set of locations for one of our users'
%%          function that incomingproxy uses, when it determines that
%%          a request is for one of it's homedomains. Returns
%%          'nomatch' if no user was found, 'none' if the user(s)
%%          associated with URL has no registered locations.
%% @end
%%--------------------------------------------------------------------
lookupuser(URL) when is_record(URL, sipurl) ->
    case local:is_gruu_url(URL) of
	{true, GRUU} ->
	    %% format lookupuser_gruu for incomingproxy, which is the one calling this function
	    case local:lookupuser_gruu(URL, GRUU) of
		{ok, User, Loc, _Contact} when is_list(User), is_tuple(Loc) ->
		    {ok, [User], Loc};
		{ok, User, Loc} ->
		    {ok, [User], Loc}
	    end;
	false ->
	    lookupuser2(URL)
    end.

lookupuser2(URL) ->
    case local:get_users_for_url(URL) of
	nomatch ->
	    NoParamURL = sipurl:set([{param, []}], URL),
	    case local:lookupregexproute(sipurl:print(NoParamURL)) of
		none ->
		    logger:log(debug, "Lookup: No user matches URL ~p, and no regexp rules match either.",
			       [sipurl:print(NoParamURL)]),
		    nomatch;
		{proxy, Loc} ->
		    logger:log(debug, "Lookup: No matching user, but a matching regexp rule was found : ~p -> ~p",
			       [sipurl:print(NoParamURL), sipurl:print(Loc)]),
		    {ok, [], {proxy, Loc}}
	    end;
	[User] when is_list(User) ->
	    %% single user, look if the user has a CPL script
	    Res =
		case local:user_has_cpl_script(User, incoming) of
		    true ->
			%% let appserver handle requests for users with CPL scripts
			case local:lookupappserver(URL) of
			    {forward, AppS} ->
				logger:log(debug, "Lookup: User ~p has a CPL script, forwarding to appserver : ~p",
					   [User, sipurl:print(AppS)]),
				{forward, AppS};
			    {response, Status, Reason} ->
				logger:log(debug, "Lookup: User ~p has a CPL script, but appserver lookup resulted in "
					   "request to send SIP response '~p ~s'",
					   [User, Status, Reason]),
				{response, Status, Reason};
			    _ ->
				logger:log(error, "Lookup: User ~p has a CPL script, but I could not find an appserver",
					   [User]),
				%% Fallback to just looking in the location database
				lookupuser_get_locations([User], URL)
			end;
		    false ->
			lookupuser_get_locations([User], URL)
		end,
	    {ok, [User], Res};
	Users when is_list(Users) ->
	    %% multiple (or no) users
	    Res = lookupuser_get_locations(Users, URL),
	    {ok, Users, Res}
    end.

%% part of lookupuser()
lookupuser_get_locations(Users, URL) ->
    %% check if more than one location exists for our list of users.
    case local:lookupuser_locations(Users, URL) of
	[] ->
	    %% User exists but has no currently known locations
	    NoParamURL = sipurl:set([{param, []}], URL),
	    case local:lookupregexproute(sipurl:print(NoParamURL)) of
		none ->
		    logger:log(debug, "Lookup: No locations found for users ~p, and no regexp rules match URL ~p.",
			       [Users, sipurl:print(NoParamURL)]),
		    none;
		{proxy, Loc} ->
		    logger:log(debug, "Lookup: Regexp-route rewrite of ~p -> ~p",
			       [sipurl:print(NoParamURL), sipurl:print(Loc)]),
		    {proxy, Loc}
	    end;
	[Location] when is_record(Location, siplocationdb_e) ->
	    lookupuser_single_location(Location, URL);
	[Location | _] = Locations when is_record(Location, siplocationdb_e) ->
	    lookupuser_multiple_locations(Locations, URL)
    end.

%% Returns: {proxy, DstList}                |
%%          {proxy, {with_path, URL, Path}} |
%%          {proxy, URL}                    |
%%          {response, Status, Reason}
lookupuser_single_location(Location, URL) when is_record(Location, siplocationdb_e) ->
    %% A single location was found in the location database (after removing any unsuitable ones)
    ThisNode = node(),
    Dst =
	case lists:keysearch(socket_id, 1, Location#siplocationdb_e.flags) of
	    {value, {socket_id, #locationdb_socketid{node = ThisNode} = SocketId}} ->
		%% We have a stored socket_id, meaning the client did Outbound. We must now
		%% check if that socket is still available.
		case sipsocket:get_specific_socket(SocketId#locationdb_socketid.id) of
		    {error, _Reason} ->
			%% The socket the user registered using is no longer available - reject
			%% request with a '430 Flow Failed' response (draft-Outbound #5.3 (Forwarding Requests))
			%% "For connection-oriented transports, if the flow no longer exists the
			%% proxy SHOULD send a 430 (Flow Failed) response to the request."
			{response, 430, "Flow Failed"};
		    SipSocket ->
			[#sipdst{proto		= SocketId#locationdb_socketid.proto,
				 addr		= SocketId#locationdb_socketid.addr,
				 port		= SocketId#locationdb_socketid.port,
				 uri		= siplocation:to_url(Location),
				 socket		= SipSocket,
				 instance	= Location#siplocationdb_e.instance
				}
			]
		end;
	    {value, {socket_id, #locationdb_socketid{node = OtherNode}}} ->
		logger:log(debug, "Lookup: User has Outbound flow to other node (~p)", [OtherNode]),
		none;
	    false ->
		none
	end,

    case Dst of
	{response, _Status2, _Reason2} ->
	    Dst;
	_ when is_list(Dst) ->
	    {proxy, Dst};
	none ->
	    %% No Outbound socket for this node to use, look for RFC3327 Path
	    case lists:keysearch(path, 1, Location#siplocationdb_e.flags) of
		{value, {path, Path}} ->
		    %% Path found, check if the first element is ours
		    Me = siprequest:construct_record_route(URL#sipurl.proto),
		    case Path of
			[Me] ->
			    {proxy, siplocation:to_url(Location)};
			[Me | PathRest] ->
			    logger:log(debug, "Lookup: Removing myself from Path of location database entry, "
				      "leaving ~p", [PathRest]),
			    {proxy, {with_path, siplocation:to_url(Location), PathRest}};
			_ ->
			    {proxy, {with_path, siplocation:to_url(Location), Path}}
		    end;
		false ->
		    {proxy, siplocation:to_url(Location)}
	    end
    end.


lookupuser_multiple_locations(Locations, URL) when is_list(Locations), is_record(URL, sipurl) ->
    case is_same_outbound_client_without_path(Locations, URL) of
	true ->
	    %% We found more than one entry in the location database for this URL, but
	    %% they all end up at the same User-Agent (they have the same Instance ID).
	    %% Presumably this User-Agent does Outbound and registers more than once for
	    %% redundancy. We should not parallell-fork this but rather go on a sequential
	    %% hunt for a working destination.
	    Sorted = siplocation:sort_most_recent_first(Locations),
	    case make_dstlist(Sorted) of
		[] ->
		    %% All locations were removed by make_dstlist. This means they all used
		    %% Outbound and the flows all terminated at this host, and are gone.
		    {response, 430, "Flow Failed"};
		DstList when is_list(DstList) ->
		    {proxy, DstList}
	    end;
	false ->
	    %% More than one location registered for this address, check for appserver...
	    %% (appserver is the program that handles forking of requests)
	    local:lookupappserver(URL)
    end.

%% part of lookupuser_multiple_locations/2
%% Returns: true | false
is_same_outbound_client_without_path(In, URL) ->
    Me = siprequest:construct_record_route(URL#sipurl.proto),
    is_same_outbound_client_without_path2(In, undefined, undefined, Me).

is_same_outbound_client_without_path2([#siplocationdb_e{instance = []} | _], _PrevInst, _PrevUser, _Me) ->
    %% Binding without instance, this is not an Outbound client
    false;

is_same_outbound_client_without_path2([H | _] = In, undefined, undefined, Me) ->
    %% First one, to get the path checked as well we recurse on all of In
    #siplocationdb_e{instance = Instance,
		     sipuser  = User
		    } = H,
    is_same_outbound_client_without_path2(In, Instance, User, Me);

is_same_outbound_client_without_path2([#siplocationdb_e{instance = PrevInst, sipuser = PrevUser} = H | T],
				      PrevInst, PrevUser, Me) ->
    %% check Path too
    case lists:keysearch(path, 1, H#siplocationdb_e.flags) of
	{value, {path, [Me]}} ->
	    %% This one is OK, check next
	    is_same_outbound_client_without_path2(T, PrevInst, PrevUser, Me);
	false ->
	    %% No Path - that is OK, check next
	    is_same_outbound_client_without_path2(T, PrevInst, PrevUser, Me);
	_ ->
	    %% uh oh, this one has Path. We currently can't return such complex data from lookupuser
	    %% so we'll have to use appserver for this.
	    false
    end;

is_same_outbound_client_without_path2([#siplocationdb_e{} | _T], _PrevInst, _PrevUser, _Me) ->
    %% Not same instance ID or user
    false;

is_same_outbound_client_without_path2([], _Instance, _User, _Me) ->
    %% Instance ID was not empty, and all matched.
    true.

%% part of lookupuser_multiple_locations/2
%% Returns: NewList = list() of siplocationdb_e record()
make_dstlist(In) ->
    ThisNode = node(),
    make_dstlist2(In, ThisNode, []).

make_dstlist2([H | T], ThisNode, Res) when is_record(H, siplocationdb_e) ->
    case lists:keysearch(socket_id, 1, H#siplocationdb_e.flags) of
	{value, {socket_id, #locationdb_socketid{node = ThisNode} = SocketId}} ->
	    case sipsocket:get_specific_socket(SocketId#locationdb_socketid.id) of
		{error, _Reason} ->
		    %% Flow not avaliable anymore, skip this one
		    make_dstlist2(T, ThisNode, Res);
		SipSocket ->
		    This =
			#sipdst{proto		= SocketId#locationdb_socketid.proto,
				addr		= SocketId#locationdb_socketid.addr,
				port		= SocketId#locationdb_socketid.port,
				uri		= siplocation:to_url(H),
				socket		= SipSocket,
				instance	= H#siplocationdb_e.instance
			       },
		    make_dstlist2(T, ThisNode, [This | Res])
	    end;
	_ ->
	    %% Not using Outbound, or connected to some other node - use as is.
	    %% We already know we don't need to care about Path (checked by
	    %% is_same_outbound_client_without_path).
	    This =
		#sipdst{uri = siplocation:to_url(H),
			instance = H#siplocationdb_e.instance
		       },
	    make_dstlist2(T, ThisNode, [This | Res])
    end;
make_dstlist2([], _ThisNode, Res) ->
    lists:reverse(Res).


%%--------------------------------------------------------------------
%% @spec    (URL, GRUU) ->
%%            {ok, User, Res, Contact}
%%
%%            URL  = #sipurl{} "GRUU Request-URI"
%%            GRUU = string()
%%
%%            Res     = {proxy, URL}                    |
%%                      {proxy, {with_path, URL, Path}} |
%%                      {response, Status, Reason}
%%            User    = none | string() "SIP authentication user of GRUU"
%%            Contact = #siplocationdb_e{} "used by outgoingproxy"
%%
%% @doc     Look up the 'best' contact of a GRUU. Note : used by
%%          incomingproxy and outgoingproxy
%% @end
%%--------------------------------------------------------------------
lookupuser_gruu(URL, GRUU) when is_record(URL, sipurl), is_list(GRUU) ->
    %% XXX if it was an 'opaque=' GRUU, verify somehow that the rest of the URI matches
    %% the user we found when we look up the GRUU? Probably a good idea.
    logger:log(debug, "Lookup: URL ~s contains a GRUU (~p), looking for active contact",
	       [sipurl:print(URL), GRUU]),
    case gruu:get_contact_for_gruu(GRUU) of
	{ok, User, Contact} when is_record(Contact, siplocationdb_e) ->
	    logger:log(debug, "Lookup: GRUU ~p matches user ~p contact ~s",
		       [GRUU, User, sipurl:print(Contact#siplocationdb_e.address)]),

	    %% Copy 'grid' parameter
	    GridURL = gruu:prepare_contact(Contact, URL),

	    Res = lookupuser_single_location(Contact#siplocationdb_e{address = GridURL}, URL),
	    {ok, User, Res};
	{ok, User, none} ->
	    %% GRUU found, but user has no active contacts
	    logger:log(debug, "Lookup: GRUU ~p matches user ~p, but user has no active contacts. "
		       "Responding '480 Temporarily Unavailable'", [GRUU, User]),
	    %% "If the request URI is within the domain of the proxy, and
	    %% the URI has been constructed by the domain such that the proxy is
	    %% able to determine that it has the form of a GRUU for an AOR that is
	    %% known within the domain, but the instance ID is unknown, the proxy
	    %% SHOULD generate a 480 (Temporarily Unavailable)."
	    %% GRUU draft 06 #8.4.1 (Request Targeting)
	    {ok, none, {response, 480, "Temporarily Unavailable"}};
	nomatch ->
	    %% looked like a GRUU, but not found
	    logger:log(debug, "Lookup: Request-URI is a GRUU, but I have no record of it. "
		       "Answering '404 Not Found'."),
	    %% "If the request URI is within the domain of the proxy, and the URI has
	    %% been constructed by the domain such that the proxy is able to
	    %% determine that it has the form of a GRUU for an AOR that is unknown
	    %% within the domain, the proxy rejects the request with a 404 (Not
	    %% Found)." GRUU draft 06 #8.4.1 (Request Targeting)
	    {ok, none, {response, 404, "Not Found"}}
    end.

%%--------------------------------------------------------------------
%% @spec    (URL, Locations) -> [#siplocationdb_e{}]
%%
%%            URL      = #sipurl{} "Request-URI of request"
%%            Location = [#siplocationdb_e{}]
%%
%% @doc     Apply local policy for what locations are good to use for
%%          a particular Request-URI. The default action we do here
%%          is to remove non-SIPS locations if the Request-URI is
%%          SIPS, unless we are configured not to.
%% @end
%%--------------------------------------------------------------------
remove_unsuitable_locations(#sipurl{proto="sips"}, Locations) when is_list(Locations) ->
    case yxa_config:get_env(ssl_require_sips_registration) of
	{ok, true} ->
	    remove_non_sips_locations(Locations, []);
	{ok, false} ->
	    Locations
    end;
remove_unsuitable_locations(URL, Locations) when is_record(URL, sipurl), is_list(Locations) ->
    Locations.

%% part of remove_unsuitable_locations/2. Returns : list() of siplocationdb_e record()
remove_non_sips_locations([#siplocationdb_e{address=URL}=H | T], Res)
  when is_record(URL, sipurl), URL#sipurl.proto == "sips" ->
    remove_non_sips_locations(T, [H | Res]);
remove_non_sips_locations([#siplocationdb_e{address=URL}=H | T], Res) ->
    %% XXX do we need to lowercase what we get from url_param:find?
    case url_param:find(URL#sipurl.param_pairs, "transport") of
	["tls"] ->
	    %% Keep this location
	    remove_non_sips_locations(T, [H | Res]);
	_ ->
	    %% Not SIPS protocol or TLS transport parameter, remove this location from result
	    remove_non_sips_locations(T, Res)
    end;
remove_non_sips_locations([], Res) ->
    lists:reverse(Res).

%%--------------------------------------------------------------------
%% @spec    (URL) ->
%%            {proxy, DefaultRoute} |
%%            {response, Status, Reason}
%%
%%            URL = #sipurl{}
%%
%%            DefaultRoute = #sipurl{}
%%            Status       = integer() "SIP status code"
%%            Reason       = string() "SIP reason phrase"
%%
%% @doc     Get the configured default route. Used in incomingproxy.
%% @end
%%--------------------------------------------------------------------
lookupdefault(URL) when is_record(URL, sipurl) ->
    case homedomain(URL#sipurl.host) of
	true ->
	    logger:log(debug, "Lookup: Cannot default-route request to a local domain (~s), aborting",
		       [URL#sipurl.host]),
	    none;
        false ->
	    case yxa_config:get_env(defaultroute) of
		{ok, DefaultURL} when is_record(DefaultURL, sipurl) ->
		    NewURI = sipurl:set([{user, URL#sipurl.user}, {pass, none}], DefaultURL),
		    logger:log(debug, "Lookup: Default-routing to ~s", [sipurl:print(NewURI)]),
		    %% XXX we should preserve the Request-URI by proxying this as a loose router.
		    %% It is almost useless to only preserve the User-info IMO. We can do this
		    %% by returning {forward, Proto, Host, Port} instead.
		    {proxy, NewURI};
		none ->
		    logger:log(debug, "Lookup: No default route - dropping request"),
		    {response, 500, "Can't route request"}	%% XXX is 500 the correct error-code?
	    end
    end.


%%--------------------------------------------------------------------
%% @spec    (Request) -> true | false
%%
%%            Request = #request{}
%%
%% @doc     Check if a request is destined for this proxy. Not for a
%%          domain handled by this proxy, but for this proxy itself.
%% @end
%%--------------------------------------------------------------------
is_request_to_this_proxy(Request) when is_record(Request, request) ->
    {Method, URI, Header} = {Request#request.method, Request#request.uri, Request#request.header},
    IsOptionsForMe = is_request_to_this_proxy2(Method, URI, Header),
    IsHomedomain = local:homedomain(URI#sipurl.host),
    NoUserpart = (URI#sipurl.user == none),
    if
	IsOptionsForMe == true ->
	    true;
	IsHomedomain == true, NoUserpart == true ->
	    true;
	true ->
	    false
    end.

%% is_request_to_this_proxy2/3 is a subfunction of is_request_to_this_proxy/1,
%% called to check if this is an OPTIONS request with Max-Forwards =< 1.
%% This procedure is from RFC3261 #11 Querying for Capabilities.
is_request_to_this_proxy2("OPTIONS", URL, Header) when is_record(URL, sipurl) ->
    %% RFC3261 # 11 says a proxy that receives an OPTIONS request with a Max-Forwards less than one
    %% MAY treat it as a request to the proxy.
    case keylist:fetch('max-forwards', Header) of
	[M] ->
	    case list_to_integer(M) of
		N when N =< 1 ->
		    logger:log(debug, "Routing: Request is OPTIONS and Max-Forwards =< 1, "
			       "treating it as a request to me."),
		    true;
		_ ->
		    false
	    end;
	_ ->
	    %% No Max-Forwards, or invalid (more than one list element)
	    false
    end;
is_request_to_this_proxy2(_, URL, _) when is_record(URL, sipurl) ->
    false.

%%--------------------------------------------------------------------
%% @spec    (Domain) -> true | false
%%
%%            Domain = string()
%%
%% @doc     Check if Domain is one of our configured homedomains.
%% @end
%%--------------------------------------------------------------------
homedomain(Domain) when is_list(Domain) ->
    {ok, HomedomainL} = yxa_config:get_env(homedomain, []),
    LCdomain = string:to_lower(Domain),
    case lists:member(LCdomain, HomedomainL) of
	true ->
	    true;
	false ->
	    %% Domain did not match configured sets of homedomain, check against list
	    %% of hostnames and also my IP address
	    {ok, MyHostnames} = yxa_config:get_env(myhostnames, []),
	    lists:member(LCdomain, MyHostnames)
		orelse lists:member(LCdomain, siphost:myip_list())
    end.


%%--------------------------------------------------------------------
%% @spec    (In) -> string()
%%
%%            In = term()
%%
%% @doc     Pretty-print our various used lookup result values.
%% @end
%%--------------------------------------------------------------------
lookup_result_to_str(In) ->
    lists:flatten(lookup_result_to_str2(In)).

lookup_result_to_str2({Type, URL}) when is_atom(Type), is_record(URL, sipurl) ->
    URLstr = lists:flatten( io_lib:format("(sipurl) ~s", [sipurl:print(URL)]) ),
    io_lib:format("~p", [{Type, URLstr}]);
lookup_result_to_str2(Unknown) ->
    io_lib:format("~p", [Unknown]).

%%====================================================================
%%% Internal functions
%%====================================================================


%%====================================================================
%% Test functions
%%====================================================================

%%--------------------------------------------------------------------
%% @spec    () -> ok
%%
%% @doc     autotest callback
%% @hidden
%% @end
%%--------------------------------------------------------------------
-ifdef( YXA_NO_UNITTEST ).
test() ->
    {error, "Unit test code disabled at compile time"}.

-else.

test() ->
    %% test homedomain/1
    %% Note: We can't test this function very well because it relies heavily
    %% on configuration that can't be assumed to have any special content
    %% when testing
    %%--------------------------------------------------------------------
    MyHostname = siprequest:myhostname(),

    autotest:mark(?LINE, "homedomain/1 - 1"),
    %% test with my IP address
    %% XXX test fails if we have no interfaces up!
    true = homedomain(MyHostname),

    autotest:mark(?LINE, "homedomain/1 - 1"),
    %% test with something that should definately NOT be our hostname
    false = homedomain("1-2"),


    %% test is_request_to_this_proxy(Request)
    %%--------------------------------------------------------------------
    autotest:mark(?LINE, "is_request_to_this_proxy/1 - 1"),
    %% test OPTIONS with Max-Forwards: 1
    true = is_request_to_this_proxy(#request{method="OPTIONS", uri=sipurl:parse("sip:ft@example.org"),
					     header=keylist:from_list([{"Max-Forwards", ["1"]}])}),

    autotest:mark(?LINE, "is_request_to_this_proxy/1 - 2"),
    %% test OPTIONS with Max-Forwards: 10
    false = is_request_to_this_proxy(#request{method="OPTIONS", uri=sipurl:parse("sip:ft@example.org"),
					      header=keylist:from_list([{"Max-Forwards", ["10"]}])}),

    autotest:mark(?LINE, "is_request_to_this_proxy/1 - 3"),
    %% test MESSAGE with Max-Forwards: 10, but with URI pointing at us
    IRTTP_URI1 = sipurl:new([{proto, "sip"}, {host, MyHostname}]),
    true = is_request_to_this_proxy(#request{method="MESSAGE", uri=IRTTP_URI1,
					     header=keylist:from_list([{"Max-Forwards", ["10"]}])}),


    %% test remove_unsuitable_locations(URL, Locations)
    %%--------------------------------------------------------------------
    Unsuitable_URL1 = sipurl:new([{proto, "sip"}, {host, "sip1.example.org"}]),
    Unsuitable_URL2 = sipurl:new([{proto, "sips"}, {host, "sips1.example.org"}]),
    Unsuitable_URL3 = sipurl:new([{proto, "sip"}, {host, "sip2.example.org"}]),
    Unsuitable_URL4 = sipurl:new([{proto, "sip"}, {host, "sip2.example.org"}, {param, ["transport=tls"]}]),

    Unsuitable_LDBE1 = #siplocationdb_e{address=Unsuitable_URL1},
    Unsuitable_LDBE2 = #siplocationdb_e{address=Unsuitable_URL2},
    Unsuitable_LDBE3 = #siplocationdb_e{address=Unsuitable_URL3},
    Unsuitable_LDBE4 = #siplocationdb_e{address=Unsuitable_URL4},

    autotest:mark(?LINE, "remove_unsuitable_locations/2 - 1"),
    %% test with non-SIPS URI, no entrys should be removed
    [Unsuitable_LDBE1, Unsuitable_LDBE2, Unsuitable_LDBE3] =
	remove_unsuitable_locations(Unsuitable_URL1, [Unsuitable_LDBE1, Unsuitable_LDBE2, Unsuitable_LDBE3]),

    autotest:mark(?LINE, "remove_unsuitable_locations/2 - 2"),
    %% test with SIPS URI
    [Unsuitable_LDBE2] =
	remove_unsuitable_locations(Unsuitable_URL2, [Unsuitable_LDBE1, Unsuitable_LDBE2, Unsuitable_LDBE3]),

    autotest:mark(?LINE, "remove_unsuitable_locations/2 - 3"),
    %% test with SIP URI but transport parameter indicating TLS
    [Unsuitable_LDBE4] =
	remove_unsuitable_locations(Unsuitable_URL2, [Unsuitable_LDBE1, Unsuitable_LDBE4]),


    %% lookup_result_to_str(In)
    %%--------------------------------------------------------------------
    autotest:mark(?LINE, "lookup_result_to_str/1 - 1"),
    %% test tuple with URL
    "{relay,\"(sipurl) sip:ft@example.net\"}" = lookup_result_to_str({relay, sipurl:parse("sip:ft@example.net")}),

    autotest:mark(?LINE, "lookup_result_to_str/1 - 2"),
    %% test tuple with atom
    "{proxy,route}" = lookup_result_to_str({proxy, route}),

    autotest:mark(?LINE, "lookup_result_to_str/1 - 3"),
    %% test unknown
    "[test]" = lookup_result_to_str([test]),


    %% Mnesia dependant tests
    %%--------------------------------------------------------------------


    autotest:mark(?LINE, "Mnesia setup - 0"),

    phone:test_create_table(),
    database_gruu:test_create_table(),
    database_regexproute:test_create_table(),

    case mnesia:transaction(fun test_mnesia_dependant_functions/0) of
	{aborted, ok} ->
	    ok;
	{aborted, Res} ->
	    {error, Res}
    end.


test_mnesia_dependant_functions() ->

    %% lookupuser(URL)
    %%--------------------------------------------------------------------
    autotest:mark(?LINE, "lookupuser/1 - 0"),
    LookupURL1 = sipurl:new([{user, "testuser1"},
			     {host, "__test__.example.org"}
			    ]),

    LookupURL2 = sipurl:new([{user, "testuser2"},
			     {host, "__test__.example.org"}
			    ]),

    autotest:mark(?LINE, "lookupuser/1 - 1"),
    %% look for user that does not exist
    nomatch = lookupuser(LookupURL1),

    %% XXX not testing rest of this function yet because it requires sipuserdb_mnesia
    %% to be used (for us to be able to predict the results that is).

    %% lookupuser_get_locations(Users, URL)
    %%--------------------------------------------------------------------
    autotest:mark(?LINE, "lookupuser_get_locations/2 - 1"),
    %% test with bad (unknown) user
    none = lookupuser_get_locations(["__test_user_dont_exist__"], LookupURL2),


    autotest:mark(?LINE, "lookupuser_get_locations/2 - 2.0"),
    %% test that lookup_regexproute is called when user has no known locations
    LGL_Rewritten2_Str = "sip:rewritten@test19119.example.com",
    LGL_Rewritten2_URL = sipurl:parse(LGL_Rewritten2_Str),
    {atomic, ok} = database_regexproute:insert(".*@__test__.example.org$", [], dynamic,
					       util:timestamp() + 20, LGL_Rewritten2_Str),

    autotest:mark(?LINE, "lookupuser_get_locations/2 - 2.1"),
    {proxy, LGL_Rewritten2_URL} = lookupuser_get_locations(["__test_user_dont_exist__"], LookupURL2),

    autotest:mark(?LINE, "lookupuser_get_locations/2 - 2.2"),
    %% clean up
    {atomic, ok} = database_regexproute:delete(".*@__test__.example.org$", [], dynamic,
					       util:timestamp() + 20, LGL_Rewritten2_Str),


    autotest:mark(?LINE, "lookupuser_get_locations/2 - 3.0"),
    %% test with a single registered contact, no Outbound and no Path
    LGL_Contact3_URL = sipurl:parse("sip:ft@192.0.2.133"),
    LGL_Username3 = "__test_user_LGL_3__",

    {atomic, ok} = phone:insert_purge_phone(LGL_Username3, [], static, never,
					    LGL_Contact3_URL, [], 1, []),

    autotest:mark(?LINE, "lookupuser_get_locations/2 - 3.1"),
    {proxy, LGL_Contact3_URL} = lookupuser_get_locations([LGL_Username3], LookupURL1),


    autotest:mark(?LINE, "lookupuser_get_locations/2 - 4.0"),
    %% test with a single registered contact, Path matching me
    LGL_Contact4_URL = sipurl:parse("sip:ft@192.0.2.144;foo=bar"),
    LGL_Path4 = siprequest:construct_record_route(LGL_Contact4_URL#sipurl.proto),
    LGL_Username4 = "__test_user_LGL_4__",

    {atomic, ok} = phone:insert_purge_phone(LGL_Username4, [{path, [LGL_Path4]}], static, never,
					    LGL_Contact4_URL, [], 1, []),

    autotest:mark(?LINE, "lookupuser_get_locations/2 - 4.1"),
    {proxy, LGL_Contact4_URL} = lookupuser_get_locations([LGL_Username4], LookupURL1),


    autotest:mark(?LINE, "lookupuser_get_locations/2 - 5.0"),
    %% test with a single registered contact, Path matching me and one more entry
    LGL_Contact5_URL = sipurl:parse("sip:ft@192.0.2.155;foo=bar"),
    LGL_Path5 = siprequest:construct_record_route(LGL_Contact5_URL#sipurl.proto),
    LGL_Path5_2 = "<sip:__test__@__test_test__.example.org;lr>",
    LGL_Username5 = "__test_user_LGL_5__",

    {atomic, ok} = phone:insert_purge_phone(LGL_Username5, [{path, [LGL_Path5, LGL_Path5_2]}], static, never,
					    LGL_Contact5_URL, [], 1, []),

    autotest:mark(?LINE, "lookupuser_get_locations/2 - 5.1"),
    {proxy, {with_path, LGL_Contact5_URL, [LGL_Path5_2]}} = lookupuser_get_locations([LGL_Username5], LookupURL1),


    autotest:mark(?LINE, "lookupuser_get_locations/2 - 6.0"),
    %% test with a single registered contact, Path pointing at some other host only
    LGL_Contact6_URL = sipurl:parse("sip:ft@192.0.2.154;foo=bar"),
    LGL_Path6 = "<sip:__test__@__test_test__.example.org;lr>",
    LGL_Username6 = "__test_user_LGL_6__",

    {atomic, ok} = phone:insert_purge_phone(LGL_Username6, [{path, [LGL_Path6]}], static, never,
					    LGL_Contact6_URL, [], 1, []),

    autotest:mark(?LINE, "lookupuser_get_locations/2 - 6.1"),
    {proxy, {with_path, LGL_Contact6_URL, [LGL_Path6]}} = lookupuser_get_locations([LGL_Username6], LookupURL1),


    autotest:mark(?LINE, "lookupuser_get_locations/2 - 9"),
    %% clean up
    {atomic, ok} = phone:delete_phone_for_user(LGL_Username3, static),
    {atomic, ok} = phone:delete_phone_for_user(LGL_Username4, static),
    {atomic, ok} = phone:delete_phone_for_user(LGL_Username5, static),
    {atomic, ok} = phone:delete_phone_for_user(LGL_Username6, static),


    %% Outbound TESTS

    autotest:mark(?LINE, "lookupuser_get_locations/2 - 10.0"),
    %% test with Outbound socket on other node
    LGL_Contact10_URL = sipurl:parse("sip:ft@192.0.2.212"),
    LGL_Username10 = "__test_user_LGL_10__",
    LGL_LDBSocketId10 = #locationdb_socketid{node = 'othernode@nowhere',
					     id   = 1
					    },

    {atomic, ok} = phone:insert_purge_phone(LGL_Username10, [{socket_id, LGL_LDBSocketId10}],
					    static, never, LGL_Contact10_URL, [], 1, []),

    autotest:mark(?LINE, "lookupuser_get_locations/2 - 10.1"),
    {proxy, LGL_Contact10_URL} = lookupuser_get_locations([LGL_Username10], LookupURL1),


    autotest:mark(?LINE, "lookupuser_get_locations/2 - 11.0"),
    %% test with Outbound socket to this node but no longer available
    LGL_Contact11_URL = sipurl:parse("sip:ft@192.0.2.212"),
    LGL_Username11 = "__test_user_LGL_11__",
    LGL_SocketId11 = #ob_id{proto = yxa_test,
			    id = 1
			   },
    LGL_LDBSocketId11 = #locationdb_socketid{node = node(),
					     id   = LGL_SocketId11
					    },
    autotest_util:store_unit_test_result(?MODULE, {sipsocket_test, get_specific_socket}, {error, "testing"}),

    {atomic, ok} = phone:insert_purge_phone(LGL_Username11, [{socket_id, LGL_LDBSocketId11}],
					    static, never, LGL_Contact11_URL, [], 1, []),

    autotest:mark(?LINE, "lookupuser_get_locations/2 - 11.1"),
    {response, 430, _} = lookupuser_get_locations([LGL_Username11], LookupURL1),

    autotest:mark(?LINE, "lookupuser_get_locations/2 - 11.2"),
    %% now test with socket available
    autotest_util:clear_unit_test_result(?MODULE, {sipsocket_test, get_specific_socket}),
    LGL_SipSocket11 = sipsocket:get_specific_socket(LGL_SocketId11),
    {proxy, [#sipdst{proto = undefined,
		     addr = undefined,
		     port = undefined,
		     uri = LGL_Contact11_URL,
		     socket = LGL_SipSocket11
		    }
	     ]} = lookupuser_get_locations([LGL_Username11], LookupURL1),




    autotest:mark(?LINE, "lookupuser_get_locations/2 - 19"),
    %% clean up
    {atomic, ok} = phone:delete_phone_for_user(LGL_Username10, static),
    {atomic, ok} = phone:delete_phone_for_user(LGL_Username11, static),


    mnesia:abort(ok).

-endif.
