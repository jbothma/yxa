-module(testserver).

%% Standard Yxa SIP-application exports
-export([init/0, request/3, response/3]).

-include("siprecords.hrl").
-include("sipsocket.hrl").

%%--------------------------------------------------------------------
%%% Standard Yxa SIP-application exported functions
%%--------------------------------------------------------------------


%% Function: init/0
%% Description: Yxa applications must export an init/0 function.
%% Returns: See XXX
%%--------------------------------------------------------------------
init() ->
    database_call:create([node()]),
    [none, stateful, {append, []}].


%% Function: request/3
%% Description: Yxa applications must export an request/3 function.
%% Returns: See XXX
%%--------------------------------------------------------------------
request(Request, Origin, LogStr) when record(Request, request), record(Origin, siporigin) ->
    THandler = transactionlayer:get_handler_for_request(Request),
    LogTag = get_branch_from_handler(THandler),
    case Request#request.method of
        "REGISTER" ->
            process_request(Request, LogTag);
	_ when Request#request.method == "INVITE"; Request#request.method == "MESSAGE" ->
	    packet_check_ok(Request#request.header, LogTag),
	    process_request(Request, LogTag);
	"ACK" ->
	    process_request(Request, LogTag);
	"CANCEL" ->
	    process_request(Request, LogTag);
	"BYE" ->
	    process_request(Request, LogTag);
	_ ->
	    logger:log(normal, "~s -- NOT IMPLEMENTED", [LogTag]),
	    transactionlayer:send_response_handler(THandler, 501, "Not Implemented")
    end.

%% Function: response/3
%% Description: Yxa applications must export an response/3 function.
%% Returns: See XXX
%%--------------------------------------------------------------------
response(Response, Origin, LogStr) when record(Response, response), record(Origin, siporigin) ->
    logger:log(normal, "~p ~p - dropping", [Response#response.status, Response#response.reason]),
    true.


%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

%%
%% REGISTER
%%
process_request(Request, LogTag) when record(Request, request), Request#request.method == "REGISTER" ->
    URI = Request#request.uri,
    case localhostname(URI#sipurl.host) of
	true ->
	    Contacts = sipheader:contact(Request#request.header),
	    logger:log(debug, "Register: Contact(s) ~p", [sipheader:contact_print(Contacts)]),
	    transactionlayer:send_response_request(Request, 200, "OK",
						   [{"Expires", ["0"]},
						    {"Contacts", sipheader:contact_print(Contacts)}]
						  );
	_ ->
	    logger:log(normal, "~s: REGISTER for non-homedomain ~p", [LogTag, URI#sipurl.host]),
	    transactionlayer:send_response_request(Request, 501, "Not Implemented")
    end;

%%
%% INVITE or MESSAGE
%%
process_request(Request, LogTag) when record(Request, request), Request#request.method == "INVITE"; 
Request#request.method == "MESSAGE" ->
    case get_user(Request#request.uri) of
	{404, Reason} ->
	    logger:log(normal, "~s: Testserver classic response: '404 ~p'", [LogTag, Reason]),
	    transactionlayer:send_response_request(Request, 404, Reason);
	{Status, Reason} ->
	    logger:log(normal, "~s: Testserver response: '~p ~s'", [LogTag, Status, Reason]),
	    transactionlayer:send_response_request(Request, Status, Reason);
	nomatch ->
	    {User, _, _, _, _} = Request#request.uri,
	    S = lists:flatten(io_lib:format("Busy Here (~s)", [User])),
	    logger:log(normal, "~s: Testserver built-in response: '486 ~s'", [LogTag, S]),
	    transactionlayer:send_response_request(Request, 486, S)
    end;

%%
%% Anything but REGISTER, INVITE or MESSAGE
%%
process_request(Request, LogTag) when record(Request, request) ->
    logger:log(normal, "~s: testserver: ~s ~s dropped",
	       [LogTag, Request#request.method, sipurl:print(Request#request.uri)]),
    true.


get_user(URI) ->
    Key = sipurl:print(URI),
    Res = regexp_locate_user(Key, sipserver:get_env(user_db, [])),
    logger:log(debug, "Locate user: ~s -> ~p", [Key, Res]),
    Res.


regexp_locate_user(Input, []) ->
    nomatch;
regexp_locate_user(Input, [{Regexp, Code, Text} | Rest]) ->
    case regexp:match(Input, Regexp) of
	{match, _, _} ->
	    {Code, Text};
	nomatch ->
	    regexp_locate_user(Input, Rest);
	{error, Error} ->
	    logger:log(normal, "Error in regexp ~p: ~p", [Regexp, Error]),
	    []
    end.


packet_check_ok(Header, LogTag) ->
    check_no_unsupported_extension(Header, LogTag).


check_no_unsupported_extension(Header, LogTag) ->
    Require = keylist:fetch("Require", Header),
    case Require of
	[] ->
	    true;
	_ ->
	    logger:log(normal, "~s: UAS Request check: The client requires unsupported extension(s) ~p",
		       [LogTag, Require]),
	    throw({siperror, 420, "Bad Extension", [{"Unsupported", Require}]})
    end.


get_branch_from_handler(TH) ->
    CallBranch = transactionlayer:get_branch_from_handler(TH),
    case string:rstr(CallBranch, "-UAS") of
	0 ->
	    CallBranch;
	Index when integer(Index) ->
            BranchBase = string:substr(CallBranch, 1, Index - 1),
	    BranchBase
    end.


localhostname(Hostname) ->
    util:casegrep(Hostname, sipserver:get_env(myhostnames)).
