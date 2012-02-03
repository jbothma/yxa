%%%===================================================================
%%% The purpose of this application is to get get a minimal SIP system
%%% running which can reply something valid to a LISTEN and OPTIONS
%%% request.
%%%===================================================================
-module(simpleapp).

-behaviour(application).
-behaviour(yxa_app).

%% export application callbacks
-export([start/2,
	 stop/1]).

%% export yxa_app callbacks
-export([config_defaults/0,
	 init/0,
         request/2,
         response/2,
	 terminate/1
	]).

%%--------------------------------------------------------------------
%% Include files
%%--------------------------------------------------------------------
-include("siprecords.hrl").
-include("sipsocket.hrl").
-include("yxa_config.hrl").

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    Res = sipserver:start(normal, [simpleapp]),
    io:format("sipserver start result ~p~n", [Res]),
    simpleapp_sup:start_link().

stop(_State) ->
    ok.

%%====================================================================
%% Behaviour functions
%% Standard YXA SIP-application callback functions
%%====================================================================

%%--------------------------------------------------------------------
%% @spec    () -> AppConfig
%%
%%            AppConfig = [#cfg_entry{}]
%%
%% @doc     Return application defaults.
%% @end
%%--------------------------------------------------------------------
config_defaults() ->
    [].

%%--------------------------------------------------------------------
%% @spec    () -> #yxa_app_init{}
%%
%% @doc     YXA applications must export an init/0 function.
%% @hidden
%% @end
%%--------------------------------------------------------------------
init() ->
    io:format("initing simpleapp~n"),
    #yxa_app_init{ sup_spec      = none,
                   mnesia_tables = []
                 }.

%%--------------------------------------------------------------------
%% @spec    (Request, YxaCtx) ->
%%            term() "Yet to be specified. Return 'ok' for now."
%%
%%            Request = #request{}
%%            YxaCtx  = #yxa_ctx{}
%%
%% @doc     YXA applications must export a request/2 function.
%% @end
%%--------------------------------------------------------------------
%%
%% INVITE
%%
request(#request{method = "INVITE"} = _Request, YxaCtx) ->
    io:format("simpleapp received INVITE.~n"),
    transactionlayer:send_response_handler(YxaCtx#yxa_ctx.thandler,
					   486,
					   "Busy Here (simpleapp demo)"),
    ok;

request(#request{method = "OPTIONS"} = Request, YxaCtx) ->
    AllowMethods = [{"Allow", ["AWESOME_STUFF"]}],
    siprequest:request_to_me(Request, YxaCtx, AllowMethods),
    ok;


request(Request, YxaCtx) ->
    io:format("unhandled request ~p ~p~n", [Request, YxaCtx]),
    ok.

%%--------------------------------------------------------------------
%% @spec    (Response, YxaCtx) ->
%%            term() "Yet to be specified. Return 'ok' for now."
%%
%%            Request = #response{}
%%            YxaCtx  = #yxa_ctx{}
%%
%% @doc     YXA applications must export an response/3 function.
%% @end
%%--------------------------------------------------------------------
response(Response, YxaCtx)->
    io:format("unhandled response ~p ~p~n", [Response, YxaCtx]),
    ok.

%%--------------------------------------------------------------------
%% @spec    (Mode) ->
%%            term() "Yet to be specified. Return 'ok' for now."
%%
%%            Mode = shutdown | graceful | atom()
%%
%% @doc     YXA applications must export a terminate/1 function.
%% @hidden
%% @end
%%--------------------------------------------------------------------
terminate(Mode) when is_atom(Mode) ->
    ok.
