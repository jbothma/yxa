%%%-------------------------------------------------------------------
%%% File    : table_update.erl
%%% @author   Håkan Stenholm <hsten@it.su.se>
%%% @doc      This code updates older database tables.
%%%           to disk (and erlang shell).
%%%
%%% @since    25 Oct 2004 by Håkan Stenholm <hsten@it.su.se>
%%% @end
%%% @private
%%%-------------------------------------------------------------------
-module(table_update).

%%--------------------------------------------------------------------
%% External exports
%%--------------------------------------------------------------------

-export([
	 update/0
	]).

%%--------------------------------------------------------------------
%% Internal exports
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% Include files
%%--------------------------------------------------------------------
-include("siprecords.hrl").

%%--------------------------------------------------------------------
%% Records
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% Macros
%%--------------------------------------------------------------------

%%====================================================================
%% External functions
%%====================================================================

%%--------------------------------------------------------------------
%% Function:
%% Descrip.: update databases
%% Returns : ok
%%--------------------------------------------------------------------
update() ->
    logger:log(debug, "Checking if any mnesia tables needs updating"),
    cpl_script_graph(),
    gruu(),
    ok.

%%--------------------------------------------------------------------
%% @spec    () -> void()
%%
%% @doc     Update the cpl_script_graph record() in cpl_db to also
%%          store CPL script as plain text. Change dated 2005-10.
%% @end
%%--------------------------------------------------------------------
cpl_script_graph() ->
    Table = cpl_script_graph,
    {ok, Attrs, Fun} = cpl_db:get_transform_fun(),
    do_transform_table(Table, Fun, Attrs).

%%--------------------------------------------------------------------
%% @spec    () -> void()
%%
%% @doc     Update the gruu record().
%% @end
%%--------------------------------------------------------------------
gruu() ->
    Table = gruu,
    {ok, Attrs, Fun} = database_gruu:get_transform_fun(),
    do_transform_table(Table, Fun, Attrs).

%%====================================================================
%% Internal functions
%%====================================================================

%% Returns: ok
do_transform_table(Table, Fun, Fields) when is_atom(Table), is_function(Fun, 1), is_list(Fields) ->
    put({Table, update}, false),

    case mnesia:transform_table(Table, Fun, Fields) of
	{atomic, ok} ->
	    ok;
	{aborted, {not_active, Reason, Table, NodeList}} ->
	    %% All disc_copies nodes must be online for table transforming, but we can't require
	    %% all those nodes to be alive in order to start the YXA servers.
	    logger:log(normal, "Warning: Failed to update Mnesia table '~p' : ~s~n(node list : ~p)",
		       [Table, Reason, NodeList]);
	{aborted, {"Bad transform function", Table, _BadFun, OtherNode, {{badfun, _BadFun}, _ST}}} ->
	    logger:log(error, "Error: Failed to update Mnesia table '~p' because the local transformation "
		       "function is not the same as the one on node ~p", [Table, OtherNode]),
	    erlang:error('Version inconsistency with other disc_copies nodes - table transform impossible')
    end,

    case erase({Table, update}) of
	true ->
	    logger:log(debug, "~p: updated", [Table]);
	false ->
	    true
    end,

    ok.
