-module(siptest).

-export([main/1]).

main(["invite", _Host]) ->
    siptest_utils:invite();

main(["options", _Host]) ->
    siptest_utils:options().
