-module(siptest).

-export([main/1]).

main(["invite", Host]) ->
    siptest_utils:invite(Host);

main(["options", Host]) ->
    siptest_utils:options(Host).
