-module(oauth1_core_app).

-include_lib("oauth1_module_abbreviations.hrl").

-behaviour(application).

-export(
    [ start/2
    , stop/1
    ]).


start(_StartType, _StartArgs) ->
    case ?storage:start()
    of  {error, _}=Error -> Error
    ;   {ok, ok}         -> oauth1_core_sup:start_link()
    end.

stop(_State) ->
    {ok, ok} = ?storage:stop(),
    ok.
