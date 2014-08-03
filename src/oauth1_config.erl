-module(oauth1_config).

-export(
    [ get/1
    ]).


-define(APPLICATION, oauth1_core).


-spec get(atom()) ->
    any().
get(Key) ->
    {ok, Value} = application:get_env(?APPLICATION, Key),
    Value.
