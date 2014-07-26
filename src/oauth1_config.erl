-module(oauth1_config).

-export(
    [ get/1
    ]).


-define(APPLICATION, oauth1).


-spec get(atom()) ->
    any().
get(Key) ->
    {ok, Value} = application:get_env(?APPLICATION, Key),
    Value.
