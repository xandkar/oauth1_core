-module(oauth1_resource_SUITE).

%% Callbacks
-export(
    [ all/0
    , groups/0
    ]).

%% Tests
-export(
    [ t_crud/1
    ]).


-define(GROUP, oauth1_resource).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP}].

groups() ->
    Tests =
        [ t_crud
        ],
    Properties = [],
    [ {?GROUP, Properties, Tests}
    ].


%%=============================================================================
%% Tests
%%=============================================================================

t_crud(_Cfg) ->
    {ok, URI} = oauth1_uri:of_bin(<<"https://foo/bar/baz">>),
    Realm     = <<"namiras-scuttling-void">>,
    Resource  = oauth1_resource:cons(Realm, URI),
    Realm     = oauth1_resource:get_realm(Resource),
    URI       = oauth1_resource:get_uri(Resource).
