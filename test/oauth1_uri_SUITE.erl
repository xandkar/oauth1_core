-module(oauth1_uri_SUITE).

-include_lib("oauth1_uri.hrl").

%% Callbacks
-export(
    [ all/0
    , groups/0
    ]).

%% Tests
-export(
    [ t_cons_parse_equality/1
    , t_to_bin/1
    ]).


-define(GROUP, oauth1_resource).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP}].

groups() ->
    Tests =
        [ t_cons_parse_equality
        , t_to_bin
        ],
    Properties = [],
    [ {?GROUP, Properties, Tests}
    ].


%%=============================================================================
%% Tests
%%=============================================================================

t_cons_parse_equality(_Cfg) ->
    URIBin = <<"https://dude@server.org/foo?k1=v1&k2=v2">>,
    {ok, URIParsed} = oauth1_uri:of_bin(URIBin),
    Args = #oauth1_uri_args_cons
        { scheme = https
        , user   = {some, <<"dude">>}
        , host   = <<"server.org">>
        , port   = 443
        , path   = <<"/foo">>
        , query  = [{<<"k1">>, <<"v1">>}, {<<"k2">>, <<"v2">>}]
        },
    URIConsed = oauth1_uri:cons(Args),
    URIConsedBin = oauth1_uri:to_bin(URIConsed),
    URIParsedBin = oauth1_uri:to_bin(URIParsed),
    ct:log("URIConsedBin: ~p", [URIConsedBin]),
    ct:log("URIParsedBin: ~p", [URIParsedBin]),
    QueryConsed = oauth1_uri:get_query(URIConsed),
    QueryParsed = oauth1_uri:get_query(URIParsed),
    ct:log("QueryConsed: ~p", [QueryConsed]),
    ct:log("QueryParsed: ~p", [QueryParsed]),
    [] = QueryConsed -- QueryParsed,
    HostConsed = oauth1_uri:get_host(URIConsed),
    HostParsed = oauth1_uri:get_host(URIParsed),
    ct:log("HostConsed: ~p", [HostConsed]),
    ct:log("HostParsed: ~p", [HostParsed]),
    HostConsed = HostParsed.

t_to_bin(_Cfg) ->
    URI_A_BinGiven    = <<"https://server.org:443/foo?k1=v1&k2=v2">>,
    URI_A_BinExpected = <<"https://server.org/foo?k1=v1&k2=v2">>,
    URI_B_BinGiven    = <<"https://server.org:587/foo?k1=v1&k2=v2">>,
    URI_B_BinExpected = <<"https://server.org:587/foo?k1=v1&k2=v2">>,
    {ok, URI_A_1} = oauth1_uri:of_bin(URI_A_BinGiven),
    {ok, URI_B_1} = oauth1_uri:of_bin(URI_B_BinGiven),
    QueryA = oauth1_uri:get_query(URI_A_1),
    QueryB = oauth1_uri:get_query(URI_B_1),
    QueryASorted = lists:sort(QueryA),
    QueryBSorted = lists:sort(QueryB),
    URI_A_2 = oauth1_uri:set_query(URI_A_1, QueryASorted),
    URI_B_2 = oauth1_uri:set_query(URI_B_1, QueryBSorted),
    URI_A_BinComputed = oauth1_uri:to_bin(URI_A_2),
    URI_B_BinComputed = oauth1_uri:to_bin(URI_B_2),
    ct:log("URI_A_BinExpected: ~p", [URI_A_BinExpected]),
    ct:log("URI_A_BinComputed: ~p", [URI_A_BinComputed]),
    ct:log("URI_B_BinExpected: ~p", [URI_B_BinExpected]),
    ct:log("URI_B_BinComputed: ~p", [URI_B_BinComputed]),
    URI_A_BinExpected = URI_A_BinComputed,
    URI_B_BinExpected = URI_B_BinComputed.
