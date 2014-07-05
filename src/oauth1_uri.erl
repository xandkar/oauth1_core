-module(oauth1_uri).

-export_type(
    [ t/0
    ]).

-export(
    [ cons/1
    ]).

-type scheme() :: http
                | https
                .

-record(t,
    { scheme         :: scheme()
    , user = none    :: hope_option:t(binary())
    , host           :: binary()
    , port           :: integer()
    , path_and_query :: binary()
    }).

-opaque t() :: #t{}.

-include_lib("oauth1_uri.hrl").

-spec cons(oauth1_uri_cons()) -> t().
cons(#oauth1_uri_cons
    { scheme         = Scheme
    , user           = User
    , host           = Host
    , port           = Port
    , path_and_query = PathAndQuery
    }
) ->
    #t
    { scheme         = Scheme
    , user           = User
    , host           = Host
    , port           = Port
    , path_and_query = PathAndQuery
    }.
