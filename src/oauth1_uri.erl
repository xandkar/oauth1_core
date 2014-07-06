-module(oauth1_uri).

-include_lib("oauth1_uri.hrl").

-export_type(
    [ t/0
    , args_cons/0
    ]).

-export(
    [ cons/1
    ]).


-type scheme() ::
      http
    | https
    .

-record(t,
    { scheme         :: scheme()
    , user = none    :: hope_option:t(binary())
    , host           :: binary()
    , port           :: integer()
    , path_and_query :: binary()
    }).

-opaque t() ::
    #t{}.

-type args_cons() ::
    #oauth1_uri_args_cons{}.


-spec cons(args_cons()) ->
    t().
cons(#oauth1_uri_args_cons
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
