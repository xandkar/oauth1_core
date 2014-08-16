Definitions.

OAuth  = OAuth
Equals = =
Quote  = "
Text   = [a-zA-Z0-9_\-%\.]+
Comma  = ,
Space  = [\s\n]+


Rules.

{OAuth}  : {token, {oauth , TokenLine, TokenChars}}.
{Equals} : {token, {equals, TokenLine, TokenChars}}.
{Quote}  : {token, {quote , TokenLine, TokenChars}}.
{Text}   : {token, {text  , TokenLine, TokenChars}}.
{Comma}  : {token, {comma , TokenLine, TokenChars}}.
{Space}  : skip_token.


Erlang code.
