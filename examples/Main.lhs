Building OAuth 2.0 applications with Snap.
==========================================

Introduction
============

The `snaplet-oauth` library allows developers to easily add authentication to
their applications using the OAuth 2.0 specification
([RFC 6749](http://tools.ietf.org/html/rfc6749)). This literate Haskell example
shows how easy it is to build applications with OAuth support.

First, a few extensions to make development easier:

> {-# LANGUAGE OverloadedStrings #-}
> {-# LANGUAGE TemplateHaskell #-}


DELETE ME
=========

> import Snap.Snaplet.OAuth2.PostgreSQL


Add some general imports we will need:

> import Control.Applicative
> import Control.Lens.TH
> import Control.Monad (forM_, join)
> import Data.Monoid (mappend)
> import Data.Text.Encoding (decodeUtf8)
> import Network.URI
> import Snap.Blaze
> import Snap.Core
> import Snap.Http.Server
> import Snap.Snaplet
> import Text.Blaze.Html5 ((!), toHtml, toValue)
> import qualified Data.Text as T
> import qualified Text.Blaze.Html5 as H
> import qualified Text.Blaze.Html5.Attributes as A

Specifically, we need to import the `OAuth2` Snaplet:

> import Snap.Snaplet.OAuth2

We are now ready to begin adding OAuth to our application. 

Application Scope
-----------------

The first thing we should do, is define the set of scopes that clients can
request. In this example application we will be working with secret documents,
so the two scopes are the ability to read secret documents, and the ability to
write new secret documents:

> data AppScope = ReadSecretDocuments | CreateDocuments
>     deriving (Enum, Eq, Ord, Show)

We also need to define an isomorphism between the custom scope and 'Text'. This
is so that scopes can be parsed from request parameters, and also used in error
responses to indicate expected scopes from clients.

> instance Scope AppScope where
>     parseScope "read" = Just ReadSecretDocuments
>     parseScope "create" = Just CreateDocuments
>     parseScope _      = Nothing
> 
>     showScope ReadSecretDocuments = "read"
>     showScope CreateDocuments = "create"

Application Definition
----------------------

We define our application as normal, nesting an 'OAuth' 'Snaplet'.

> data App = App { _oAuth :: Snaplet (OAuth AppScope) }
> makeLenses ''App

OAuth Handlers
==============

We are now ready to write the handlers necessary for OAuth interaction. These
handlers must be provided, and as you are able to write them yourself you are
able to design them so that they integrate consistently with the rest of your
application.

Authorization Grants
--------------------

The first handler we need is used by resource owners to grant authorization to
applications. In most applications, this will normally display a login form, and
require resource owners to login to the website and then grant access to a client.
However, in this example to keep things simple we'll display 2 buttons - one to
deny a request and one to grant it.

> doLogin :: Client -> [AppScope] -> Handler App (OAuth AppScope) AuthorizationResult
> doLogin client scope = do

We will do some (overly) simplified request parsing. The response field can
contain two possible values - 'Deny' or Authorize. If it is missing, then we
assume that the resource owner hasn't yet responded

>   possibleResponse <- getParam "response"
>   case possibleResponse of

If the resource owner denied the request, we inform them of their choice...

>     Just "Deny" -> do
>       blaze $ pageTemplate "Access Denied" $ do
>         H.h1 "Access Denied"
>         H.p "Access has been denied"

And tell the OAuth Snaplet that the request was denied:

>       return Denied

If the resource owner authorized the request, then we inform them of their
choice..

>     Just "Authorize" -> do
>         blaze $ pageTemplate "Access Granted" $ do
>             H.h1 "Access Granted"
>             H.p "Access has been granted"

And tell the OAuth Snaplet that the request was granted:

>         return Granted

Finally, for any other case we assume that the resource owner is yet to
respond, and so we ask for their permission.

>     _ -> do
>       currentUrl <- withRequest (return . decodeUtf8 . rqURI)
>       blaze $ pageTemplate "Grant access?" $ do
>         H.h1 "Authorization Request"
>         H.p "Do you wish to allow access to protected documents?"
>         H.p "The following access is being requested"

The request will contain a list of scopes that the client is requesting, which
we can pattern match on to display a human readable description of what these
scopes mean:

>         H.ul $ forM_ scope $ \scope -> H.li $ do
>             case scope of
>                 ReadSecretDocuments -> "Read secret documents"
>                 CreateDocuments -> "Create new documents"

Finally we present a form to grant or deny authorization:

>         H.form ! A.method "POST" $ do
>           H.input ! A.type_ "submit" ! A.name "response" ! A.value "Authorize"
>           H.input ! A.type_ "submit" ! A.name "response" ! A.value "Deny"

Because the user has yet to make a choice, we inform the OAuth Snaplet that
authorization is still in progress.

>       return InProgress

Client Registration
-------------------

Clients are mandatory in the implementation of OAuth 2 in this Snaplet,
so we need to provide an end point to register new clients. In this handler,
we present a simplified form to do so, and on successful submission we
register the client.

> registerClient = do
>   clientRedirect <- getParam "redirect-uri"
>   clientId <- getParam "client-id"
>   clientName <- getParam "name"

The request validation is again a very simplified one. We simply "parse"
the request for a submitted client name, client ID, and parseable redirection
URI.

>   case (clientName, clientId, join (fmap (parseURI . T.unpack . decodeUtf8) clientRedirect)) of

If this parsing succeeds, we register the client (`with oAuth $ register`) and
inform the user that the registration was successful.

>     (Just name, Just cid, Just redir) -> do
>         with oAuth $ register Client { clientId = decodeUtf8 cid
>                                      , clientRedirectUri = redir
>                                      , clientName = decodeUtf8 name
>                                      }
>         blaze $ pageTemplate "Register Client" $ do
>             H.h1 "Client Registered"
>             H.p "Client successfully registered"

Otherwise, we present a form to submit.

>     _ ->
>       blaze $ pageTemplate "Register Client" $ do
>         H.h1 "Register Client"
>         H.form $ do
>             H.p $ do
>                 H.label "Client ID:"
>                 H.input ! A.name "client-id"
>             H.p $ do
>                 H.label "Redirection URI:"
>                 H.input ! A.name "redirect-uri"
>             H.input ! A.type_ "submit" ! A.value "Register"

Showing Authorization Codes
---------------------------

We also need a handler that will display authorization codes to resource
owners. This is needed because some applications are not web servers, and thus
redirecting them to an authorization code does not make sense. For these
applications, the resource owner needs to copy the authorization code and paste
it into the application.

> showCode :: Code -> Handler App (OAuth scope) ()
> showCode code = blaze $ pageTemplate "Authorization Code" $ do
>   H.h1 "Authorization Code"
>   H.p "Please copy and paste the below code into the calling application"
>   H.input ! A.type_ "text" ! A.value (toValue code)

Authorization Grant Errors
--------------------------

Finally, it is possible that clients issue malformed requests that the OAuth
Snaplet is unable to process. While some of these errors can be delivered
back to the client, some of them cannot (for example, if we are given a request
where the client can't even be identified!). In these cases, we need to present
the error to the resource owner:

> showError :: AuthorizationGrantError -> Handler App (OAuth scope) ()
> showError e = blaze $ pageTemplate "Authorization Grant Error" $ do
>     H.h1 "Authorization Grant Error"
>     H.p "An application requested authorization, but the request could not be parsed."
>     case e of
>         InvalidClientId _ ->
>             H.p "The client identifier could not be parsed"
>         InvalidRedirectionUri _ ->
>             H.p "The redirection URI could not be parsed"
>         MalformedRedirectionUri _ ->
>             H.p "The redirection URI does not form a valid URI"
>         MismatchingRedirectionUri client ->
>             H.p $ toHtml $
>                 "The redirection URI specified does not match the one registered for "
>                     `mappend` clientName client
>         UnknownClient _ ->
>             H.p "The client with the specified ID has not been registered"

Protecting Resources
====================

Protecting resources is done via the `protect` combinator. This combinator
takes a list of scopes that are required (we take the conjunction of all
scopes).

> protected :: Handler App App ()
> protected = with oAuth $ protect [ReadSecretDocuments] $
>     blaze $ pageTemplate "Protected" $ do
>         H.h1 "Secret Information"
>         H.p "The brief case is with Gray Squirrel"

Putting It All Together
=======================

With all handlers declared, we just need to wire our application together. This
is all done inside `SnapletInit`:

> appInit :: SnapletInit App App
> appInit = makeSnaplet "oauth-example" "Example OAuth server" Nothing $ do
>   addRoutes [ ("/protected", protected)
>             , ("/register", registerClient)
>             ]
>   inMem <- initInMemoryOAuth
>   App <$> nestSnaplet "" oAuth (initOAuth doLogin showCode showError inMem)

In this example we've nested the in-memory backend, but you are free to use
other, more persistent backends. You can even developy your own. The oAuth
Snaplet has been nested at the empty path (`""`), which means that we will
have the top-level end points `/token` and `/auth`.

Finally, we use `serveSnaplet` to run the web server:

> main :: IO ()
> main = serveSnaplet defaultConfig appInit

--------------------------

Appendix
========

`pageTemplate`
--------------

This is a simple `H.Html` combinator to provide a common page layout.

> pageTemplate :: H.Html -> H.Html -> H.Html
> pageTemplate title body = do
>     H.docType
>     H.html $ do
>         H.head $ H.title title
>         H.body body
