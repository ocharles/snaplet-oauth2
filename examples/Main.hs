{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
--------------------------------------------------------------------------------
module Main where

--------------------------------------------------------------------------------
import Prelude hiding (unlines)


--------------------------------------------------------------------------------
import Control.Applicative
import Control.Lens.TH
import Control.Monad (forM_, join)
import Data.Monoid (mappend)
import Data.Text.Encoding (decodeUtf8)
import Network.URI
import Snap.Blaze
import Snap.Core
import Snap.Http.Server
import Snap.Snaplet
import Snap.Snaplet.OAuth2
import Text.Blaze.Html5 ((!), toHtml, toValue)


--------------------------------------------------------------------------------
import qualified Data.Text as T
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A


--------------------------------------------------------------------------------
-- Our application can define whatever scope it needs.
data AppScope = ReadSecretDocuments | CreateDocuments
  deriving (Enum, Eq, Ord, Show)

-- We need to define an isomorphism between the custom scope and 'Text'.
instance Scope AppScope where
    parseScope "read" = Just ReadSecretDocuments
    parseScope "create" = Just CreateDocuments
    parseScope _      = Nothing

    showScope ReadSecretDocuments = "read"
    showScope CreateDocuments = "create"


--------------------------------------------------------------------------------
-- We define our application as normal, nesting an 'OAuth' 'Snaplet'.
data App = App { _oAuth :: Snaplet (OAuth AppScope) }
makeLenses ''App


--------------------------------------------------------------------------------
-- This handler will normally display a login form, and require users to
-- login to the website and then grant access to a client. In this example
-- we'll display 2 buttons - one to deny a request and one to grant it.
--
-- Most applications will need to extend this to perform some actual
-- authentication, for example using 'Snap.Snaplet.Auth'.
doLogin :: Client -> [AppScope] -> Handler App (OAuth AppScope) AuthorizationResult
doLogin client scope = do
  possibleResponse <- getParam "response"
  case possibleResponse of
    Just "Deny" -> do
      blaze $ pageTemplate "Access Denied" $ do
        H.h1 "Access Denied"
        H.p "Access has been denied"
      return Denied

    Just "Authorize" -> do
        blaze $ pageTemplate "Access Granted" $ do
            H.h1 "Access Granted"
            H.p "Access has been granted"
        return Granted

    _ -> do
      currentUrl <- withRequest (return . decodeUtf8 . rqURI)
      blaze $ pageTemplate "Grant access?" $ do
        H.h1 "Authorization Request"
        H.p "Do you wish to allow access to protected documents?"
        H.p "The following access is being requested"
        H.ul $ forM_ scope $ \scope -> H.li $ do
            case scope of
                ReadSecretDocuments -> "Read secret documents"
                CreateDocuments -> "Create new documents"
        H.form ! A.method "POST" $ do
          H.input ! A.type_ "submit" ! A.name "response" ! A.value "Authorize"
          H.input ! A.type_ "submit" ! A.name "response" ! A.value "Deny"
      return InProgress

--------------------------------------------------------------------------------
-- This handler will let clients register
registerClient = do
  clientRedirect <- getParam "redirect-uri"
  clientId <- getParam "client-id"
  clientName <- getParam "name"
  case (clientName, clientId, join (fmap (parseURI . T.unpack . decodeUtf8) clientRedirect)) of
    (Just name, Just cid, Just redir) -> do
        with oAuth $ register Client { clientId = decodeUtf8 cid
                                     , clientRedirectUri = redir
                                     , clientName = decodeUtf8 name
                                     }
        blaze $ pageTemplate "Register Client" $ do
            H.h1 "Client Registered"
            H.p "Client successfully registered"
    _ ->
      blaze $ pageTemplate "Register Client" $ do
        H.h1 "Register Client"
        H.form $ do
            H.p $ do
                H.label "Client ID:"
                H.input ! A.name "client-id"
            H.p $ do
                H.label "Redirection URI:"
                H.input ! A.name "redirect-uri"
            H.input ! A.type_ "submit" ! A.value "Register"


--------------------------------------------------------------------------------
-- A handler to present an authorization request 'Code' to a client,
-- once it has been granted. This is useful for pasting into command line
-- applications, for example.
showCode :: Code -> Handler App (OAuth scope) ()
showCode code = blaze $ pageTemplate "Authorization Code" $ do
  H.h1 "Authorization Code"
  H.p "Please copy and paste the below code into the calling application"
  H.input ! A.type_ "text" ! A.value (toValue code)


--------------------------------------------------------------------------------
-- A handler to present authorization grant errors
showError :: AuthorizationGrantError -> Handler App (OAuth scope) ()
showError e = blaze $ pageTemplate "Authorization Grant Error" $ do
    H.h1 "Authorization Grant Error"
    H.p "An application requested authorization, but the request could not be parsed."
    case e of
        InvalidClientId _ ->
            H.p "The client identifier could not be parsed"
        InvalidRedirectionUri _ ->
            H.p "The redirection URI could not be parsed"
        MalformedRedirectionUri _ ->
            H.p "The redirection URI does not form a valid URI"
        MismatchingRedirectionUri client ->
            H.p $ toHtml $
                "The redirection URI specified does not match the one registered for "
                    `mappend` clientName client
        UnknownClient _ ->
            H.p "The client with the specified ID has not been registered"


--------------------------------------------------------------------------------
-- Our protected resource that requires authentication.
protected :: Handler App App ()
protected = with oAuth $ protect [ReadSecretDocuments] deny $
    blaze $ pageTemplate "Protected" $ do
        H.h1 "Secret Information"
        H.p "The brief case is with Gray Squirrel"
  where
    deny = writeText "Denied"


--------------------------------------------------------------------------------
-- A simple initializer for our application. This hooks everything together,
-- telling the OAuth Snaplet how to authorize with resource owners ('doLogin')
-- and how to display authorization codes to end users ('showCode') for them
-- to copy and paste.
appInit :: SnapletInit App App
appInit = makeSnaplet "oauth-example" "Example OAuth server" Nothing $ do
  addRoutes [ ("/protected", protected)
            , ("/register", registerClient)
            ]
  App <$> nestSnaplet "" oAuth (initInMemoryOAuth doLogin showCode showError)


--------------------------------------------------------------------------------
-- And serve it!
main :: IO ()
main = serveSnaplet defaultConfig appInit


--------------------------------------------------------------------------------
-- This stuff isn't so interesting
pageTemplate :: H.Html -> H.Html -> H.Html
pageTemplate title body = do
    H.docType
    H.html $ do
        H.head $ H.title title
        H.body body
