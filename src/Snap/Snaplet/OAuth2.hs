{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Rank2Types #-}
module Snap.Snaplet.OAuth2
    ( -- * Snaplet Definition
      OAuth
    , initInMemoryOAuth

      -- * Authorization Snap.Handlers
    , AuthorizationResult(..)
    , AuthorizationRequest
    , Code
    , authReqClientId
    , authReqRedirectUri
    , authReqScope
    , authReqState

      -- * Defining Protected Resources
    , protect
    ) where


--------------------------------------------------------------------------------
import Control.Applicative ((<$>), (<*>), (<*), pure)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.State.Class (get, gets)
import Control.Monad.Trans (lift)
import Control.Monad (unless)
import Data.Aeson (ToJSON(..), encode, (.=), object)
import Data.Maybe (fromMaybe)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Text (Text, pack)
import Data.Time (UTCTime, addUTCTime, getCurrentTime)
import Data.Tuple (swap)
import Network.URI (isAbsoluteURI, parseAbsoluteURI, uriQuery)
import Network.URL (importParams, exportParams)


--------------------------------------------------------------------------------
import qualified Control.Concurrent.MVar as MVar
import qualified Control.Error as Error
import qualified Control.Monad.Trans.Reader as Reader
import qualified Data.ByteString.Char8 as BS
import qualified Data.IORef as IORef
import qualified Data.Map as Map
import qualified Data.Text as Text
import qualified Snap.Core as Snap
import qualified Snap.Snaplet as Snap
import qualified Snap.Snaplet.Session.Common as Snap


--------------------------------------------------------------------------------
-- | All storage backends for OAuth must implement the following API. See the
-- documentation for each method for various invariants that either MUST or
-- SHOULD be implemented (as defined by RFC-2119).
class OAuthBackend oauth where
    -- | Store an access token that has been granted to a client.
    storeToken :: oauth -> AccessToken -> IO ()

    -- | Store an authorization grant that has been granted to a client.
    storeAuthorizationGrant :: oauth -> AuthorizationGrant -> IO ()

    -- | Retrieve an authorization grant from storage for inspection. This is
    -- used to verify an authorization grant for its validaty against subsequent
    -- client requests.
    --
    -- This function should remove the authorization grant from storage entirely
    -- so that subsequent calls to 'inspectAuthorizationGrant' with the same
    -- parameters return 'Nothing'.
    inspectAuthorizationGrant :: oauth -> Code -> IO (Maybe AuthorizationGrant)

    -- | Attempt to lookup an access token.
    lookupToken :: oauth -> Code -> IO (Maybe AccessToken)


--------------------------------------------------------------------------------
-- | The type of both authorization request tokens and access tokens.
type Code = Text


--------------------------------------------------------------------------------
data InMemoryOAuth = InMemoryOAuth
  { oAuthGranted :: MVar.MVar (Map.Map Code AuthorizationGrant)
  , oAuthAliveTokens :: IORef.IORef (Map.Map Code AccessToken)
  }


--------------------------------------------------------------------------------
instance OAuthBackend InMemoryOAuth where
  storeAuthorizationGrant be grant =
    MVar.modifyMVar_ (oAuthGranted be) $
      return . (Map.insert (authGrantCode grant) grant)

  inspectAuthorizationGrant be code =
    MVar.modifyMVar (oAuthGranted be) $
      return . (swap . Map.updateLookupWithKey (const (const Nothing)) code)

  storeToken be token =
    IORef.modifyIORef (oAuthAliveTokens be) (Map.insert (accessToken token) token)

  lookupToken be token =
    Map.lookup token <$> IORef.readIORef (oAuthAliveTokens be)

--------------------------------------------------------------------------------
-- | The OAuth snaplet. You should nest this inside your application snaplet
-- using 'nestSnaplet' with the 'initInMemoryOAuth' initializer.
data OAuth = forall o. OAuthBackend o => OAuth
  { oAuthBackend :: o
  , oAuthRng :: Snap.RNG
  }

--------------------------------------------------------------------------------
-- | The result of an authorization request.
data AuthorizationResult =
    -- | The resource owner is in the process of granting authorization. There
    -- may be multiple page requests to grant authorization (ie, the user
    -- accidently types invalid input, or uses multifactor authentication).
    InProgress

    -- | The request was not approved.
  | Denied

    -- | The resource owner has granted permission.
  | Granted


--------------------------------------------------------------------------------
-- | Information about an authorization request from a client.
data AuthorizationRequest = AuthorizationRequest
  { -- | The client's unique identifier.
    authReqClientId :: Text

    -- | The (optional) redirection URI to redirect to on success. The OAuth
    -- snaplet will take care of this redirection; you do not need to perform the
    -- redirection yourself.
  , authReqRedirectUri :: Maybe BS.ByteString

    -- | The scope of authorization requested.
  , authReqScope :: Maybe Text

    -- | Any state the client wishes to be associated with the authorization
    -- request.
  , authReqState :: Maybe Text
  }


--------------------------------------------------------------------------------
data AuthorizationGrant = AuthorizationGrant
  { authGrantCode :: Code
  , authGrantExpiresAt :: UTCTime
  , authGrantRedirectUri :: Maybe BS.ByteString
  , authGrantClientId :: Text
  }


--------------------------------------------------------------------------------
data AccessTokenRequest = AccessTokenRequest
  { accessTokenReqCode :: Code
  , accessTokenReqRedirect :: Maybe BS.ByteString
  , accessTokenReqClientId :: Text
  }


--------------------------------------------------------------------------------
data Error = Error { errorCode :: ErrorCode
                   , errorBody :: Text
                   }


--------------------------------------------------------------------------------
data ErrorCode = InvalidRequest | InvalidClient | InvalidGrant
               | UnauthorizedClient | UnsupportedGrantType
               | InvalidScope | AccessDenied


--------------------------------------------------------------------------------
instance Show ErrorCode where
  show c = case c of
    InvalidRequest -> "invalid_request"
    InvalidClient -> "invalid_client"
    InvalidGrant -> "invalid_grant"
    UnauthorizedClient -> "unauthorized_client"
    UnsupportedGrantType -> "unsupported_grant_type"
    InvalidScope -> "invalid_scope"
    AccessDenied -> "access_denied"


--------------------------------------------------------------------------------
instance ToJSON Error where
  toJSON (Error code body) = object [ "error" .= code
                                    , "error_description" .= body
                                    ]


--------------------------------------------------------------------------------
instance ToJSON ErrorCode where
  toJSON = toJSON . show


--------------------------------------------------------------------------------
data AccessToken = AccessToken
  { accessToken :: Code
  , accessTokenType :: AccessTokenType
  , accessTokenExpiresIn :: Int
  , accessTokenRefreshToken :: Code
  , accessTokenClientId :: Text
  } deriving (Eq, Ord)


--------------------------------------------------------------------------------
data AccessTokenType = Example | Bearer
  deriving (Eq, Ord, Show)


--------------------------------------------------------------------------------
instance ToJSON AccessToken where
  toJSON at = object [ "access_token" .= accessToken at
                     , "token_type" .= show (accessTokenType at)
                     , "expires_in" .= show (accessTokenExpiresIn at)
                     , "refresh_token" .= accessTokenRefreshToken at
                     ]


--------------------------------------------------------------------------------
authorizationRequest :: (AuthorizationRequest -> Snap.Handler b OAuth AuthorizationResult)
                     -> (Code -> Snap.Handler b OAuth ())
                     -> Snap.Handler b OAuth ()
authorizationRequest authSnap genericDisplay = Error.eitherT id authReqStored $ do
    -- Parse the request for validity.
    authReq <- runParamParser Snap.getQueryParams parseAuthorizationRequestParameters
                 Snap.writeText

    -- Confirm with the resource owner that they wish to grant this request.
    verifyWithResourceOwner authReq

    -- Produce a new authorization code.
    code <- lift newCSRFToken
    now <- liftIO getCurrentTime
    let authGrant = AuthorizationGrant
          { authGrantCode = code
          , authGrantExpiresAt = addUTCTime 600 now
          , authGrantRedirectUri = authReqRedirectUri authReq
          , authGrantClientId = authReqClientId authReq
          }
    lift (withBackend' $ \be -> storeAuthorizationGrant be authGrant) >>= liftIO

    return (code, authReq)

  where
    authReqStored (code, authReq) =
      case authReqRedirectUri authReq of
        Just "urn:ietf:wg:oauth:2.0:oob" -> genericDisplay code
        Just uri -> augmentedRedirect uri [ ("code", Text.unpack code) ]
        Nothing -> genericDisplay code

    augmentedRedirect uri params =
      -- We have already validated this in the request parser.
      let uri' = fromMaybe (error "Invalid redirect") $ parseAbsoluteURI $
                   Text.unpack $ decodeUtf8 uri
      in Snap.redirect $ encodeUtf8 $ pack $ show $ uri'
           { uriQuery = ("?" ++) $ exportParams $
                        (fromMaybe [] $ importParams $ uriQuery uri') ++
                        params }

    verifyWithResourceOwner authReq = do
      authResult <- lift $ authSnap authReq
      case authResult of
        Granted    -> Error.right ()
        InProgress -> lift $ Snap.getResponse >>= Snap.finishWith
        Denied     -> Error.left $ redirectError authReq $ Error AccessDenied
                        "The resource owner has denied this request"

    redirectError authReq oAuthError = do
      case authReqRedirectUri authReq of
        Just uri -> augmentedRedirect uri
                      [ ("error", show $ errorCode oAuthError)
                      , ("error_description", Text.unpack $ errorBody oAuthError)
                      ]


--------------------------------------------------------------------------------
requestToken :: Snap.Handler b OAuth ()
requestToken = Error.eitherT jsonError success $ do
    -- Parse the request into a AccessTokenRequest.
    tokenReq <- runParamParser Snap.getPostParams parseTokenRequestParameters
                  (Error InvalidRequest)

    -- Find the authorization grant, failing if it can't be found.
    -- Error.EitherT $ (fmap.fmap) (Error.note (notFound tokenReq)) $
    grant <- do
      ioGrant <- lift $ withBackend' $ \be -> inspectAuthorizationGrant be
                   (accessTokenReqCode tokenReq)
      Error.EitherT $ fmap (Error.note $ notFound tokenReq) $
        liftIO ioGrant

    -- Require that the current redirect URL matches the one an authorization
    -- token was granted to.
    (authGrantRedirectUri grant == accessTokenReqRedirect tokenReq)
      `orFail` mismatchedClientRedirect

    -- Require that the client IDs match.
    (accessTokenReqClientId tokenReq == authGrantClientId grant)
      `orFail` mismatchedClient

    -- Require that the token has not expired.
    now <- liftIO getCurrentTime
    (now <= authGrantExpiresAt grant) `orFail` expired

    -- All good, grant a new access token!
    token <- lift newCSRFToken
    let grantedAccessToken = AccessToken
          { accessToken = token
          , accessTokenType = Bearer
          , accessTokenExpiresIn = 3600
          , accessTokenRefreshToken = token
          , accessTokenClientId = accessTokenReqClientId tokenReq
          }

    -- Store the granted access token, handling backend failure.
    lift (withBackend' $ \be -> storeToken be grantedAccessToken) >>= liftIO
    return grantedAccessToken

  where
    success :: AccessToken -> Snap.Handler b OAuth ()
    success = writeJSON

    notFound tokenReq = Error InvalidGrant
      (Text.append "Authorization request not found: " $
         accessTokenReqCode tokenReq)

    expired = Error InvalidGrant
      "This authorization grant has expired"

    mismatchedClient = Error InvalidGrant
      "This authorization token was issued to another client"

    mismatchedClientRedirect = Error InvalidGrant $
      Text.append "The redirection URL does not match the redirection URL in "
        "the original authorization grant"

    True  `orFail` _ = return ()
    False `orFail` a = Error.left a

    jsonError e = Snap.modifyResponse (Snap.setResponseCode 400) >> writeJSON e

    writeJSON :: (ToJSON a, Snap.MonadSnap m) => a -> m ()
    writeJSON j = do
      Snap.modifyResponse $ Snap.setContentType "application/json"
      Snap.writeLBS $ encode j


--------------------------------------------------------------------------------
withBackend :: (forall o. (OAuthBackend o) => o -> Snap.Handler b OAuth a)
            -> Snap.Handler b OAuth a
withBackend a = do (OAuth be _) <- get
                   a be


--------------------------------------------------------------------------------
withBackend' :: (forall o. (OAuthBackend o) => o -> a)
             -> Snap.Handler b OAuth a
withBackend' a = do (OAuth be _) <- get
                    return $ a be


--------------------------------------------------------------------------------
newCSRFToken :: Snap.Handler b OAuth Text
newCSRFToken = gets oAuthRng >>= liftIO . Snap.mkCSRFToken


--------------------------------------------------------------------------------
-- | Initialize the OAuth snaplet, providing handlers to do actual
-- authentication, and a handler to display an authorization request token to
-- clients who are not web servers (ie, cannot handle redirections).
initInMemoryOAuth :: (AuthorizationRequest
                  -> Snap.Handler b OAuth AuthorizationResult)
                  -- ^ A handler to perform authorization against the server.
                  -> (Code -> Snap.Handler b OAuth ())
                  -- ^ A handler to display an authorization request 'Code' to
                  -- clients.
                  -> Snap.SnapletInit b OAuth
initInMemoryOAuth authSnap genericCodeDisplay =
  Snap.makeSnaplet "OAuth" "OAuth 2 Authentication" Nothing $ do
    Snap.addRoutes
      [ ("/auth", authorizationRequest authSnap genericCodeDisplay)
      , ("/token", requestToken)
      ]

    codeStore <- liftIO $ MVar.newMVar Map.empty
    aliveTokens <- liftIO $ IORef.newIORef Map.empty
    rng <- liftIO Snap.mkRNG

    return $ OAuth (InMemoryOAuth codeStore aliveTokens) rng


--------------------------------------------------------------------------------
-- | Protect a resource by requiring valid OAuth tokens in the request header
-- before running the body of the handler.
protect :: Snap.Handler b OAuth ()
        -- ^ A handler to run if the client is /not/ authorized
        -> Snap.Handler b OAuth ()
        -- ^ The handler to run on sucessful authentication.
        -> Snap.Handler b OAuth ()
protect failure h =
    Error.maybeT failure (const h) $ do
        ["Bearer", reqToken] <-
            Error.MaybeT $ fmap (take 2 . Text.words . decodeUtf8) <$>
                Snap.withRequest (return . Snap.getHeader "Authorization")

        Error.MaybeT $ withBackend (\be -> liftIO $ lookupToken be reqToken)


--------------------------------------------------------------------------------
-- | Parameter parsers are a combination of 'Reader.Reader'/'Error.EitherT'
-- monads. The environment is a 'Snap.Params' map (from Snap), and
-- 'Error.EitherT' allows us to fail validation at any point. Combinators
-- 'require' and 'optional' take a parameter key, and a validation routine.
type ParameterParser a = Error.EitherT Text (Reader.Reader Snap.Params) a


--------------------------------------------------------------------------------
param :: String -> Reader.Reader Snap.Params (Maybe BS.ByteString)
param p = fmap head . Map.lookup (BS.pack p) <$> Reader.ask


--------------------------------------------------------------------------------
require :: String -> (BS.ByteString -> Bool) -> Text
        -> ParameterParser BS.ByteString
require name predicate e = do
  v <- Error.EitherT $
         Error.note (Text.append (pack name) " is required") <$> param name
  unless (predicate v) $ Error.left e
  return v


--------------------------------------------------------------------------------
optional :: String -> (BS.ByteString -> Bool) -> Text
         -> ParameterParser (Maybe BS.ByteString)
optional name predicate e = do
  v <- lift (param name)
  case v of
    Just v' -> if predicate v' then return v else Error.left e
    Nothing -> return Nothing


--------------------------------------------------------------------------------
parseAuthorizationRequestParameters :: ParameterParser AuthorizationRequest
parseAuthorizationRequestParameters = pure AuthorizationRequest
  <*  require "response_type" (== "code") "response_type must be code"
  <*> clientIdField
  <*> redirectUriField
  <*> fmap (fmap decodeUtf8) (optional "scope" validScope "")
  <*> fmap (fmap decodeUtf8) (optional "state" (const True) "")


--------------------------------------------------------------------------------
parseTokenRequestParameters :: ParameterParser AccessTokenRequest
parseTokenRequestParameters = pure AccessTokenRequest
  <*  require "grant_type" (== "authorization_code")
        "grant_type must be authorization_code"
  <*> fmap decodeUtf8 (require "code" (const True) "")
  <*> redirectUriField
  <*> clientIdField


--------------------------------------------------------------------------------
clientIdField :: ParameterParser Text
clientIdField = fmap decodeUtf8 (require "client_id" (const True) "")


--------------------------------------------------------------------------------
redirectUriField :: ParameterParser (Maybe BS.ByteString)
redirectUriField = optional "redirect_uri" validRedirectUri
  (Text.append "redirect_uri must be an absolute URI and not contain a "
               "fragment component")


--------------------------------------------------------------------------------
validRedirectUri :: BS.ByteString -> Bool
validRedirectUri = isAbsoluteURI . Text.unpack . decodeUtf8


--------------------------------------------------------------------------------
validScope :: BS.ByteString -> Bool
validScope _  = True


--------------------------------------------------------------------------------
runParamParser :: Snap.MonadSnap m => m Snap.Params -> ParameterParser a -> (Text -> e)
               -> Error.EitherT e m a
runParamParser params parser errorFmt = do
  qps <- lift params
  case Reader.runReader (Error.runEitherT parser) qps of
    Left e -> Error.left (errorFmt e)
    Right a -> Error.right a
