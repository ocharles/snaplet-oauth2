{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Rank2Types #-}
module Snap.Snaplet.OAuth2
       ( -- * Snaplet Definition
         OAuth
       , initInMemoryOAuth

         -- * Authorization Handlers
       , AuthorizationResult(..)
       , AuthorizationRequest
       , Code
       , authReqClientId, authReqRedirectUri
       , authReqScope, authReqState

         -- * Defining Protected Resources
       , protect
       ) where

import Control.Applicative ((<$>), (<*>), (<*), pure)
import Control.Error.Util
import Control.Monad (unless)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.Reader
import Control.Monad.State.Class (get, gets)
import Control.Monad.Trans (lift)
import Control.Monad.Trans.Either
import Data.Aeson (ToJSON(..), encode, (.=), object)
import qualified Data.ByteString.Char8 as BS
import qualified Data.Map as Map
import qualified Data.Set as Set
import qualified Data.Text as Text
import Data.IORef
import Data.Text (Text, pack)
import Data.Text.Encoding (decodeUtf8)
import Data.Time (UTCTime, addUTCTime, getCurrentTime)
import Snap.Core
import Snap.Snaplet
import Snap.Snaplet.Session.Common

--------------------------------------------------------------------------------
-- | All storage backends for OAuth must implement the following API. See the
-- documentation for each method for various invariants that either MUST or
-- SHOULD be implemented (as defined by RFC-2119).
class OAuthBackend oauth where
  -- | Store an access token that has been granted to a client.
  storeToken :: oauth -> AccessToken -> IO ()

  -- | Store an authorization grant that has been granted to a client.
  storeAuthorizationGrant :: oauth -> AuthorizationGrant -> IO ()

  -- | Retrieve an authorization grant from storage for inspection. This is used
  -- to verify an authorization grant for its validaty against subsequent client
  -- requests.
  --
  -- It is important to ensure that this authorization grant is somehow locked
  -- so that no other threads can inspect this authorization grant. Failing to
  -- lock the authorization grant can allow multiple clients to consume an
  -- authorization grant at the same time, which is forbidden.
  inspectAuthorizationGrant :: oauth -> Code -> IO (Maybe AuthorizationGrant)

--------------------------------------------------------------------------------
-- | The type of both authorization request tokens and access tokens.
type Code = Text

--------------------------------------------------------------------------------
data InMemoryOAuth = InMemoryOAuth
  { oAuthGranted :: IORef (Map.Map Code AuthorizationGrant)
  , oAuthAliveTokens :: IORef (Set.Set AccessToken)
  }

instance OAuthBackend InMemoryOAuth where
  storeAuthorizationGrant be grant =
    modifyIORef (oAuthGranted be) (Map.insert (authGrantCode grant) grant)

  inspectAuthorizationGrant be code =
    Map.lookup code <$> readIORef (oAuthGranted be)

  storeToken be token =
    modifyIORef (oAuthAliveTokens be) (Set.insert token)

{-| The OAuth snaplet. You should nest this inside your application snaplet
using 'nestSnaplet' with the 'initInMemoryOAuth' initializer. -}
data OAuth = forall o. OAuthBackend o => OAuth
  { oAuthBackend :: o
  , oAuthRng :: RNG
  }

--------------------------------------------------------------------------------
{-| The result of an authorization request. -}
data AuthorizationResult =
    {-| The resource owner is in the process of granting authorization. There
may be multiple page requests to grant authorization (ie, the user accidently
types invalid input, or uses multifactor authentication). -}
    InProgress

    -- | The request was not approved. The associated string indicates why.
  | Failed String

    -- | Authorization succeeded.
  | Success

--------------------------------------------------------------------------------
-- | Information about an authorization request from a client.
data AuthorizationRequest = AuthorizationRequest
  { -- | The client's unique identifier.
    authReqClientId :: Text

    {-| The (optional) redirection URI to redirect to on success. The OAuth
snaplet will take care of this redirection; you do not need to perform the
redirection yourself. -}
  , authReqRedirectUri :: Maybe BS.ByteString

    -- | The scope of authorization requested.
  , authReqScope :: Maybe Text

    {-| Any state the client wishes to be associated with the authorization
request. -}
  , authReqState :: Maybe Text
  }

--------------------------------------------------------------------------------
data AuthorizationGrant = AuthorizationGrant
  { authGrantCode :: Code
  , authGrantExpiresAt :: UTCTime
  , authGrantRedirectUri :: Maybe BS.ByteString
  }

--------------------------------------------------------------------------------
data AccessTokenRequest = AccessTokenRequest
  { accessTokenCode :: Code
  , accessTokenRedirect :: Maybe BS.ByteString
  }

--------------------------------------------------------------------------------
data AccessTokenError = AccessTokenError
  { accessTokenErrorCode :: AccessTokenErrorCode
  , accessTokenErrorBody :: Text
  }

data AccessTokenErrorCode = InvalidRequest | InvalidClient | InvalidGrant
                          | UnauthorizedClient | UnsupportedGrantType
                          | InvalidScope

instance ToJSON AccessTokenError where
  toJSON (AccessTokenError code body) = object [ "error" .= code
                                               , "error_description" .= body
                                               ]

instance ToJSON AccessTokenErrorCode where
  toJSON = toJSON . asText
    where
      asText :: AccessTokenErrorCode -> Text
      asText c = case c of
        InvalidRequest -> "invalid_request"
        InvalidClient -> "invalid_client"
        InvalidGrant -> "invalid_grant"
        UnauthorizedClient -> "unauthorized_client"
        UnsupportedGrantType -> "unsupported_grant_type"
        InvalidScope -> "invalid_scope"

--------------------------------------------------------------------------------
data AccessToken = AccessToken
  { accessToken :: Code
  , accessTokenType :: AccessTokenType
  , accessTokenExpiresIn :: Int
  , accessTokenRefreshToken :: Code
  } deriving (Eq, Ord)

data AccessTokenType = Example | Bearer
  deriving (Eq, Ord, Show)

instance ToJSON AccessToken where
  toJSON at = object [ "access_token" .= accessToken at
                     , "token_type" .= show (accessTokenType at)
                     , "expires_in" .= show (accessTokenExpiresIn at)
                     , "refresh_token" .= accessTokenRefreshToken at
                     ]

--------------------------------------------------------------------------------
authorizationRequest :: (AuthorizationRequest
                     -> Handler b OAuth AuthorizationResult)
                     -> (Code -> Handler b OAuth ())
                     -> Handler b OAuth ()
authorizationRequest authHandler genericDisplay = eitherT id authReqStored $ do
    -- Parse the request for validity.
    authReq <- runParamParser getQueryParams parseAuthorizationRequestParameters

    -- Confirm with the resource owner that they wish to grant this request.
    verifyWithResourceOwner authReq

    -- Produce a new authorization code.
    code <- lift newCSRFToken
    now <- liftIO getCurrentTime
    let authGrant = AuthorizationGrant
          { authGrantCode = code
          , authGrantExpiresAt = addUTCTime 600 now
          , authGrantRedirectUri = authReqRedirectUri authReq
          }
    lift (withBackend' $ \be -> storeAuthorizationGrant be authGrant) >>= liftIO

    return (code, authReq)
  where
    authReqStored (code, authReq) =
      case authReqRedirectUri authReq of
        Just "urn:ietf:wg:oauth:2.0:oob" -> genericDisplay code
        Just uri -> error "Redirect to a URI is not yet supported"
        Nothing -> genericDisplay code

    verifyWithResourceOwner authReq = do
      authResult <- lift $ authHandler authReq
      case authResult of
        Success -> return ()
        InProgress -> left $ return ()

--------------------------------------------------------------------------------
requestToken :: Handler b OAuth ()
requestToken = eitherT id writeJSON $ do
    -- Parse the request into a AccessTokenRequest.
    tokenReq <- runParamParser getPostParams parseTokenRequestParameters

    -- Find the authorization grant, failing if it can't be found.
    grant <- noteT (notFound tokenReq) . liftMaybe =<< liftIO =<< lift
               (withBackend' $
                  \be -> inspectAuthorizationGrant be (accessTokenCode tokenReq))

    -- Require that the current redirect URL matches the one an authorization
    -- token was granted to.
    (authGrantRedirectUri grant == accessTokenRedirect tokenReq)
      `orFail` mismatchedClientRedirect

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
          }

    -- Store the granted access token, handling backend failure.
    lift (withBackend' $ \be -> storeToken be grantedAccessToken) >>= liftIO

  where
    writeJSON :: (ToJSON a, MonadSnap m) => a -> m ()
    writeJSON = writeLBS . encode

    notFound tokenReq = do
      modifyResponse (setResponseCode 400)
      writeText $ Text.append (pack "Authorization request not found: ")
                              (accessTokenCode tokenReq)

    mismatchedClientRedirect = return ()

    orFail True _ = return ()
    orFail False a = left a

    expired = do
      modifyResponse (setResponseCode 400)
      writeJSON $
        AccessTokenError InvalidGrant "This authorization grant has expired"

withBackend :: (forall o. (OAuthBackend o) => o -> Handler b OAuth a)
            -> Handler b OAuth a
withBackend a = do (OAuth be _) <- get
                   a be

withBackend' :: (forall o. (OAuthBackend o) => o -> a)
             -> Handler b OAuth a
withBackend' a = do (OAuth be _) <- get
                    return $ a be

newCSRFToken :: Handler b OAuth Text
newCSRFToken = gets oAuthRng >>= liftIO . mkCSRFToken

--------------------------------------------------------------------------------
-- | Initialize the OAuth snaplet, providing handlers to do actual
-- authentication, and a handler to display an authorization request token to
-- clients who are not web servers (ie, cannot handle redirections).
initInMemoryOAuth :: (AuthorizationRequest
                  -> Handler b OAuth AuthorizationResult)
                  -- ^ A handler to perform authorization against the server.
                  -> (Code -> Handler b OAuth ())
                  -- ^ A handler to display an authorization request 'Code' to
                  -- clients.
                  -> SnapletInit b OAuth
initInMemoryOAuth authHandler genericCodeDisplay =
  makeSnaplet "OAuth" "OAuth 2 Authentication" Nothing $ do
    addRoutes [ ("/auth", authorizationRequest authHandler genericCodeDisplay)
              , ("/token", requestToken)
              ]
    codeStore <- liftIO $ newIORef Map.empty
    aliveTokens <- liftIO $ newIORef Set.empty
    rng <- liftIO mkRNG
    return $ OAuth (InMemoryOAuth codeStore aliveTokens) rng

--------------------------------------------------------------------------------
-- | Protect a resource by requiring valid OAuth tokens in the request header
-- before running the body of the handler.
protect :: Handler b OAuth ()
        -- ^ A handler to run if the client is /not/ authorized
        -> Handler b OAuth ()
        -- ^ The handler to run on sucessful authentication.
        -> Handler b OAuth ()
protect failure h = do
  authHead <- fmap (take 2 . BS.words) <$>
                withRequest (return . getHeader "Authorization")
  case authHead of
    Just ["Bearer", token] -> h
    _ -> failure

--------------------------------------------------------------------------------
{- Parameter parsers are a combination of 'Reader'/'EitherT' monads. The
environment is a 'Params' map (from Snap), and 'EitherT' allows us to fail
validation at any point. Combinators 'require' and 'optional' take a parameter
key, and a validation routine.  -}

type ParameterParser a = EitherT String (Reader Params) a

param :: String -> ParameterParser (Maybe BS.ByteString)
param p = fmap head . Map.lookup (BS.pack p) <$> lift ask

require :: String -> (BS.ByteString -> Bool) -> String
        -> ParameterParser BS.ByteString
require name predicate e = do
  v <- param name >>= noteT (name ++ " is required") . liftMaybe
  unless (predicate v) $ left e
  return v

optional :: String -> (BS.ByteString -> Bool) -> String
         -> ParameterParser (Maybe BS.ByteString)
optional name predicate e = do
  v <- param name
  case v of
    Just v' -> if predicate v' then return v else left e
    Nothing -> return Nothing

parseAuthorizationRequestParameters :: ParameterParser AuthorizationRequest
parseAuthorizationRequestParameters = pure AuthorizationRequest
  <*  require "response_type" (== "code") "response_type must be code"
  <*> fmap decodeUtf8 (require "client_id" (const True) "")
  <*> optional "redirect_uri" validRedirectUri
        ("redirect_uri must be an absolute URI and not contain a " ++
         "fragment component")
  <*> fmap (fmap decodeUtf8) (optional "scope" validScope "")
  <*> fmap (fmap decodeUtf8) (optional "state" (const True) "")

parseTokenRequestParameters :: ParameterParser AccessTokenRequest
parseTokenRequestParameters = pure AccessTokenRequest
  <*  require "grant_type" (== "authorization_code")
        "grant_type must be authorization_code"
  <*> fmap decodeUtf8 (require "code" (const True) "")
  <*> optional "redirect_uri" validRedirectUri
        ("redirect_uri must be an absolute URI and not contain a " ++
         "fragment component")

validRedirectUri _ = True
validScope _  = True

runParamParser :: MonadSnap m => m Params -> ParameterParser a
               -> EitherT (m ()) m a
runParamParser params parser = do
  qps <- lift params
  case runReader (runEitherT parser) qps of
    Left e -> left (writeText $ pack e)
    Right a -> right a
