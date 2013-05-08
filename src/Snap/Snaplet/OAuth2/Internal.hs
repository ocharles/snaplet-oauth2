{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE CPP #-}

module Snap.Snaplet.OAuth2.Internal
    ( AccessToken(..)
    , Code
    , AccessTokenType(..)
    , Client(..)
    )
    where

--------------------------------------------------------------------------------
import Data.Text (Text)
import Data.Time (UTCTime)

import qualified Data.Set as Set
import qualified Network.URI as URI

--------------------------------------------------------------------------------
-- | The type of both authorization request tokens and access tokens.
type Code = Text


--------------------------------------------------------------------------------
data AccessToken scope = AccessToken
  { accessToken :: Code
  , accessTokenType :: AccessTokenType
  , accessTokenExpiresAt :: UTCTime
  , accessTokenRefreshToken :: Code
  , accessTokenClient :: Client
  , accessTokenScope :: Set.Set scope
  } deriving (Eq, Ord)


--------------------------------------------------------------------------------
data AccessTokenType = Example | Bearer
  deriving (Eq, Ord, Show)


--------------------------------------------------------------------------------

#if !MIN_VERSION_network(2,4,0)
-- Ord instances were introduced in network-2.4.0.0
deriving instance Ord URI.URIAuth
deriving instance Ord URI.URI
#endif

data Client = Client { clientRedirectUri :: URI.URI
                     , clientId :: Text
                     , clientName :: Text
                     }
  deriving (Eq, Ord, Show)

