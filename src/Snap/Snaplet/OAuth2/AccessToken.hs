{-# LANGUAGE OverloadedStrings #-}
module Snap.Snaplet.OAuth2.AccessToken
    ( ErrorCode(..)
    ) where

--------------------------------------------------------------------------------
import Data.Aeson (ToJSON(..))
import Data.Text (Text)


--------------------------------------------------------------------------------
data ErrorCode
  = InvalidRequest | InvalidClient | InvalidGrant
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
instance ToJSON ErrorCode where
  toJSON = toJSON . show

