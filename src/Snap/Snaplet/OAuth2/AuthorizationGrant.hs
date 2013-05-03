module Snap.Snaplet.OAuth2.AuthorizationGrant
    ( ErrorCode(..) ) where

data ErrorCode
  = InvalidRequest | UnauthorizedClient | AccessDenied
  | UnsupportedResponseType | InvalidScope | ServerError
  | TemporarilyUnavailable
 deriving (Show)
