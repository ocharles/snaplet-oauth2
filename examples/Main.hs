{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module Main where

import Control.Applicative
import Data.Lens.Template
import Data.Text
import Snap.Core
import Snap.Http.Server
import Snap.Snaplet
import Snap.Snaplet.OAuth2

-- First we define our application as normal, nesting a 'OAuth' 'Snaplet'.
data App = App { _oAuth :: Snaplet OAuth }
makeLenses [''App]

-- This handler what normally display a login form, and require users to
-- login to the website and then grant access to a client. In this example
-- we'll just assume a sucessful login, and that request was granted.
doLogin :: AuthorizationRequest -> Handler App OAuth AuthorizationResult
doLogin authReq = return Success

-- A handler to present an authorization request 'Code' to a client,
-- once it has been granted. This is useful for pasting into command line
-- applications, for example.
showCode :: Code -> Handler App OAuth ()
showCode = writeText

-- Our protected resource, that requires OAuth authentication.
protected :: Handler App App ()
protected = with oAuth $ protect deny $ do
  writeText "Congragulationing! This resource is protected"
  where deny = do writeText "Denied"
                  modifyResponse (setResponseCode 500)

-- A simple initializer for our application
appInit :: SnapletInit App App
appInit = makeSnaplet "oauth-example" "Example OAuth server" Nothing $ do
  addRoutes [ ("/protected", protected) ]
  App <$> nestSnaplet "" oAuth (oAuthInit doLogin showCode)

-- And serve it!
main = serveSnaplet defaultConfig appInit
