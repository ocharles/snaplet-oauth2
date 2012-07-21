{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module Main where

import Prelude hiding (unlines)

import Control.Applicative
import Data.Lens.Template
import Data.Text
import Data.Text.Encoding (decodeUtf8)
import Snap.Blaze
import Snap.Core
import Snap.Http.Server
import Snap.Snaplet
import Snap.Snaplet.OAuth2

import Text.Blaze.Html5 ((!), toValue)
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A

-- First we define our application as normal, nesting a 'OAuth' 'Snaplet'.
data App = App { _oAuth :: Snaplet OAuth }
makeLenses [''App]

-- This handler will normally display a login form, and require users to
-- login to the website and then grant access to a client. In this example
-- we'll display 2 buttons - one to deny a request and one to grant it.
doLogin :: AuthorizationRequest -> Handler App OAuth AuthorizationResult
doLogin authReq = do
  possibleResponse <- getParam "response"
  case possibleResponse of
    Just "Deny"      -> return Denied
    Just "Authorize" -> return Granted
    _                -> do
      currentUrl <- withRequest (return . decodeUtf8 . rqURI)
      blaze $ do
        H.docType
        H.html $ do
          H.head $ H.title "Grant access?"
          H.body $ do
            H.h1 "Authorization Request"
            H.p "Do you wish to allow access to protected documents?"
            H.form ! A.method "POST" $ do
              H.input ! A.type_ "submit" ! A.name "response" ! A.value "Authorize"
              H.input ! A.type_ "submit" ! A.name "response" ! A.value "Deny"
      return InProgress

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
  App <$> nestSnaplet "" oAuth (initInMemoryOAuth doLogin showCode)

-- And serve it!
main = serveSnaplet defaultConfig appInit
