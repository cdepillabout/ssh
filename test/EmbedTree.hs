{-# LANGUAGE TemplateHaskell, TupleSections #-}
module EmbedTree where

import Control.Applicative ((<$>))
import qualified Data.Map as Map
import Data.Map (Map)

import Instances.TH.Lift ()

import Language.Haskell.TH
import Language.Haskell.TH.Syntax

import PseudoMacros

import System.Directory
  (doesFileExist, doesDirectoryExist
  ,getDirectoryContents
  )
import System.FilePath (takeDirectory, (</>))

data Entry = File String | Directory (Map String Entry)

getFile :: Entry -> String
getFile (File contents) = contents
getFile (Directory _) = error $ "getFile: found a directory"

getDirectory :: Entry -> Map String Entry
getDirectory (File _) = error $ "getDirectory: found a file"
getDirectory (Directory contents) = contents

getEntry :: String -> Map String Entry -> Entry
getEntry name entries =
  case Map.lookup name entries of
    Nothing -> error $ "getEntry: " ++ name ++ " not found"
    Just v -> v

instance Lift Entry where
  lift (File contents) = AppE (ConE 'File) <$> [|contents|]
  lift (Directory entries) = AppE (ConE 'Directory) <$> [|entries|]

readTree :: FilePath -> IO Entry
readTree path = do
  isFile <- doesFileExist path
  if isFile
    then File <$> readFile path
    else do
      isDirectory <- doesDirectoryExist path
      if isDirectory
        then do
          entries <- filter (`notElem` [".", ".."]) <$> getDirectoryContents path
          Directory . Map.fromList <$> mapM (\entry -> (entry,) <$> readTree (path </> entry)) entries
        else fail $ path ++ " is not a file or directory"

embedTree :: FilePath -> ExpQ
embedTree relPath = do
    t <- runIO (readTree (takeDirectory $__FILE__ </> relPath))
    [|t|]
