{-# LANGUAGE CPP #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}

module Test.Util.EmbedTree ( Entry(..)
                           , getFile
                           , getDirectory
                           , getEntry
                           , embedTree
                           ) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import qualified Data.Map as Map
import Data.Map (Map)
import Data.Maybe (fromMaybe)

import Instances.TH.Lift ()

import Language.Haskell.TH
import Language.Haskell.TH.Syntax

import System.Directory
  (doesFileExist, doesDirectoryExist
  ,getDirectoryContents
  )
import System.FilePath (takeDirectory, (</>))

-- | This represents a directory listing.  It can either
-- a file with it's contents, or a directory, containing
-- a map of filenames to entries.
data Entry = File String -- ^ The contents of a file.
           | Directory (Map String Entry) -- ^ Mapping of filenames to 'Entry's.
           deriving Show

-- | Get the 'File' contents out of an entry.  Returns contents of a file
-- if this 'Entry' is actually a 'File', otherwise throws an error.
getFile :: Entry -> String
getFile (File contents) = contents
getFile (Directory _) = error "getFile: found a directory"

-- | Get the directory map contents out of an entry.  Returns directory map
-- if this 'Entry' is actually a 'Directory', otherwise throws an error.
getDirectory :: Entry -> Map String Entry
getDirectory (File _) = error "getDirectory: found a file"
getDirectory (Directory contents) = contents

-- | Returns the 'Entry' corresponding to a filename in a Directory 'Map'.
-- Throws an error if the filename is not found.
getEntry :: String              -- ^ The filename to search for.
         -> Map String Entry    -- ^ Filename to 'Entry' 'Map' to search in.
         -> Entry               -- ^ Corresponding 'Entry'
getEntry name entries =
    fromMaybe (error $ "getEntry: " ++ name ++ " not found")
              (Map.lookup name entries)

instance Lift Entry where
  lift (File contents) = AppE (ConE 'File) <$> [|contents|]
  lift (Directory entries) = AppE (ConE 'Directory) <$> [|entries|]

-- | Create an 'Entry' that represents a directory tree with the
-- root being the first argument to this function.
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

-- | Create and embed an 'Entry' using 'readTree'.  This should be used
-- from Template Haskell like the following:
--
-- @
--  files :: Entry
--  files = $(embedTree "my-directory")
-- @
--
-- @my-directory@ will be looked for as a relative path from the current
-- source directory.
embedTree :: FilePath -> ExpQ
embedTree relPath = do
    t <- runIO (readTree (takeDirectory __FILE__ </> relPath))
    [|t|]
